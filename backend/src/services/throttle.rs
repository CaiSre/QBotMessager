//! 进程内限速器：滑动窗口 QPS/QPM + 最小发送间隔，以及登录失败计数限速。
//!
//! QQ 主动消息频控是账号级（按机器人 AppID）的，因此必须单 worker、单副本运行。
//!
//! 语义与 Python `server/services/throttle.py` 一致：
//! - `RateLimiter`：只有记账在锁内完成，等待在锁外进行；
//! - `AttemptLimiter`：回环或空 IP 只计 `(来源, 账号)` 维度。

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// QPS 滑动窗口长度。
const SECOND_WINDOW: Duration = Duration::from_secs(1);
/// QPM 滑动窗口长度。
const MINUTE_WINDOW: Duration = Duration::from_secs(60);
/// 等待的下限（秒），避免忙等。
const MIN_SLEEP: Duration = Duration::from_millis(10);

/// 限流器的可变状态。
#[derive(Debug)]
struct LimiterState {
    qps: u32,
    qpm: u32,
    min_interval: Duration,
    second_window: VecDeque<Instant>,
    minute_window: VecDeque<Instant>,
    last_sent: Option<Instant>,
}

/// QQ 发送频控：滑动窗口 QPS + QPM + 最小发送间隔。
#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<LimiterState>,
}

impl RateLimiter {
    /// 创建限流器。
    pub fn new(qps: u32, qpm: u32, min_interval: Duration) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                qps: qps.max(1),
                qpm: qpm.max(1),
                min_interval,
                second_window: VecDeque::new(),
                minute_window: VecDeque::new(),
                last_sent: None,
            }),
        }
    }

    /// 获取一次发送许可（阻塞直到满足频率限制）。
    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut state = lock(&self.state);
                let now = Instant::now();
                prune(&mut state, now);
                let mut wait = Duration::ZERO;
                if state.second_window.len() as u32 >= state.qps {
                    wait = wait.max(until(state.second_window[0] + SECOND_WINDOW, now));
                }
                if state.minute_window.len() as u32 >= state.qpm {
                    wait = wait.max(until(state.minute_window[0] + MINUTE_WINDOW, now));
                }
                if let Some(last_sent) = state.last_sent {
                    wait = wait.max(until(last_sent + state.min_interval, now));
                }
                if wait.is_zero() {
                    state.last_sent = Some(now);
                    state.second_window.push_back(now);
                    state.minute_window.push_back(now);
                    return;
                }
                wait
            };
            tokio::time::sleep(wait.max(MIN_SLEEP)).await;
        }
    }

    /// 更新参数但保留已有窗口，避免瞬时放行双倍配额。
    pub fn configure(&self, qps: u32, qpm: u32, min_interval: Duration) {
        let mut state = lock(&self.state);
        state.qps = qps.max(1);
        state.qpm = qpm.max(1);
        state.min_interval = min_interval;
    }

    /// 当前 QPS 配额。
    pub fn qps(&self) -> u32 {
        lock(&self.state).qps
    }

    /// 当前 QPM 配额。
    pub fn qpm(&self) -> u32 {
        lock(&self.state).qpm
    }

    /// 当前最小发送间隔。
    pub fn min_interval(&self) -> Duration {
        lock(&self.state).min_interval
    }
}

/// 按 key（机器人）分配独立限流器。
///
/// QQ 的主动消息频控按机器人（AppID）维度计算，多个用户共用一条全局配额会互相
/// 拖慢，因此每个机器人各维护一份窗口。键沿用 QqClient 的 `bot:<id>` 约定。
#[derive(Debug)]
pub struct LimiterRegistry {
    defaults: Mutex<RegistryDefaults>,
    limiters: DashMap<String, Arc<RateLimiter>>,
}

/// 新建限流器的默认参数。
#[derive(Debug, Clone, Copy)]
struct RegistryDefaults {
    qps: u32,
    qpm: u32,
    min_interval: Duration,
}

impl LimiterRegistry {
    /// 创建注册表。
    pub fn new(qps: u32, qpm: u32, min_interval: Duration) -> Self {
        Self {
            defaults: Mutex::new(RegistryDefaults {
                qps: qps.max(1),
                qpm: qpm.max(1),
                min_interval,
            }),
            limiters: DashMap::new(),
        }
    }

    /// 取（必要时创建）某个 key 的限流器。
    pub fn get(&self, key: &str) -> Arc<RateLimiter> {
        if let Some(limiter) = self.limiters.get(key) {
            return limiter.clone();
        }
        let defaults = *lock(&self.defaults);
        let limiter = Arc::new(RateLimiter::new(
            defaults.qps,
            defaults.qpm,
            defaults.min_interval,
        ));
        self.limiters
            .entry(key.to_string())
            .or_insert_with(|| limiter.clone())
            .clone()
    }

    /// 采用新的频控参数；保留已有窗口，避免瞬时放行双倍配额。
    pub fn configure(&self, qps: u32, qpm: u32, min_interval: Duration) {
        {
            let mut defaults = lock(&self.defaults);
            defaults.qps = qps.max(1);
            defaults.qpm = qpm.max(1);
            defaults.min_interval = min_interval;
        }
        for limiter in self.limiters.iter() {
            limiter.configure(qps, qpm, min_interval);
        }
    }
}

/// 登录失败计数限速。
///
/// 同时按 (客户端 IP, 账号) 与 客户端 IP 两个维度计数：前者拦针对单个账号的爆破，
/// 后者拦大范围撞库；因为按组合计数，攻击者无法只靠一个来源锁死他人账号。
/// 客户端地址无法区分来源时只启用前一个维度。
///
/// 计数保存在进程内，与 QQ 频控一样要求单 worker、单副本运行。
#[derive(Debug)]
pub struct AttemptLimiter {
    state: Mutex<AttemptState>,
}

/// 登录失败计数的可变状态。
#[derive(Debug)]
struct AttemptState {
    pair_limit: u32,
    ip_limit: u32,
    window_seconds: u64,
    failures: HashMap<String, VecDeque<Instant>>,
}

/// 计数桶数量的上限，超过后整体清理。
const MAX_KEYS: usize = 4096;

impl AttemptLimiter {
    /// 创建限速器。
    pub fn new(pair_limit: u32, ip_limit: u32, window_seconds: u64) -> Self {
        Self {
            state: Mutex::new(AttemptState {
                pair_limit: pair_limit.max(1),
                ip_limit: ip_limit.max(1),
                window_seconds: window_seconds.max(1),
                failures: HashMap::new(),
            }),
        }
    }

    /// 更新阈值与窗口长度。
    pub fn configure(&self, pair_limit: u32, ip_limit: u32, window_seconds: u64) {
        let mut state = lock(&self.state);
        state.pair_limit = pair_limit.max(1);
        state.ip_limit = ip_limit.max(1);
        state.window_seconds = window_seconds.max(1);
    }

    /// 检查是否还能继续尝试。
    ///
    /// 超限时返回还需等待的时长。
    pub fn check(&self, ip: Option<&str>, account: &str) -> Result<(), Duration> {
        let wait = self.remaining_wait(ip, account);
        if wait > 0 {
            Err(Duration::from_secs(wait))
        } else {
            Ok(())
        }
    }

    /// 超限时返回还需等待的秒数，未超限返回 0。
    pub fn remaining_wait(&self, ip: Option<&str>, account: &str) -> u64 {
        let now = Instant::now();
        let mut state = lock(&self.state);
        let pair = prune_bucket(&mut state, &pair_key(ip, account), now);
        let mut wait = wait_of(&pair, now, state.pair_limit, state.window_seconds);
        if !is_shared_peer(ip) {
            let by_ip = prune_bucket(&mut state, &ip_key(ip), now);
            wait = wait.max(wait_of(&by_ip, now, state.ip_limit, state.window_seconds));
        }
        wait
    }

    /// 记录一次失败。
    pub fn record_failure(&self, ip: Option<&str>, account: &str) {
        let now = Instant::now();
        let mut state = lock(&self.state);
        let mut keys = vec![pair_key(ip, account)];
        if !is_shared_peer(ip) {
            keys.push(ip_key(ip));
        }
        for key in keys {
            state.failures.entry(key).or_default().push_back(now);
        }
        if state.failures.len() > MAX_KEYS {
            prune_all(&mut state, now);
        }
    }

    /// 登录成功后清掉该 (IP, 账号) 的计数；IP 维度保留，避免靠偶发成功绕过。
    pub fn reset(&self, ip: Option<&str>, account: &str) {
        let mut state = lock(&self.state);
        state.failures.remove(&pair_key(ip, account));
    }
}

/// 判断客户端地址能否区分来源。
///
/// 后端只监听 127.0.0.1、由同机 Next 反代访问时，请求方地址始终是回环地址，
/// 这时按 IP 计数会把所有用户算作同一个来源：一次撞库就能把所有账号一起锁死。
/// 这种情况只按 (来源, 账号) 计数。
fn is_shared_peer(ip: Option<&str>) -> bool {
    let Some(ip) = ip else {
        return true;
    };
    if ip.is_empty() {
        return true;
    }
    if ip == "::1" || ip == "localhost" {
        return true;
    }
    ip.starts_with("127.")
}

/// `(来源, 账号)` 维度的键。
fn pair_key(ip: Option<&str>, account: &str) -> String {
    format!("pair:{}|{account}", ip.unwrap_or("-"))
}

/// IP 维度的键。
fn ip_key(ip: Option<&str>) -> String {
    format!("ip:{}", ip.unwrap_or("-"))
}

/// 距离目标时刻还有多久（已过则为零）。
fn until(target: Instant, now: Instant) -> Duration {
    target.checked_duration_since(now).unwrap_or(Duration::ZERO)
}

/// 加锁；锁中毒时取回内部值继续用（限流计数不值得因此 panic）。
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

/// 清理滑出窗口的记账。
fn prune(state: &mut LimiterState, now: Instant) {
    while let Some(&oldest) = state.second_window.front() {
        if now.duration_since(oldest) >= SECOND_WINDOW {
            state.second_window.pop_front();
        } else {
            break;
        }
    }
    while let Some(&oldest) = state.minute_window.front() {
        if now.duration_since(oldest) >= MINUTE_WINDOW {
            state.minute_window.pop_front();
        } else {
            break;
        }
    }
}

/// 清理某个键下过期���失败记录；桶空了就把键删掉。
fn prune_bucket(state: &mut AttemptState, key: &str, now: Instant) -> VecDeque<Instant> {
    let Some(bucket) = state.failures.get_mut(key) else {
        return VecDeque::new();
    };
    while let Some(&oldest) = bucket.front() {
        if now.duration_since(oldest).as_secs() >= state.window_seconds {
            bucket.pop_front();
        } else {
            break;
        }
    }
    let snapshot = bucket.clone();
    if snapshot.is_empty() {
        state.failures.remove(key);
    }
    snapshot
}

/// 桶未达上限时返回 0；超限时返回还需等待的秒数。
fn wait_of(bucket: &VecDeque<Instant>, now: Instant, limit: u32, window_seconds: u64) -> u64 {
    if (bucket.len() as u32) < limit {
        return 0;
    }
    let Some(&oldest) = bucket.front() else {
        return 0;
    };
    let elapsed = now.duration_since(oldest).as_secs_f64();
    let remaining = (window_seconds as f64 - elapsed).max(0.0);
    let seconds = remaining as u64 + 1;
    seconds.max(1)
}

/// 清理所有过期的失败记录。
fn prune_all(state: &mut AttemptState, now: Instant) {
    let keys: Vec<String> = state.failures.keys().cloned().collect();
    for key in keys {
        prune_bucket(state, &key, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn min_interval_spacing() {
        let limiter = RateLimiter::new(50, 600, Duration::from_millis(50));
        let started = Instant::now();
        for _ in 0..3 {
            limiter.acquire().await;
        }
        assert!(started.elapsed() >= Duration::from_millis(90));
    }

    #[tokio::test]
    async fn qps_window_blocks_burst() {
        let limiter = RateLimiter::new(2, 600, Duration::ZERO);
        let started = Instant::now();
        for _ in 0..3 {
            limiter.acquire().await;
        }
        // 第 3 次必须等到窗口滑出，约 1s
        assert!(started.elapsed() >= Duration::from_millis(900));
    }

    #[tokio::test]
    async fn concurrent_acquire_is_serialized() {
        let limiter = Arc::new(RateLimiter::new(50, 600, Duration::from_millis(20)));
        let started = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..3 {
            let limiter = limiter.clone();
            handles.push(tokio::spawn(async move { limiter.acquire().await }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert!(started.elapsed() >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn registry_gives_each_bot_its_own_window() {
        let registry = LimiterRegistry::new(2, 600, Duration::ZERO);

        let first = registry.get("bot:1");
        assert!(Arc::ptr_eq(&first, &registry.get("bot:1")));
        assert!(!Arc::ptr_eq(&first, &registry.get("bot:2")));

        // 第一个机器人用满自己的 QPS 窗口，不影响第二个机器人
        first.acquire().await;
        first.acquire().await;
        let started = Instant::now();
        registry.get("bot:2").acquire().await;
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn registry_configure_keeps_windows() {
        let registry = LimiterRegistry::new(2, 600, Duration::ZERO);
        let limiter = registry.get("bot:1");
        limiter.acquire().await;
        limiter.acquire().await;
        // 收紧参数后已有窗口仍然保留：仍需等窗口滑出
        registry.configure(1, 600, Duration::ZERO);
        assert_eq!(limiter.qps(), 1);
        let started = Instant::now();
        limiter.acquire().await;
        assert!(started.elapsed() >= Duration::from_millis(900));
    }

    #[test]
    fn attempt_limiter_counts_per_pair_and_per_ip() {
        let limiter = AttemptLimiter::new(2, 10, 60);

        for _ in 0..2 {
            limiter.record_failure(Some("1.2.3.4"), "a@example.com");
        }
        assert!(limiter.remaining_wait(Some("1.2.3.4"), "a@example.com") > 0);
        // 同一 IP 下换账号仍可用，IP 额度还没用完
        assert_eq!(limiter.remaining_wait(Some("1.2.3.4"), "b@example.com"), 0);
        // 别的 IP 完全不受影响
        assert_eq!(limiter.remaining_wait(Some("5.6.7.8"), "a@example.com"), 0);
    }

    #[test]
    fn attempt_limiter_ip_budget_blocks_wide_sweep() {
        let limiter = AttemptLimiter::new(5, 3, 60);

        for index in 0..3 {
            limiter.record_failure(Some("1.2.3.4"), &format!("user{index}@example.com"));
        }
        assert!(limiter.remaining_wait(Some("1.2.3.4"), "fresh@example.com") > 0);
    }

    #[test]
    fn attempt_limiter_reset_clears_pair_only() {
        let limiter = AttemptLimiter::new(2, 10, 60);

        limiter.record_failure(Some("1.2.3.4"), "a@example.com");
        limiter.record_failure(Some("1.2.3.4"), "a@example.com");
        assert!(limiter.remaining_wait(Some("1.2.3.4"), "a@example.com") > 0);

        limiter.reset(Some("1.2.3.4"), "a@example.com");
        assert_eq!(limiter.remaining_wait(Some("1.2.3.4"), "a@example.com"), 0);
        // IP 维度的计数保留，避免靠偶发成功绕过
        for _ in 0..3 {
            limiter.record_failure(Some("1.2.3.4"), "b@example.com");
        }
        assert!(limiter.remaining_wait(Some("1.2.3.4"), "b@example.com") > 0);
    }

    #[test]
    fn attempt_limiter_ignores_ip_budget_for_shared_peer() {
        // 来源地址是回环（反代未透传客户端 IP）时，IP 维度会把所有用户算成一个人。
        let limiter = AttemptLimiter::new(5, 3, 60);

        for index in 0..10 {
            limiter.record_failure(Some("127.0.0.1"), &format!("user{index}@example.com"));
        }

        // 别的账号不受牵连，否则一次撞库会把所有人一起锁死
        assert_eq!(
            limiter.remaining_wait(Some("127.0.0.1"), "fresh@example.com"),
            0
        );
        // 同一账号仍然按组合计数限速
        for _ in 0..5 {
            limiter.record_failure(Some("127.0.0.1"), "user0@example.com");
        }
        assert!(limiter.remaining_wait(Some("127.0.0.1"), "user0@example.com") > 0);
    }

    #[test]
    fn check_returns_remaining_duration() {
        let limiter = AttemptLimiter::new(1, 10, 60);
        limiter.record_failure(Some("1.2.3.4"), "a@example.com");
        let wait = limiter.check(Some("1.2.3.4"), "a@example.com").unwrap_err();
        assert!(wait >= Duration::from_secs(1));
        assert!(limiter.check(Some("9.9.9.9"), "a@example.com").is_ok());
    }

    #[test]
    fn missing_ip_counts_pair_dimension_only() {
        let limiter = AttemptLimiter::new(2, 1, 60);
        for index in 0..5 {
            limiter.record_failure(None, &format!("user{index}@example.com"));
        }
        assert_eq!(limiter.remaining_wait(None, "fresh@example.com"), 0);
    }
}
