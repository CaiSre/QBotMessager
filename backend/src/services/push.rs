//! 一次 Webhook 推送的执行：QQ 发送与推送日志落库。
//!
//! Webhook（队列不可用时的同步回退）与 worker 共用这里的逻辑，
//! 因此任务所需字段全部放在 [`PushJob`] 里，不依赖请求上下文。
//!
//! 逐目标串行发送，每个目标发送后立即
//! 用短事务写一条日志；只要有一个目标失败且全部错误都可重试，才允许整体重试。

use std::time::Instant;

use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

use crate::crypto::decrypt_secret;
use crate::db::queries::{
    bots, channels,
    push_logs::{self, NewPushLog},
};
use crate::renderer::QqPayload;
use crate::services::qq::{DEFAULT_MAX_ATTEMPTS, QqClient, QqTarget};
use crate::services::queue::SentGuard;
use crate::services::runtime_settings::RuntimeSettings;
use crate::services::throttle::RateLimiter;

/// 内容预览的最大字符数。
const PREVIEW_CHARS: usize = 200;

/// 一次推送任务；字段必须可序列化，便于写入队列交给 worker。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PushJob {
    /// 请求 ID（`uuid4` 的 32 位十六进制）。
    pub request_id: String,
    /// 钩子类型。
    pub hook_type: String,
    /// 推送来源（用户自填）。
    pub push_source: String,
    /// 来源通道；通道删除后为 `None`。
    pub channel_id: Option<i64>,
    /// 机器人 ID。
    pub bot_id: i64,
    /// 机器人归属用户。
    pub owner_user_id: i64,
    /// QQ API 域名。
    pub bot_host: String,
    /// QQ AppID。
    pub bot_appid: String,
    /// QQ AppSecret 密文（worker 用主密钥解密，避免明文进入队列）。
    pub app_secret_cipher: String,
    /// 钩子原始消息类型。
    pub source_msgtype: String,
    /// QQ 消息类型：0 纯文本 / 2 Markdown。
    pub msg_type: i32,
    /// 纯文本内容。
    pub content: String,
    /// Markdown 内容。
    pub markdown: Option<String>,
    /// 推送目标。
    pub targets: Vec<QqTarget>,
}

impl PushJob {
    /// 实际使用的 QQ API 域名：任务未指定时回落到运行期设置。
    pub fn qq_host<'a>(&'a self, settings: &'a RuntimeSettings) -> &'a str {
        if self.bot_host.is_empty() {
            settings.qq_host()
        } else {
            self.bot_host.as_str()
        }
    }

    /// QQ 凭据缓存与频控键（按 AppID 归属，多个机器人复用同一 AppID 时共享）。
    pub fn qq_account_key(&self, settings: &RuntimeSettings) -> String {
        crate::services::qq::account_key(self.qq_host(settings), &self.bot_appid)
    }
}

/// 队列任务执行前发现的目标上下文已不可用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushBlock {
    /// 机器人已删除。
    BotMissing,
    /// 机器人已停用。
    BotDisabled,
    /// 机器人归属与任务记录不一致。
    OwnerMismatch,
    /// 通道已删除。
    ChannelMissing,
    /// 通道已停用。
    ChannelDisabled,
    /// 通道不属于任务中的机器人。
    ChannelMismatch,
}

impl PushBlock {
    /// 推送日志错误码。
    fn code(self) -> &'static str {
        match self {
            Self::BotMissing => "bot_missing",
            Self::BotDisabled => "bot_disabled",
            Self::OwnerMismatch => "bot_owner_mismatch",
            Self::ChannelMissing => "channel_missing",
            Self::ChannelDisabled => "channel_disabled",
            Self::ChannelMismatch => "channel_mismatch",
        }
    }

    /// 对外错误信息。
    fn message(self) -> &'static str {
        match self {
            Self::BotMissing => "机器人配置已删除",
            Self::BotDisabled => "机器人配置已停用",
            Self::OwnerMismatch => "机器人归属已变更",
            Self::ChannelMissing => "推送通道已删除",
            Self::ChannelDisabled => "推送通道已停用",
            Self::ChannelMismatch => "推送通道与机器人不匹配",
        }
    }

    /// 写日志时保留的关联 ID；不存在的行必须置空，避免外键失败。
    fn log_ids(self, job: &PushJob) -> (Option<i64>, Option<i64>) {
        match self {
            Self::BotMissing | Self::OwnerMismatch => (None, None),
            Self::BotDisabled | Self::ChannelMissing | Self::ChannelMismatch => {
                (Some(job.bot_id), None)
            }
            Self::ChannelDisabled => (Some(job.bot_id), job.channel_id),
        }
    }
}

/// 发送前回查机器人/通道；管理员在任务入队后停用或删除配置时不再发送。
async fn push_block(pool: &MySqlPool, job: &PushJob) -> Result<Option<PushBlock>, sqlx::Error> {
    let Some(bot) = bots::find_by_id(pool, job.bot_id).await? else {
        return Ok(Some(PushBlock::BotMissing));
    };
    if bot.owner_user_id != job.owner_user_id {
        return Ok(Some(PushBlock::OwnerMismatch));
    }
    if !bot.enabled {
        return Ok(Some(PushBlock::BotDisabled));
    }
    if let Some(channel_id) = job.channel_id {
        let Some(channel) = channels::find_by_id(pool, channel_id).await? else {
            return Ok(Some(PushBlock::ChannelMissing));
        };
        if channel.bot_profile_id != job.bot_id {
            return Ok(Some(PushBlock::ChannelMismatch));
        }
        if !channel.enabled {
            return Ok(Some(PushBlock::ChannelDisabled));
        }
    }
    Ok(None)
}

/// 推送结果：每个目标一条错误信息（`None` 表示成功）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PushOutcome {
    /// 与 [`PushJob::targets`] 一一对应的错误信息。
    pub errors: Vec<Option<String>>,
    /// 全部目标失败且错误都标记为可重试时才允许整体重试，避免重复推送已成功的目标。
    pub retryable: bool,
}

impl PushOutcome {
    /// 是否全部目标成功。
    pub fn is_success(&self) -> bool {
        self.errors.iter().all(Option::is_none)
    }

    /// 失败的错误信息。
    pub fn failed(&self) -> Vec<&str> {
        self.errors
            .iter()
            .filter_map(|error| error.as_deref())
            .collect()
    }

    /// 失败目标数量。
    pub fn failure_count(&self) -> usize {
        self.errors.iter().filter(|error| error.is_some()).count()
    }
}

/// 逐个目标串行发送并落推送日志。
///
/// 发送期间不持有数据库连接；每个目标发送后立即用短事务写日志。
/// `sent` 用于跳过本次投递中已经发送成功的目标（队列至少一次语义）。
pub async fn execute_push(
    pool: &MySqlPool,
    job: &PushJob,
    settings: &RuntimeSettings,
    client: &QqClient,
    limiter: &RateLimiter,
    sent: Option<&SentGuard>,
) -> PushOutcome {
    let payload = QqPayload {
        msg_type: job.msg_type,
        content: job.content.clone(),
        markdown: job.markdown.clone(),
    };
    // 预览与长度都按原样消息文本计算，Markdown 消息取 markdown 正文。
    let text = payload.text().to_string();
    let content_preview: String = text.chars().take(PREVIEW_CHARS).collect();
    let content_len = text.chars().count() as i32;

    // 任务可能已在队列中停留一段时间；执行前以数据库当前状态为准。
    let block = match push_block(pool, job).await {
        Ok(block) => block,
        Err(err) => {
            tracing::error!(error = %err, bot_id = job.bot_id, "推送前校验机器人状态失败");
            return PushOutcome {
                errors: vec![Some("推送上下文校验失败".to_string()); job.targets.len()],
                retryable: true,
            };
        }
    };
    if let Some(block) = block {
        let (bot_profile_id, channel_id) = block.log_ids(job);
        for target in &job.targets {
            let target_label = target.to_db_value();
            let entry = NewPushLog {
                owner_user_id: job.owner_user_id,
                channel_id,
                bot_profile_id,
                hook_type: &job.hook_type,
                push_source: &job.push_source,
                source_msgtype: &job.source_msgtype,
                target: &target_label,
                qq_msg_type: Some(job.msg_type),
                content_preview: &content_preview,
                content_len,
                status: "failed",
                error_code: Some(block.code()),
                error_message: Some(block.message()),
                duration_ms: 0.0,
                request_id: &job.request_id,
                created_at: chrono::Utc::now().naive_utc(),
            };
            if let Err(err) = push_logs::insert(pool, &entry).await {
                tracing::error!(
                    error = %err,
                    request_id = %job.request_id,
                    "写入跳过推送日志失败"
                );
            }
        }
        tracing::warn!(
            bot_id = job.bot_id,
            channel_id = ?job.channel_id,
            reason = block.code(),
            "推送任务上下文已失效，跳过发送"
        );
        return PushOutcome {
            errors: vec![Some(block.message().to_string()); job.targets.len()],
            retryable: false,
        };
    }

    let app_secret = match decrypt_secret(&job.app_secret_cipher, settings.secret_key()) {
        Ok(secret) => secret,
        Err(err) => {
            tracing::error!(error = %err, bot_id = job.bot_id, "机器人密钥无法解密");
            return PushOutcome {
                errors: vec![
                    Some("机器人密钥无法解密，请检查 APP_SECRET_KEY".to_string(),);
                    job.targets.len()
                ],
                retryable: false,
            };
        }
    };

    let host = job.qq_host(settings);
    let token_key = job.qq_account_key(settings);

    let mut errors: Vec<Option<String>> = Vec::with_capacity(job.targets.len());
    let mut retryable_flags: Vec<bool> = Vec::with_capacity(job.targets.len());

    for target in &job.targets {
        let guard_key = format!("{}:{}", job.request_id, target.label());
        if let Some(sent) = sent {
            match sent.done(&guard_key).await {
                Ok(true) => {
                    // 上一轮已经送达，日志也已写成功，这里不再重复发送与记录。
                    errors.push(None);
                    retryable_flags.push(false);
                    continue;
                }
                Ok(false) => {}
                // 读不到标记时按未发送处理：宁可重发，也不丢消息。
                Err(err) => tracing::warn!(
                    error = %err,
                    guard_key = %guard_key,
                    "读取推送完成标记失败"
                ),
            }
        }

        let started = Instant::now();
        let mut error: Option<String> = None;
        let mut error_code: Option<String> = None;
        let mut retryable = false;

        // 频控许可在 QqClient 内部于取 token 之前获取（含重试）。
        match client
            .send(
                &token_key,
                host,
                &job.bot_appid,
                &app_secret,
                target,
                &payload,
                limiter,
                DEFAULT_MAX_ATTEMPTS,
            )
            .await
        {
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    target = %target.label(),
                    code = %err.code,
                    message = %err.message,
                    "QQ 推送失败"
                );
                error = Some(err.message);
                error_code = Some(err.code);
                retryable = err.retryable;
            }
        }

        if error.is_none()
            && let Some(sent) = sent
            && let Err(err) = sent.mark(&guard_key).await
        {
            // 标记写失败只会导致重跑时重发，不影响本次结果。
            tracing::warn!(error = %err, guard_key = %guard_key, "写入推送完成标记失败");
        }

        let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        let target_label = target.to_db_value();
        {
            let entry = NewPushLog {
                owner_user_id: job.owner_user_id,
                channel_id: job.channel_id,
                bot_profile_id: Some(job.bot_id),
                hook_type: &job.hook_type,
                push_source: &job.push_source,
                source_msgtype: &job.source_msgtype,
                target: &target_label,
                qq_msg_type: Some(job.msg_type),
                content_preview: &content_preview,
                content_len,
                status: if error.is_none() { "success" } else { "failed" },
                error_code: error_code.as_deref(),
                error_message: error.as_deref(),
                duration_ms,
                request_id: &job.request_id,
                created_at: chrono::Utc::now().naive_utc(),
            };
            // 每个目标发送后立即写日志：任务被取消或超时时，已处理的目标仍有审计记录。
            if let Err(err) = push_logs::insert(pool, &entry).await {
                tracing::error!(
                    error = %err,
                    request_id = %job.request_id,
                    "写入推送日志失败"
                );
            }
        }

        errors.push(error);
        retryable_flags.push(retryable);
    }

    let failure_count = errors.iter().filter(|error| error.is_some()).count();
    let retryable = failure_count > 0
        && failure_count == errors.len()
        && retryable_flags.iter().all(|flag| *flag);
    PushOutcome { errors, retryable }
}
