//! 临时认证 Cookie 的命名与读取。
//!
//! HTTPS 下优先使用 `__Host-` 前缀：强制 Secure、Path=/、无 Domain，降低
//! 子域写入或明文覆盖的风险；同时保留旧名读取，兼容升级中的浏览器会话。

use actix_web::HttpRequest;

use crate::services::runtime_settings::RuntimeSettings;

/// `__Host-` Cookie 前缀。
pub const HOST_PREFIX: &str = "__Host-";

/// 拼 flow 后缀的基准名：`{base}_{flow}`；flow 为空时只返回 `base`。
pub fn plain_name(base: &str, flow: &str) -> String {
    if flow.is_empty() {
        base.to_string()
    } else {
        format!("{base}_{flow}")
    }
}

/// 当前设置下的 Cookie 名，优先返回 `__Host-` 前缀版本。
///
/// 第二个元素是旧名；读取与清理都应覆盖两者。
pub fn names(base: &str, flow: &str, settings: &RuntimeSettings) -> Vec<String> {
    let plain = plain_name(base, flow);
    if settings.secure_cookies() {
        vec![format!("{HOST_PREFIX}{plain}"), plain]
    } else {
        vec![plain]
    }
}

/// 当前设置下应当签发的 Cookie 名。
pub fn preferred_name(base: &str, flow: &str, settings: &RuntimeSettings) -> String {
    names(base, flow, settings)
        .into_iter()
        .next()
        .expect("Cookie 名列表至少有一个元素")
}

/// 依次读取 `__Host-` 版本与旧版 Cookie；均缺失时返回空串。
pub fn read(req: &HttpRequest, base: &str, flow: &str, settings: &RuntimeSettings) -> String {
    for name in names(base, flow, settings) {
        if let Some(cookie) = req.cookie(&name) {
            return cookie.value().to_string();
        }
    }
    String::new()
}
