//! 出站 HTTP 客户端。
//!
//! 统一超时、连接超时与 User-Agent，并禁用自动重定向：OAuth token
//! 请求会携带 client_secret，QQ token 请求会携带 AppSecret，307/308
//! 跟随重定向会把请求体重发到未校验的目标。

use std::time::Duration;

/// 构造共享的 reqwest 客户端。
pub fn client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .user_agent("qbotmessager")
        .redirect(reqwest::redirect::Policy::none())
        .build()
}
