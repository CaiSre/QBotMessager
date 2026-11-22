//! SMTP 邮件发送。
//!
//! 参数来自运行期系统设置；发送使用 lettre 的异步 tokio 传输，
//! 不阻塞 actix worker。未填写服务器或发件人时视为未启用。
//!
//! 与 Python `server/services/mail.py` 一致：
//! - `security ∈ {starttls, ssl, none}`；
//! - 仅当 `smtp_username` 非空时登录；
//! - 未配置时返回 [`MailError::NotConfigured`]（API 层映射为 503「邮件服务未配置」）。

use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::services::runtime_settings::RuntimeSettings;

/// 邮件中的品牌名。
pub const BRAND: &str = "QBotMessager";

/// 邮件发送错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    /// SMTP 未配置。
    #[error("邮件服务未配置")]
    NotConfigured,
    /// SMTP 发送失败（不携带服务器返回的敏感细节）。
    #[error("SMTP 发送失败")]
    SendFailed,
}

/// SMTP 是否已配置。
pub fn is_configured(settings: &RuntimeSettings) -> bool {
    settings.smtp_configured()
}

/// 发送一封邮件。
pub async fn send_mail(
    settings: &RuntimeSettings,
    to: &str,
    subject: &str,
    text: &str,
    html: Option<&str>,
) -> Result<(), MailError> {
    if !is_configured(settings) {
        return Err(MailError::NotConfigured);
    }

    let from: Mailbox = sender(settings).parse().map_err(|err| {
        tracing::warn!(error = %err, "SMTP 发件人地址非法");
        MailError::SendFailed
    })?;
    let to: Mailbox = to.trim().parse().map_err(|err| {
        tracing::warn!(error = %err, "收件人地址非法");
        MailError::SendFailed
    })?;

    let message_builder = Message::builder()
        .from(from)
        .to(to)
        .subject(subject.to_string());
    let message = match html.filter(|html| !html.is_empty()) {
        Some(html) => message_builder.multipart(MultiPart::alternative_plain_html(
            text.to_string(),
            html.to_string(),
        )),
        None => message_builder.body(text.to_string()),
    }
    .map_err(|err| {
        tracing::warn!(error = %err, "邮件内容构造失败");
        MailError::SendFailed
    })?;

    let host = settings.smtp_host().trim().to_string();
    let security = {
        let value = settings.smtp_security().trim().to_ascii_lowercase();
        if value.is_empty() {
            "starttls".to_string()
        } else {
            value
        }
    };

    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host.clone())
        .port(settings.smtp_port())
        .timeout(Some(Duration::from_secs(settings.smtp_timeout())));

    match security.as_str() {
        // 隐式 TLS（通常 465）。
        "ssl" => builder = builder.tls(Tls::Wrapper(tls_parameters(&host)?)),
        // 明文（不推荐）。
        "none" => builder = builder.tls(Tls::None),
        // 其余按 STARTTLS（通常 587）；服务器不支持升级时直接失败，避免降级。
        _ => builder = builder.tls(Tls::Required(tls_parameters(&host)?)),
    }

    if !settings.smtp_username().trim().is_empty() {
        let password = resolve_password(settings.smtp_password())?;
        builder = builder.credentials(Credentials::new(
            settings.smtp_username().trim().to_string(),
            password,
        ));
    }

    let transport = builder.build::<Tokio1Executor>();
    transport.send(message).await.map_err(|err| {
        tracing::warn!(error = %err, "SMTP 发送失败");
        MailError::SendFailed
    })?;
    Ok(())
}

/// 生成与站点风格一致的验证码邮件：返回 `(subject, text, html)`。
pub fn render_code_email(
    code: &str,
    purpose_label: &str,
    ttl_minutes: i64,
) -> (String, String, String) {
    let subject = format!("{BRAND} 验证码");
    let text = format!(
        "您的{BRAND}验证码是 {code}，{ttl_minutes} 分钟内有效。\n\n用途：{purpose_label}\n若非本人操作，请忽略此邮件。"
    );
    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
  <body style="margin:0;padding:24px;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;color:#18181b;">
    <div style="max-width:480px;margin:0 auto;background:#ffffff;border:1px solid #e4e4e7;border-radius:16px;overflow:hidden;">
      <div style="padding:24px 28px;border-bottom:1px solid #e4e4e7;">
        <div style="font-size:20px;font-weight:600;letter-spacing:-0.01em;">{BRAND}</div>
        <div style="margin-top:4px;font-size:13px;color:#71717a;">统一消息接入层</div>
      </div>
      <div style="padding:28px;">
        <p style="margin:0 0 8px;font-size:15px;">您正在进行{purpose_label}。</p>
        <p style="margin:0 0 20px;font-size:14px;color:#71717a;">请在页面中输入以下验证码：</p>
        <div style="padding:28px 20px;background:#f4f4f5;border-radius:12px;text-align:center;">
          <div style="font-size:36px;font-weight:700;letter-spacing:10px;line-height:1.1;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#18181b;">{code}</div>
        </div>
        <p style="margin:20px 0 0;font-size:13px;color:#71717a;">验证码 {ttl_minutes} 分钟内有效，请勿转发给他人。</p>
      </div>
      <div style="padding:18px 28px;border-top:1px solid #e4e4e7;font-size:12px;color:#a1a1aa;">
        若非本人操作，请忽略此邮件。
      </div>
    </div>
  </body>
</html>
"#
    );
    (subject, text, html)
}

/// 发件人：`smtp_from` 优先，留空时使用 `smtp_username`。
fn sender(settings: &RuntimeSettings) -> &str {
    let from = settings.smtp_from().trim();
    if from.is_empty() {
        settings.smtp_username().trim()
    } else {
        from
    }
}

/// 解析 SMTP 密码。
///
/// 运行期设置缓存里的敏感项通常已是明文；这里按规格书 6.2 的三分支兼容：
/// `enc1:` 需要主密钥（缓存层已解密，出现密文说明数据来源异常，按发送失败处理）、
/// `plain1:` 去前缀、其它原样使用。
fn resolve_password(raw: &str) -> Result<String, MailError> {
    crate::crypto::decrypt_secret(raw, None).map_err(|err| {
        tracing::error!(error = %err, "SMTP 密码无法解密，请检查 APP_SECRET_KEY");
        MailError::SendFailed
    })
}

/// 构造 TLS 参数；域名非法或根证书不可用时按发送失败处理。
fn tls_parameters(host: &str) -> Result<TlsParameters, MailError> {
    TlsParameters::new(host.to_string()).map_err(|err| {
        tracing::warn!(error = %err, "SMTP TLS 参数构造失败");
        MailError::SendFailed
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::services::runtime_settings::SettingValue;

    #[test]
    fn not_configured_by_default() {
        let settings = RuntimeSettings::new(None);
        assert!(!is_configured(&settings));
    }

    #[test]
    fn configured_requires_server_and_sender() {
        let mut settings = RuntimeSettings::new(None);
        let mut values = BTreeMap::new();
        values.insert(
            "smtp_host".to_string(),
            SettingValue::Str("smtp.example.com".to_string()),
        );
        settings.apply(&values);
        assert!(!is_configured(&settings), "缺少发件人时仍未配置");

        values.insert(
            "smtp_username".to_string(),
            SettingValue::Str("bot@example.com".to_string()),
        );
        settings.apply(&values);
        assert!(is_configured(&settings));
        assert_eq!(sender(&settings), "bot@example.com");

        values.insert(
            "smtp_from".to_string(),
            SettingValue::Str("noreply@example.com".to_string()),
        );
        settings.apply(&values);
        assert_eq!(sender(&settings), "noreply@example.com");
    }

    #[test]
    fn password_three_branches() {
        // 明文原样使用
        assert_eq!(resolve_password("legacy").unwrap(), "legacy");
        // plain1: 去前缀
        assert_eq!(resolve_password("plain1:s3cret").unwrap(), "s3cret");
        // 空串保持为空
        assert_eq!(resolve_password("").unwrap(), "");
        // enc1: 没有主密钥时按发送失败处理
        assert_eq!(
            resolve_password("enc1:gAAAAABrAl8u3rbx89t5ksepnGbmqOyv").unwrap_err(),
            MailError::SendFailed
        );
    }

    #[test]
    fn render_code_email_matches_python_shape() {
        let (subject, text, html) = render_code_email("123456", "注册账号", 10);
        assert_eq!(subject, "QBotMessager 验证码");
        assert!(text.contains("您的QBotMessager验证码是 123456，10 分钟内有效。"));
        assert!(text.contains("用途：注册账号"));
        assert!(text.contains("若非本人操作，请忽略此邮件。"));
        assert!(html.contains("123456"));
        assert!(html.contains("注册账号"));
        assert!(html.contains("验证码 10 分钟内有效"));
        assert!(html.contains("统一消息接入层"));
    }

    #[test]
    fn is_configured_delegates_to_settings() {
        let settings = RuntimeSettings::new(None);
        assert_eq!(is_configured(&settings), settings.smtp_configured());
    }
}
