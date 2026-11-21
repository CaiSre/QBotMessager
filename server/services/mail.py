"""SMTP 邮件发送。

参数来自运行期系统设置；发送在独立线程执行，避免阻塞事件循环。
未填写服务器或发件人时视为未启用，调用方应据此跳过验证码流程。
"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

BRAND = "QBotMessager"


class MailNotConfigured(RuntimeError):
    """SMTP 未配置。"""


class MailSendError(RuntimeError):
    """SMTP 发送失败（不携带服务器返回的敏感细节）。"""


def is_configured(settings: Any) -> bool:
    return bool(getattr(settings, "smtp_configured", False))


def _sender(settings: Any) -> str:
    return str(settings.smtp_from or settings.smtp_username or "").strip()


def _deliver(settings: Any, *, to: str, subject: str, text: str, html: str | None) -> None:
    message = EmailMessage()
    message["From"] = _sender(settings)
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")

    host = str(settings.smtp_host)
    port = int(settings.smtp_port)
    timeout = int(settings.smtp_timeout)
    security = str(settings.smtp_security or "starttls").lower()

    try:
        if security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                host,
                port,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
        else:
            client = smtplib.SMTP(host, port, timeout=timeout)
        with client:
            client.ehlo()
            if security == "starttls":
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if settings.smtp_username:
                client.login(str(settings.smtp_username), str(settings.smtp_password))
            client.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailSendError("SMTP 发送失败") from exc


async def send_mail(
    settings: Any,
    *,
    to: str,
    subject: str,
    text: str,
    html: str | None = None,
) -> None:
    if not is_configured(settings) or not _sender(settings):
        raise MailNotConfigured("SMTP 未配置")
    await asyncio.to_thread(
        _deliver, settings, to=to, subject=subject, text=text, html=html
    )


def render_code_email(
    *, code: str, purpose_label: str, ttl_minutes: int
) -> tuple[str, str, str]:
    """生成与站点风格一致的验证码邮件：顶部品牌、灰色底大号加粗验证码。"""
    subject = f"{BRAND} 验证码"
    text = (
        f"您的{BRAND}验证码是 {code}，{ttl_minutes} 分钟内有效。\n\n"
        f"用途：{purpose_label}\n"
        "若非本人操作，请忽略此邮件。"
    )
    html = f"""\
<!doctype html>
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
"""
    return subject, text, html
