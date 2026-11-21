"""运行配置。

所有配置项均可用同名环境变量覆盖（见 .env.example）。
"""

from __future__ import annotations

import ast
import logging
import os
from datetime import datetime, tzinfo
from functools import lru_cache
from zoneinfo import ZoneInfo

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


def load_openids(raw: str | None) -> list[str]:
    """从 OPENID 读取 openid 列表，兼容 JSON 数组与 Python list 字面量。

    沿用 send_message.py 的解析规则，保证旧 .env 无需改动即可导入默认推送目标。
    """
    if not raw:
        return []
    raw = raw.strip()
    try:
        value = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        value = [raw]
    if isinstance(value, str):
        value = [value]
    return [str(v) for v in value if v]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # 基础
    app_name: str = "QBotMessager"
    log_level: str = "INFO"
    mysql_url: str = ""

    # 密钥：Fernet 主密钥，用于加密库内敏感字段；缺失时敏感字段降级为明文并告警
    app_secret_key: str = ""

    # 对外地址：用于生成 webhook URL 与 OAuth 回调；留空时按请求头推导
    public_base_url: str = ""

    # WebAuthn
    rp_id: str = ""
    rp_name: str = "QBotMessager"

    # 会话
    session_ttl_hours: int = 72
    cookie_name: str = "sid"
    cookie_secure: bool = False

    # 注册
    register_enabled: bool = False

    # 引导：首次启动创建超级管理员，并导入 .env 中的 QQ 凭据
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""

    # QQ 机器人（引导导入用；运行期以库内 bot_profiles 为准）
    qq_host: str = "https://api.bot.qq.com"
    qq_appid: str = ""
    qq_app_secret: str = ""
    openid: str = ""

    # QQ 频控（账号级：5/qps、30/qpm）
    qq_qps: int = 5
    qq_qpm: int = 30
    qq_min_interval: float = 0.21

    # 内容长度上限（QQ 侧未公开，保守取值）
    markdown_max_len: int = 4000
    text_max_len: int = 2000

    # 请求体上限
    max_body_bytes: int = 65536
    # GitHub 的 Webhook 负载上限为 25MB，推送事件可能明显大于普通消息
    github_max_body_bytes: int = 2_097_152

    # 入站鉴权：是否允许用 ?token= 传凭据（会落入访问日志，默认关闭）
    webhook_allow_query_token: bool = False

    # 登录失败限速：同一 (IP, 账号) 与同一 IP 各自的失败次数上限与统计窗口
    login_max_failures: int = 5
    login_ip_max_failures: int = 30
    login_window_seconds: int = 900

    # 业务统计使用的时区：留空则取容器 TZ，再退回本机时区
    timezone: str = ""

    # SMTP 邮件（验证码）：运行期以库内「系统设置」为准，这里仅作首启导入
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_timeout: int = 15
    email_code_ttl_minutes: int = 10
    email_code_resend_seconds: int = 60
    email_code_hourly_limit: int = 5

    @property
    def openids(self) -> list[str]:
        return load_openids(self.openid)

    @property
    def secure_cookies(self) -> bool:
        """会话类 Cookie 是否带 Secure：显式开启，或对外地址是 https 时自动开启。"""
        if self.cookie_secure:
            return True
        return self.public_base_url.lower().startswith("https://")

    @property
    def tz(self) -> tzinfo:
        """业务统计使用的时区。"""
        name = self.timezone.strip() or os.environ.get("TZ", "").strip()
        if name:
            try:
                return ZoneInfo(name)
            except Exception:  # noqa: BLE001 - 时区名非法或本机缺时区库时退回本机时区
                logger.warning("时区 %s 不可用（名称非法或本机缺少时区库），改用本机时区", name)
        return datetime.now().astimezone().tzinfo


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
