"""运行配置。

所有配置项均可用同名环境变量覆盖（见 .env.example）。
"""

from __future__ import annotations

import ast
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @property
    def openids(self) -> list[str]:
        return load_openids(self.openid)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
