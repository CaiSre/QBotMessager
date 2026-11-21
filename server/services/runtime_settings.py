"""系统设置：非敏感运行配置持久化到数据库，并通过内存缓存即时生效。

数据库连接串、加密主密钥、初始管理员与 QQ 引导凭据仍由环境变量提供，
其余曾经的环境变量在这里统一声明；启动时把仍写在环境变量里的非默认值
一次性导入数据库，此后运行期只读取数据库。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, tzinfo
from typing import Any, Literal
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import Settings
from server.db.crypto import DecryptError, decrypt_secret, encrypt_secret
from server.db.models import SystemSetting

logger = logging.getLogger(__name__)

Kind = Literal["bool", "int", "float", "string", "select"]

GROUP_SITE = "站点与访问"
GROUP_ACCOUNT = "注册与会话"
GROUP_LOGIN = "登录保护"
GROUP_MAIL = "邮件服务"
GROUP_QQ = "QQ 推送"


@dataclass(frozen=True)
class SettingSpec:
    key: str
    label: str
    group: str
    kind: Kind
    default: Any
    description: str = ""
    minimum: float | None = None
    maximum: float | None = None
    options: tuple[str, ...] = ()
    max_length: int = 512
    # 敏感项：库里以 Fernet 密文保存，接口与页面只回显是否已设置
    secret: bool = False


CATALOG: tuple[SettingSpec, ...] = (
    SettingSpec(
        "public_base_url",
        "对外访问地址",
        GROUP_SITE,
        "string",
        "",
        "用于生成 Webhook 地址与 OAuth 回调；留空时按请求头推导",
        max_length=512,
    ),
    SettingSpec(
        "timezone",
        "统计时区",
        GROUP_SITE,
        "string",
        "",
        "统计按该时区切分日期，例如 Asia/Shanghai；留空取容器 TZ 或本机时区",
        max_length=64,
    ),
    SettingSpec(
        "log_level",
        "日志级别",
        GROUP_SITE,
        "select",
        "INFO",
        "保存后立即调整后端日志输出",
        options=("DEBUG", "INFO", "WARNING", "ERROR"),
    ),
    SettingSpec(
        "max_body_bytes",
        "请求体上限",
        GROUP_SITE,
        "int",
        65536,
        "Webhook 单次请求体上限（字节）",
        minimum=1024,
        maximum=10_485_760,
    ),
    SettingSpec(
        "github_max_body_bytes",
        "GitHub 请求体上限",
        GROUP_SITE,
        "int",
        2_097_152,
        "GitHub Webhook 单次请求体上限（字节）；GitHub 自身的负载上限为 25MB",
        minimum=1024,
        maximum=26_214_400,
    ),
    SettingSpec(
        "webhook_allow_query_token",
        "允许 URL 传凭据",
        GROUP_SITE,
        "bool",
        False,
        "允许用 ?token= 传 Webhook 凭据；查询参数会落入访问日志，默认关闭",
    ),
    SettingSpec(
        "register_enabled",
        "允许邀请注册",
        GROUP_ACCOUNT,
        "bool",
        False,
        "开启后持有邀请码的用户才能注册",
    ),
    SettingSpec(
        "session_ttl_hours",
        "会话有效期",
        GROUP_ACCOUNT,
        "int",
        72,
        "登录会话有效小时数，对新登录生效",
        minimum=1,
        maximum=8760,
    ),
    SettingSpec(
        "cookie_secure",
        "Cookie 仅限 HTTPS",
        GROUP_ACCOUNT,
        "bool",
        False,
        "对外访问地址为 https 时会自动开启",
    ),
    SettingSpec(
        "rp_id",
        "通行密钥 RP ID",
        GROUP_ACCOUNT,
        "string",
        "",
        "WebAuthn 依赖方标识；留空时取对外地址的主机名",
        max_length=255,
    ),
    SettingSpec(
        "rp_name",
        "通行密钥显示名称",
        GROUP_ACCOUNT,
        "string",
        "QBotMessager",
        "创建通行密钥时展示给用户的名称",
        max_length=128,
    ),
    SettingSpec(
        "login_max_failures",
        "单账号失败上限",
        GROUP_LOGIN,
        "int",
        5,
        "同一（IP, 账号）在统计窗口内的失败次数上限",
        minimum=1,
        maximum=1000,
    ),
    SettingSpec(
        "login_ip_max_failures",
        "单 IP 失败上限",
        GROUP_LOGIN,
        "int",
        30,
        "同一 IP 在统计窗口内的失败次数上限",
        minimum=1,
        maximum=10_000,
    ),
    SettingSpec(
        "login_window_seconds",
        "统计窗口",
        GROUP_LOGIN,
        "int",
        900,
        "登录失败计数的统计窗口（秒）",
        minimum=60,
        maximum=86_400,
    ),
    SettingSpec(
        "smtp_host",
        "SMTP 服务器",
        GROUP_MAIL,
        "string",
        "",
        "邮件服务器地址，例如 smtp.example.com；留空则停用邮件验证码",
        max_length=255,
    ),
    SettingSpec(
        "smtp_port",
        "SMTP 端口",
        GROUP_MAIL,
        "int",
        587,
        "常用端口：587（STARTTLS）、465（SSL）、25（不加密）",
        minimum=1,
        maximum=65535,
    ),
    SettingSpec(
        "smtp_security",
        "连接方式",
        GROUP_MAIL,
        "select",
        "starttls",
        "starttls 为 STARTTLS 升级，ssl 为直接 TLS，none 为明文（不推荐）",
        options=("starttls", "ssl", "none"),
    ),
    SettingSpec(
        "smtp_username",
        "SMTP 用户名",
        GROUP_MAIL,
        "string",
        "",
        "登录邮件服务器的账号；留空则不登录",
        max_length=255,
    ),
    SettingSpec(
        "smtp_password",
        "SMTP 密码",
        GROUP_MAIL,
        "string",
        "",
        "登录邮件服务器的密码或授权码；加密入库，留空保持不变",
        max_length=512,
        secret=True,
    ),
    SettingSpec(
        "smtp_from",
        "发件人地址",
        GROUP_MAIL,
        "string",
        "",
        "验证码邮件的发件人；留空时使用 SMTP 用户名",
        max_length=255,
    ),
    SettingSpec(
        "smtp_timeout",
        "SMTP 超时",
        GROUP_MAIL,
        "int",
        15,
        "连接与发送的超时秒数",
        minimum=1,
        maximum=120,
    ),
    SettingSpec(
        "email_code_ttl_minutes",
        "验证码有效期",
        GROUP_MAIL,
        "int",
        10,
        "邮箱验证码的有效分钟数",
        minimum=1,
        maximum=60,
    ),
    SettingSpec(
        "email_code_resend_seconds",
        "重发间隔",
        GROUP_MAIL,
        "int",
        60,
        "同一邮箱同一用途两次发码的最短间隔（秒）",
        minimum=30,
        maximum=600,
    ),
    SettingSpec(
        "email_code_hourly_limit",
        "每小时发码上限",
        GROUP_MAIL,
        "int",
        5,
        "同一邮箱同一用途每小时最多发送次数",
        minimum=1,
        maximum=50,
    ),
    SettingSpec(
        "qq_host",
        "QQ API 域名",
        GROUP_QQ,
        "string",
        "https://api.bot.qq.com",
        "机器人未单独配置域名时使用的默认地址",
        max_length=255,
    ),
    SettingSpec(
        "qq_qps",
        "每秒上限",
        GROUP_QQ,
        "int",
        5,
        "单个机器人每秒最多发送数",
        minimum=1,
        maximum=1000,
    ),
    SettingSpec(
        "qq_qpm",
        "每分钟上限",
        GROUP_QQ,
        "int",
        30,
        "单个机器人每分钟最多发送数",
        minimum=1,
        maximum=100_000,
    ),
    SettingSpec(
        "qq_min_interval",
        "最小发送间隔",
        GROUP_QQ,
        "float",
        0.21,
        "两次发送之间的最小间隔（秒）",
        minimum=0,
        maximum=60,
    ),
    SettingSpec(
        "markdown_max_len",
        "Markdown 长度上限",
        GROUP_QQ,
        "int",
        4000,
        "Markdown 类型消息的长度上限",
        minimum=1,
        maximum=100_000,
    ),
    SettingSpec(
        "text_max_len",
        "文本长度上限",
        GROUP_QQ,
        "int",
        2000,
        "纯文本类型消息的长度上限",
        minimum=1,
        maximum=100_000,
    ),
)

SPECS: dict[str, SettingSpec] = {spec.key: spec for spec in CATALOG}
KEYS: tuple[str, ...] = tuple(spec.key for spec in CATALOG)

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _coerce(spec: SettingSpec, raw: Any) -> Any:
    """把接口传入值或库内字符串转换为声明类型，非法时抛 ValueError。"""
    if spec.kind == "bool":
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in _TRUE_VALUES
        raise ValueError(f"「{spec.label}」必须是布尔值")

    if spec.kind in ("int", "float"):
        if isinstance(raw, bool):
            raise ValueError(f"「{spec.label}」必须是数字")
        if isinstance(raw, str):
            try:
                raw = float(raw) if spec.kind == "float" else int(raw.strip())
            except ValueError as exc:
                raise ValueError(f"「{spec.label}」必须是数字") from exc
        if spec.kind == "int":
            if not isinstance(raw, int):
                if isinstance(raw, float) and raw.is_integer():
                    raw = int(raw)
                else:
                    raise ValueError(f"「{spec.label}」必须是整数")
            value: float = float(raw)
        else:
            if not isinstance(raw, (int, float)):
                raise ValueError(f"「{spec.label}」必须是数字")
            value = float(raw)
        if spec.minimum is not None and value < spec.minimum:
            raise ValueError(f"「{spec.label}」不能小于 {spec.minimum:g}")
        if spec.maximum is not None and value > spec.maximum:
            raise ValueError(f"「{spec.label}」不能大于 {spec.maximum:g}")
        return int(value) if spec.kind == "int" else value

    if not isinstance(raw, str):
        raise ValueError(f"「{spec.label}」必须是文本")
    value = raw.strip()
    if len(value) > spec.max_length:
        raise ValueError(f"「{spec.label}」不能超过 {spec.max_length} 个字符")
    if spec.kind == "select" and value not in spec.options:
        raise ValueError(f"「{spec.label}」取值非法")
    return value


def _serialize(spec: SettingSpec, value: Any, secret_key: str) -> str:
    if spec.secret:
        return encrypt_secret(str(value), secret_key)
    if spec.kind == "bool":
        return "true" if value else "false"
    return str(value)


class RuntimeSettings:
    """app.state.settings 的替身：非敏感配置读缓存，其余透传环境变量配置。"""

    def __init__(self, base: Settings) -> None:
        object.__setattr__(self, "_base", base)
        # 库内设置加载失败时仍反映环境变量，而不是直接落到硬编码默认值
        values = {
            spec.key: getattr(base, spec.key, spec.default) for spec in CATALOG
        }
        object.__setattr__(self, "_values", values)
        object.__setattr__(
            self,
            "_sources",
            {
                spec.key: "environment" if values[spec.key] != spec.default else "default"
                for spec in CATALOG
            },
        )

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        values = object.__getattribute__(self, "_values")
        if name in values:
            return values[name]
        return getattr(object.__getattribute__(self, "_base"), name)

    @property
    def secure_cookies(self) -> bool:
        if self.cookie_secure:
            return True
        return str(self.public_base_url or "").lower().startswith("https://")

    @property
    def smtp_configured(self) -> bool:
        """填了服务器地址与发件人后才启用邮件验证码。"""
        return bool(
            str(self.smtp_host or "").strip()
            and str(self.smtp_from or self.smtp_username or "").strip()
        )

    @property
    def tz(self) -> tzinfo:
        name = str(self.timezone or "").strip() or os.environ.get("TZ", "").strip()
        if name:
            try:
                return ZoneInfo(name)
            except Exception:  # noqa: BLE001 - 时区名非法或本机缺时区库时退回本机时区
                logger.warning("时区 %s 不可用，改用本机时区", name)
        return datetime.now().astimezone().tzinfo

    async def load(self, db: AsyncSession) -> None:
        """读取库内设置；缺失项把环境变量中的非默认值一次性落库。"""
        rows = {
            row.key: row.value
            for row in (
                await db.execute(select(SystemSetting).where(SystemSetting.key.in_(KEYS)))
            )
            .scalars()
            .all()
        }
        seeded = False
        for spec in CATALOG:
            if spec.key in rows:
                raw = rows[spec.key]
                if spec.secret:
                    try:
                        raw = decrypt_secret(raw, self._base.app_secret_key)
                    except DecryptError as exc:
                        logger.warning("系统设置 %s 解密失败：%s", spec.key, exc)
                        raw = ""
                try:
                    self._values[spec.key] = _coerce(spec, raw)
                    self._sources[spec.key] = "database"
                except ValueError as exc:
                    logger.warning("系统设置 %s 的值非法，改用默认值：%s", spec.key, exc)
                continue

            env_value = getattr(self._base, spec.key, spec.default)
            if env_value == spec.default:
                continue
            try:
                value = _coerce(spec, env_value)
            except ValueError as exc:
                logger.warning("环境变量 %s 的值非法，忽略：%s", spec.key, exc)
                continue
            self._values[spec.key] = value
            self._sources[spec.key] = "environment"
            db.add(
                SystemSetting(
                    key=spec.key,
                    value=_serialize(spec, value, self._base.app_secret_key),
                )
            )
            seeded = True
        if seeded:
            await db.commit()
            logger.info("已将环境变量中的非默认系统设置导入数据库")

    def validate(self, changes: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(changes) - set(SPECS))
        if unknown:
            raise ValueError(f"未知设置项：{', '.join(unknown)}")
        values: dict[str, Any] = {}
        for key, raw in changes.items():
            spec = SPECS[key]
            value = _coerce(spec, raw)
            # 敏感项留空表示保持原值，避免页面回显导致误清空
            if spec.secret and value == "":
                continue
            values[key] = value
        return values

    async def persist(self, db: AsyncSession, values: dict[str, Any]) -> None:
        """写入待提交事务，由调用方统一提交。"""
        for key, value in values.items():
            row = await db.get(SystemSetting, key)
            text = _serialize(SPECS[key], value, self._base.app_secret_key)
            if row is None:
                db.add(SystemSetting(key=key, value=text))
            else:
                row.value = text

    def apply(self, values: dict[str, Any]) -> None:
        for key, value in values.items():
            self._values[key] = value
            self._sources[key] = "database"

    def source_of(self, key: str) -> str:
        return self._sources.get(key, "default")

    def describe_groups(self) -> list[dict]:
        groups: dict[str, list[dict]] = {}
        for spec in CATALOG:
            groups.setdefault(spec.group, []).append(
                {
                    "key": spec.key,
                    "label": spec.label,
                    "description": spec.description,
                    "kind": spec.kind,
                    "value": "" if spec.secret else self._values[spec.key],
                    "default": spec.default,
                    "minimum": spec.minimum,
                    "maximum": spec.maximum,
                    "options": list(spec.options),
                    "source": self._sources[spec.key],
                    "secret": spec.secret,
                    "has_value": bool(self._values[spec.key]) if spec.secret else None,
                }
            )
        return [{"name": name, "items": items} for name, items in groups.items()]

    def apply_side_effects(self, app) -> None:
        """让日志级别与进程内限速器立即采用新值。"""
        level = getattr(logging, str(self.log_level).upper(), None)
        if isinstance(level, int):
            root = logging.getLogger()
            root.setLevel(level)
            for handler in root.handlers:
                handler.setLevel(level)

        limiters = getattr(app.state, "limiters", None)
        if limiters is not None:
            limiters.configure(
                qps=self.qq_qps,
                qpm=self.qq_qpm,
                min_interval=self.qq_min_interval,
            )
        login_limiter = getattr(app.state, "login_limiter", None)
        if login_limiter is not None:
            login_limiter.configure(
                pair_limit=self.login_max_failures,
                ip_limit=self.login_ip_max_failures,
                window_seconds=self.login_window_seconds,
            )
