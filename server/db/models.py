"""ORM 模型：账号、鉴权凭据、机器人配置、通道、日志、系统设置、审计。"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column

from server.db.base import Base, TimestampMixin, utcnow

# 角色与状态取值
ROLE_SUPER_ADMIN = "super_admin"
ROLE_USER = "user"
ROLES = (ROLE_SUPER_ADMIN, ROLE_USER)

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"

PLATFORM_DINGTALK = "dingtalk"
PLATFORM_WECOM = "wecom"
PLATFORM_FEISHU = "feishu"
PLATFORMS = (PLATFORM_DINGTALK, PLATFORM_WECOM, PLATFORM_FEISHU)

# MySQL 用 BIGINT 自增；SQLite 只认 INTEGER PRIMARY KEY 才自增（测试用）
_AUTO_PK = BigInteger().with_variant(Integer, "sqlite")


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default=ROLE_USER, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=STATUS_ACTIVE, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuthIdentity(TimestampMixin, Base):
    """OAuth2 提供方与用户的绑定关系。"""

    __tablename__ = "auth_identities"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_identity_provider_uid"),
    )

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_login: Mapped[str | None] = mapped_column(String(255), nullable=True)


class WebAuthnCredential(TimestampMixin, Base):
    """Passkey（WebAuthn）凭据。"""

    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=False, index=True
    )
    # MySQL 的 BLOB 不能直接建唯一索引，凭据 ID 用 VARBINARY；SQLite 仍为 BLOB。
    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary().with_variant(mysql.VARBINARY(255), "mysql"),
        nullable=False,
        unique=True,
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    aaguid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transports: Mapped[list | None] = mapped_column(JSON, nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    backed_up: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    label: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Session(TimestampMixin, Base):
    """服务端会话；Cookie 只保存 token，库里只存哈希。"""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=False, index=True
    )
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class InviteCode(TimestampMixin, Base):
    """超级管理员邀请码；注册用户一律为普通用户。"""

    __tablename__ = "invite_codes"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    used_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=True
    )


class BotProfile(TimestampMixin, Base):
    """用户的 QQ 机器人配置。"""

    __tablename__ = "bot_profiles"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    qq_appid: Mapped[str] = mapped_column(String(128), nullable=False)
    qq_app_secret: Mapped[str] = mapped_column(Text, nullable=False)
    qq_host: Mapped[str] = mapped_column(
        String(255), default="https://api.bot.qq.com", nullable=False
    )
    default_openids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    default_group_openid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Channel(TimestampMixin, Base):
    """平台接入通道；webhook_token 用于反查所属机器人。"""

    __tablename__ = "channels"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    bot_profile_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("bot_profiles.id"), nullable=False, index=True
    )
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    webhook_token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class PushLog(TimestampMixin, Base):
    """推送日志（审计）。"""

    __tablename__ = "push_logs"
    __table_args__ = (
        Index("ix_push_logs_owner_created", "owner_user_id", "created_at"),
        Index("ix_push_logs_created", "created_at"),
        Index("ix_push_logs_status", "status"),
    )

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=False
    )
    # 机器人/通道删除后日志仍保留，归属判断不依赖它们。
    channel_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("channels.id", ondelete="SET NULL"), nullable=True
    )
    bot_profile_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("bot_profiles.id", ondelete="SET NULL"), nullable=True
    )
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    source_msgtype: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    qq_msg_type: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)
    content_len: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)


class EmailVerificationCode(TimestampMixin, Base):
    """邮箱验证码：只保存哈希，按用途与邮箱匹配，一次性消费。"""

    __tablename__ = "email_verification_codes"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AdminAuditLog(TimestampMixin, Base):
    """后台写操作审计。"""

    __tablename__ = "admin_audit_logs"
    __table_args__ = (Index("ix_audit_actor_created", "actor_user_id", "created_at"),)

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class OAuthProvider(TimestampMixin, Base):
    """通用 OAuth2 提供方配置（GitHub 等）；client_secret 加密入库。"""

    __tablename__ = "oauth_providers"

    id: Mapped[int] = mapped_column(_AUTO_PK, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret: Mapped[str] = mapped_column(Text, nullable=False)
    authorization_url: Mapped[str] = mapped_column(String(512), nullable=False)
    token_url: Mapped[str] = mapped_column(String(512), nullable=False)
    userinfo_url: Mapped[str] = mapped_column(String(512), nullable=False)
    scopes: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    email_field: Mapped[str] = mapped_column(String(64), default="email", nullable=False)
    id_field: Mapped[str] = mapped_column(String(64), default="id", nullable=False)
    name_field: Mapped[str] = mapped_column(String(64), default="name", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # 该提供方的邮箱是否可信（提供方已验证过邮箱所有权）；
    # 不可信时不会自动关联同邮箱的本地账号，避免冒名登录接管
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class SystemSetting(TimestampMixin, Base):
    """全局开关（注册开关等）。"""

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
