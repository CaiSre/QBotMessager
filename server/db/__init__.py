"""数据库基础设施。"""

from __future__ import annotations

from server.db.base import Base
from server.db.models import (
    AdminAuditLog,
    AuthIdentity,
    BotProfile,
    Channel,
    EnvConfig,
    InviteCode,
    OAuthProvider,
    PushLog,
    Session,
    SystemSetting,
    User,
    WebAuthnCredential,
)
from server.db.session import (
    build_engine,
    dispose_engine,
    get_session,
    session_scope,
)

metadata = Base.metadata

__all__ = [
    "AdminAuditLog",
    "AuthIdentity",
    "Base",
    "BotProfile",
    "Channel",
    "EnvConfig",
    "InviteCode",
    "OAuthProvider",
    "PushLog",
    "Session",
    "SystemSetting",
    "User",
    "WebAuthnCredential",
    "build_engine",
    "dispose_engine",
    "get_session",
    "metadata",
    "session_scope",
]
