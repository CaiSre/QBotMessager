"""首次启动引导：超级管理员账号，并把 .env 中的 QQ 凭据导入为默认机器人与通道。"""

from __future__ import annotations

import logging
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.auth.passwords import hash_password
from server.config import Settings
from server.db.crypto import encrypt_secret
from server.db.models import (
    PLATFORM_DINGTALK,
    PLATFORM_FEISHU,
    PLATFORM_WECOM,
    ROLE_SUPER_ADMIN,
    STATUS_ACTIVE,
    BotProfile,
    Channel,
    User,
)

logger = logging.getLogger(__name__)


def generate_webhook_token() -> str:
    return secrets.token_urlsafe(24)


async def bootstrap(session: AsyncSession, settings: Settings) -> dict:
    """幂等引导。返回本次创建的实体摘要，用于启动日志。"""
    created: dict[str, object] = {}

    admin: User | None = None
    if settings.bootstrap_admin_email and settings.bootstrap_admin_password:
        admin = (
            await session.execute(
                select(User).where(User.email == settings.bootstrap_admin_email)
            )
        ).scalar_one_or_none()
        if admin is None:
            admin = User(
                email=settings.bootstrap_admin_email,
                name=settings.bootstrap_admin_email.split("@")[0],
                password_hash=hash_password(settings.bootstrap_admin_password),
                role=ROLE_SUPER_ADMIN,
            )
            session.add(admin)
            await session.flush()
            created["admin"] = admin.email
            logger.info("已创建初始超级管理员账号 %s", admin.email)
        elif admin.role != ROLE_SUPER_ADMIN:
            active_super = (
                await session.execute(
                    select(User.id)
                    .where(User.role == ROLE_SUPER_ADMIN, User.status == STATUS_ACTIVE)
                    .limit(1)
                )
            ).scalar_one_or_none()
            if active_super is None:
                admin.role = ROLE_SUPER_ADMIN
                created["admin_promoted"] = admin.email
                logger.warning("系统中没有可用超级管理员，已将 %s 提升为超级管理员", admin.email)
    else:
        logger.warning("未配置 BOOTSTRAP_ADMIN_EMAIL/PASSWORD，系统可能没有超级管理员")

    if admin is None:
        if settings.qq_appid and settings.qq_app_secret:
            logger.warning("未配置初始超级管理员，跳过 QQ 机器人导入")
        await session.commit()
        return created

    existing_bot = (
        await session.execute(
            select(BotProfile).where(BotProfile.owner_user_id == admin.id)
        )
    ).scalars().first()
    if existing_bot is None and settings.qq_appid and settings.qq_app_secret:
        bot = BotProfile(
            owner_user_id=admin.id,
            name="默认机器人",
            qq_appid=settings.qq_appid,
            qq_app_secret=encrypt_secret(settings.qq_app_secret, settings.app_secret_key),
            qq_host=settings.qq_host,
            default_openids=settings.openids,
        )
        session.add(bot)
        await session.flush()
        for platform in (PLATFORM_DINGTALK, PLATFORM_WECOM, PLATFORM_FEISHU):
            session.add(
                Channel(
                    bot_profile_id=bot.id,
                    platform=platform,
                    webhook_token=generate_webhook_token(),
                )
            )
        created["bot_profile"] = bot.name
        logger.info("已从环境变量导入默认 QQ 机器人配置")

    await session.commit()
    return created
