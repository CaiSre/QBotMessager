"""一次 Webhook 推送的执行：QQ 发送与推送日志落库。

Webhook 进程（未配置 Redis 时的同步回退）与 SAQ worker 共用这里的逻辑，
因此任务所需的字段全部放在 PushJob 里，不依赖请求上下文。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from server.db.crypto import decrypt_secret
from server.db.models import PushLog
from server.db.session import get_session_factory
from server.renderer import QqPayload
from server.services.qq import QqClient, QqError, QqTarget
from server.services.throttle import RateLimiter

if TYPE_CHECKING:
    from server.services.queue import SentGuard

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PushJob:
    """一次推送任务；字段必须可序列化，便于写入队列交给 worker。"""

    request_id: str
    platform: str
    channel_id: int | None
    bot_id: int
    owner_user_id: int
    bot_host: str
    bot_appid: str
    app_secret_cipher: str
    source_msgtype: str
    msg_type: int
    content: str
    markdown: str | None
    targets: tuple[QqTarget, ...]

    def to_dict(self) -> dict:
        """转为 JSON 可序列化的载荷，供 SAQ 写入 Redis。"""
        return {
            "request_id": self.request_id,
            "platform": self.platform,
            "channel_id": self.channel_id,
            "bot_id": self.bot_id,
            "owner_user_id": self.owner_user_id,
            "bot_host": self.bot_host,
            "bot_appid": self.bot_appid,
            "app_secret_cipher": self.app_secret_cipher,
            "source_msgtype": self.source_msgtype,
            "msg_type": self.msg_type,
            "content": self.content,
            "markdown": self.markdown,
            "targets": [
                {"openid": target.openid, "group_openid": target.group_openid}
                for target in self.targets
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> PushJob:
        """从队列载荷还原任务。"""
        return cls(
            request_id=data["request_id"],
            platform=data["platform"],
            channel_id=data["channel_id"],
            bot_id=data["bot_id"],
            owner_user_id=data["owner_user_id"],
            bot_host=data["bot_host"],
            bot_appid=data["bot_appid"],
            app_secret_cipher=data["app_secret_cipher"],
            source_msgtype=data["source_msgtype"],
            msg_type=data["msg_type"],
            content=data["content"],
            markdown=data["markdown"],
            targets=tuple(
                QqTarget(openid=item.get("openid"), group_openid=item.get("group_openid"))
                for item in data["targets"]
            ),
        )


@dataclass
class PushOutcome:
    """每个目标一条错误信息（None 表示成功）。"""

    errors: list[str | None]
    # 全部目标失败且错误都标记为可重试时才允许整体重试，避免重复推送已成功的目标
    retryable: bool = False

    @property
    def failed(self) -> list[str]:
        return [error for error in self.errors if error]


async def execute_push(
    job: PushJob,
    *,
    settings,
    client: QqClient,
    limiter: RateLimiter,
    sent: SentGuard | None = None,
) -> PushOutcome:
    """逐个目标串行发送并落推送日志。

    发送期间不持有数据库连接；每个目标发送后立即用短事务写一条日志，
    这样任务被取消或超时时，已处理的目标也不会丢失审计记录。
    sent 用于跳过本次投递中已经发送成功的目标：队列任务被取消或超时后重跑时，
    不应把已经送达的目标再发一遍。
    """
    try:
        app_secret = decrypt_secret(job.app_secret_cipher, settings.app_secret_key)
    except Exception:  # noqa: BLE001 - 密钥不匹配时统一报配置错误
        logger.exception("机器人密钥无法解密（bot=%s）", job.bot_id)
        error = "机器人密钥无法解密，请检查 APP_SECRET_KEY"
        return PushOutcome(errors=[error] * len(job.targets))

    payload = QqPayload(msg_type=job.msg_type, content=job.content, markdown=job.markdown)
    text = payload.text

    errors: list[str | None] = []
    retryable_flags: list[bool] = []
    for target in job.targets:
        guard_key = f"{job.request_id}:{target.label()}"
        if sent is not None:
            try:
                if await sent.done(guard_key):
                    # 上一轮已经送达，日志也已写成功，这里不再重复发送与记录
                    errors.append(None)
                    retryable_flags.append(False)
                    continue
            except Exception:  # noqa: BLE001 - 读不到标记时按未发送处理，宁可重发也不丢消息
                logger.warning("读取推送完成标记失败：%s", guard_key, exc_info=True)

        started = time.perf_counter()
        error: str | None = None
        error_code: str | None = None
        retryable = False
        try:
            await client.send(
                key=f"bot:{job.bot_id}",
                host=job.bot_host or settings.qq_host,
                app_id=job.bot_appid,
                app_secret=app_secret,
                target=target,
                payload=payload,
                before_attempt=limiter.acquire,
            )
        except QqError as exc:
            error, error_code, retryable = exc.message, exc.code, exc.retryable
            logger.warning("QQ 推送失败 [%s] %s: %s", target.label(), exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - 记录后按失败处理，避免中断其他目标
            error, error_code = str(exc), "unexpected"
            logger.exception("QQ 推送异常 [%s]", target.label())

        if error is None and sent is not None:
            try:
                await sent.mark(guard_key)
            except Exception:  # noqa: BLE001 - 标记写失败只会导致重跑时重发，不影响本次结果
                logger.warning("写入推送完成标记失败：%s", guard_key, exc_info=True)

        duration_ms = (time.perf_counter() - started) * 1000
        # 每个目标发送后立即用短事务写日志：任务被取消或超时时，已处理的目标仍有审计记录
        try:
            async with get_session_factory()() as db:
                db.add(
                    PushLog(
                        owner_user_id=job.owner_user_id,
                        channel_id=job.channel_id,
                        bot_profile_id=job.bot_id,
                        platform=job.platform,
                        source_msgtype=job.source_msgtype,
                        target=target.to_db_value(),
                        qq_msg_type=job.msg_type,
                        content_preview=text[:200],
                        content_len=len(text),
                        status="success" if error is None else "failed",
                        error_code=error_code,
                        error_message=error,
                        duration_ms=round(duration_ms, 2),
                        request_id=job.request_id,
                    )
                )
                await db.commit()
        except Exception:  # noqa: BLE001 - 日志写入失败不应影响推送结果
            logger.exception("写入推送日志失败（request_id=%s）", job.request_id)
        errors.append(error)
        retryable_flags.append(retryable)

    failures = [error for error in errors if error]
    return PushOutcome(
        errors=errors,
        retryable=bool(failures) and len(failures) == len(errors) and all(retryable_flags),
    )
