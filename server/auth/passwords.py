"""密码哈希：标准库 PBKDF2-HMAC-SHA256，不引入 bcrypt/passlib。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
DEFAULT_ROUNDS = 600_000

# 计时均衡用的哑元哈希，首次用到时才生成
_dummy_hash: str | None = None


def hash_password(password: str, *, salt: bytes | None = None, rounds: int = DEFAULT_ROUNDS) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return "$".join(
        [
            ALGORITHM,
            str(rounds),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        algorithm, rounds_s, salt_b64, digest_b64 = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        rounds = int(rounds_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(actual, expected)


def burn_password(password: str) -> None:
    """账号不存在时消耗一次等价 PBKDF2 计算。

    否则「邮箱未注册」会明显快于「密码错误」，攻击者可用响应时间枚举已注册邮箱。
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("qbotmessager-timing-equalizer")
    verify_password(password, _dummy_hash)
