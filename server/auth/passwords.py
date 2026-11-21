"""密码哈希：标准库 PBKDF2-HMAC-SHA256，不引入 bcrypt/passlib。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
DEFAULT_ROUNDS = 600_000


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
