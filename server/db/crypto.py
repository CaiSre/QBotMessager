"""敏感字段的落库加密（Fernet）。

APP_SECRET_KEY 缺失时降级为明文存储（带前缀标记），并在启动时告警；
密钥更换后旧密文无法解密，需重新录入。
"""

from __future__ import annotations

import logging

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

ENC_PREFIX = "enc1:"
PLAIN_PREFIX = "plain1:"


class DecryptError(RuntimeError):
    """密文无法解密（通常是主密钥不匹配）。"""


def encrypt_secret(plain: str, key: str) -> str:
    if plain == "":
        return ""
    if not key:
        return PLAIN_PREFIX + plain
    token = Fernet(key.encode() if isinstance(key, str) else key).encrypt(
        plain.encode("utf-8")
    )
    return ENC_PREFIX + token.decode("ascii")


def decrypt_secret(stored: str, key: str) -> str:
    if not stored:
        return ""
    if stored.startswith(ENC_PREFIX):
        if not key:
            raise DecryptError("密文存在但未配置 APP_SECRET_KEY，无法解密")
        raw = stored[len(ENC_PREFIX) :]
        try:
            return Fernet(key.encode() if isinstance(key, str) else key).decrypt(
                raw.encode("ascii")
            ).decode("utf-8")
        except InvalidToken as exc:  # 密钥不匹配或密文损坏
            raise DecryptError("解密失败：APP_SECRET_KEY 与密文不匹配") from exc
    if stored.startswith(PLAIN_PREFIX):
        return stored[len(PLAIN_PREFIX) :]
    return stored


def is_encrypted(stored: str) -> bool:
    return stored.startswith(ENC_PREFIX)


def mask_secret(value: str) -> str:
    """界面回显用的掩码：保留首尾各 2 位。"""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:2]}{'*' * 6}{value[-2:]}"
