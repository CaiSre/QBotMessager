"""Passkey（WebAuthn）登记与认证。

challenge 由服务端生成并按会话（临时 cookie）保存；认证成功后必须回写 sign_count，
否则下次认证会被判定为凭据克隆。
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

CHALLENGE_COOKIE = "webauthn_challenge"


@dataclass
class RegistrationResult:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    aaguid: str
    device_type: str | None
    backed_up: bool


@dataclass
class AuthenticationResult:
    new_sign_count: int
    device_type: str | None
    backed_up: bool


def _device_type(value: object | None) -> str | None:
    """webauthn 返回的枚举取 value（如 single_device），避免 str(Enum) 超出库字段长度。"""
    if value is None:
        return None
    return str(getattr(value, "value", value))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def registration_options(
    *, rp_id: str, rp_name: str, user_id: int, user_name: str, challenge: bytes
) -> str:
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=str(user_id).encode("utf-8"),
        user_name=user_name,
        user_display_name=user_name,
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return options_to_json(options)


def authentication_options(*, rp_id: str, challenge: bytes, credential_ids: list[bytes]) -> str:
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cid) for cid in credential_ids],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options_to_json(options)


def verify_registration(
    *, credential: dict, challenge: bytes, rp_id: str, origin: str
) -> RegistrationResult:
    verified = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
    )
    return RegistrationResult(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        aaguid=str(verified.aaguid),
        device_type=_device_type(verified.credential_device_type),
        backed_up=bool(verified.credential_backed_up),
    )


def verify_authentication(
    *,
    credential: dict,
    challenge: bytes,
    rp_id: str,
    origin: str,
    public_key: bytes,
    current_sign_count: int,
) -> AuthenticationResult:
    verified = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=public_key,
        credential_current_sign_count=current_sign_count,
    )
    return AuthenticationResult(
        new_sign_count=verified.new_sign_count,
        device_type=_device_type(verified.credential_device_type),
        backed_up=bool(verified.credential_backed_up),
    )


def parse_credential_json(raw: str | bytes | dict) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("凭证格式非法")
    return data
