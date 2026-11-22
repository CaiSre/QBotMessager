//! Passkey（WebAuthn）注册与断言。
//!
//! 与 Python `server/auth/passkey.py` 的数据/协议兼容点：
//! - user handle = `str(user_id)` 的 UTF-8 字节；
//! - 支持算法固定为 `[-8 EdDSA, -7 ES256, -257 RS256]`；
//! - challenge = 32 随机字节 → base64url 无填充，放 Cookie `webauthn_challenge`；
//! - 库内 `public_key` 是 **COSE 原始字节**（Python 直接存
//!   `verified.credential_public_key`），因此 Rust 必须能从原始字节反序列化出公钥；
//! - 认证成功后回写 sign_count / last_used_at / device_type / backed_up；
//! - 签名计数回退 `(current > 0 || stored > 0) && current <= stored` 一律拒绝。
//!
//! webauthn-rs 的注册/认证校验需要成对的 ceremony state（含 challenge），
//! Python 只把 challenge 放在 Cookie 里。这里额外用 `webauthn_state` Cookie
//! 保存 base64url 编码的 state JSON；`webauthn_challenge` 仍按旧协议保存
//! challenge，本地校验时两者必须一致。

use std::time::Duration as StdDuration;

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, AttestationFormat, AuthenticationState, COSEAlgorithm,
    COSEEC2Key, COSEKey, COSEKeyType, COSEOKPKey, COSERSAKey, Credential, ECDSACurve, EDDSACurve,
    ParsedAttestation, PublicKeyCredential, RegisterPublicKeyCredential, RegisteredExtensions,
    RegistrationState, ResidentKeyRequirement, UserVerificationPolicy,
};

use crate::error::AppError;
use crate::services::runtime_settings::RuntimeSettings;

/// challenge Cookie 名（与 Python 完全一致）。
pub const CHALLENGE_COOKIE: &str = "webauthn_challenge";
/// 注册时绑定用户 ID 的 Cookie 名（与 Python 完全一致）。
pub const USER_COOKIE: &str = "webauthn_user";
/// ceremony state 的附加 Cookie 名。
pub const STATE_COOKIE: &str = "webauthn_state";
/// 临时 Cookie 有效期（秒）。
pub const COOKIE_MAX_AGE_SECONDS: i64 = 300;
/// WebAuthn 超时（秒）。
const WEBAUTHN_TIMEOUT_SECONDS: u64 = 300;
/// CBOR 嵌套深度上限，避免恶意数据导致栈溢出。
const CBOR_MAX_DEPTH: usize = 64;

/// 注册挑战的生成结果。
#[derive(Debug, Clone)]
pub struct RegistrationBegin {
    /// 下发给浏览器的 `PublicKeyCredentialCreationOptions`。
    pub options: Value,
    /// base64url 无填充的 challenge（写入 `webauthn_challenge`）。
    pub challenge: String,
    /// base64url 编码的 ceremony state（写入 `webauthn_state`）。
    pub state: String,
}

/// 断言挑战的生成结果。
#[derive(Debug, Clone)]
pub struct AuthenticationBegin {
    /// 下发给浏览器的 `PublicKeyCredentialRequestOptions`。
    pub options: Value,
    /// base64url 无填充的 challenge。
    pub challenge: String,
    /// base64url 编码的 ceremony state。
    pub state: String,
}

/// 注册校验结果（字段直接对应 `webauthn_credentials` 列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationResult {
    /// 凭据 ID（原始字节）。
    pub credential_id: Vec<u8>,
    /// COSE 公钥原始字节（与 Python 存量格式一致）。
    pub public_key: Vec<u8>,
    /// 签名计数。
    pub sign_count: i64,
    /// AAGUID（UUID 字符串，全零时也是合法 UUID）。
    pub aaguid: String,
    /// `single_device` / `multi_device`。
    pub device_type: String,
    /// 是否已备份（BS 标志）。
    pub backed_up: bool,
}

/// 认证校验结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAuthentication {
    /// 新的签名计数（调用方必须回写）。
    pub new_sign_count: u32,
    /// `single_device` / `multi_device`。
    pub device_type: String,
    /// 是否已备份。
    pub backed_up: bool,
    /// 本次断言是否提供了用户验证。
    pub user_verified: bool,
}

/// 库内已保存的凭据（认证时构造 `Credential` 所需的最小集合）。
#[derive(Debug, Clone, Copy)]
pub struct StoredCredential<'a> {
    /// 凭据 ID。
    pub credential_id: &'a [u8],
    /// COSE 公钥原始字节。
    pub public_key: &'a [u8],
    /// 已保存的签名计数（数据库列为 BIGINT）。
    pub sign_count: i64,
    /// 已保存的设备类型（`single_device` / `multi_device`）。
    pub device_type: Option<&'a str>,
    /// 已保存的备份状态。
    pub backed_up: bool,
}

/// 支持算法：EdDSA、ES256、RS256。
pub fn allowed_algorithms() -> Vec<COSEAlgorithm> {
    vec![
        COSEAlgorithm::EDDSA,
        COSEAlgorithm::ES256,
        COSEAlgorithm::RS256,
    ]
}

/// 发起注册：生成 options 与 ceremony state。
pub fn registration_options(
    rp_id: &str,
    rp_name: &str,
    origin: &str,
    user_id: i64,
    user_name: &str,
) -> Result<RegistrationBegin, AppError> {
    let core = build_core(rp_id, rp_name, origin)?;
    // user handle 必须是 str(user_id) 的字节形式，不能换成随机 UUID。
    let user_handle = user_id.to_string();
    let builder = core
        .new_challenge_register_builder(user_handle.as_bytes(), user_name, user_name)
        .map_err(|err| AppError::internal(format!("WebAuthn 配置错误：{err}")))?
        .attestation(AttestationConveyancePreference::None)
        .credential_algorithms(allowed_algorithms())
        // PREFERRED：不强制常驻凭据，但也不像 Discouraged 那样劝退。
        .require_resident_key(false)
        .user_verification_policy(UserVerificationPolicy::Preferred)
        .reject_synchronised_authenticators(false)
        .exclude_credentials(None)
        .hints(None)
        .extensions(None);

    let (mut options, state) = core
        .generate_challenge_register(builder)
        .map_err(|err| AppError::internal(format!("WebAuthn 配置错误：{err}")))?;
    // webauthn-rs 只能表达 Required/Discouraged；按规格书覆盖为 PREFERRED。
    if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Preferred);
    }

    let challenge = b64url_encode(&options.public_key.challenge);
    let state = encode_state(
        &serde_json::to_string(&state)
            .map_err(|err| AppError::internal(format!("WebAuthn 状态序列化失败：{err}")))?,
    );
    let options = serde_json::to_value(&options)
        .map_err(|err| AppError::internal(format!("WebAuthn 选项序列化失败：{err}")))?;

    Ok(RegistrationBegin {
        options,
        challenge,
        state,
    })
}

/// 发起断言（可发现凭据流程，allowCredentials 为空）。
pub fn authentication_options(
    rp_id: &str,
    rp_name: &str,
    origin: &str,
) -> Result<AuthenticationBegin, AppError> {
    let core = build_core(rp_id, rp_name, origin)?;
    let builder = core
        .new_challenge_authenticate_builder(Vec::new(), Some(UserVerificationPolicy::Preferred))
        .map_err(|err| AppError::internal(format!("WebAuthn 配置错误：{err}")))?
        .extensions(None)
        .allow_backup_eligible_upgrade(true)
        .hints(None);

    let (options, state) = core
        .generate_challenge_authenticate(builder)
        .map_err(|err| AppError::internal(format!("WebAuthn 配置错误：{err}")))?;

    let challenge = b64url_encode(&options.public_key.challenge);
    let state = encode_state(
        &serde_json::to_string(&state)
            .map_err(|err| AppError::internal(format!("WebAuthn 状态序列化失败：{err}")))?,
    );
    let options = serde_json::to_value(&options)
        .map_err(|err| AppError::internal(format!("WebAuthn 选项序列化失败：{err}")))?;

    Ok(AuthenticationBegin {
        options,
        challenge,
        state,
    })
}

/// 校验注册响应。
///
/// `expected_challenge` 来自 `webauthn_challenge` Cookie（已解码的原始字节），
/// `state_cookie` 来自 `webauthn_state` Cookie。
pub fn verify_registration(
    credential: &RegisterPublicKeyCredential,
    expected_challenge: &[u8],
    rp_id: &str,
    rp_name: &str,
    origin: &str,
    state_cookie: &str,
) -> Result<RegistrationResult, AppError> {
    let state: RegistrationState =
        decode_state(state_cookie).map_err(|_| AppError::bad_request("注册会话已过期，请重试"))?;

    let client_challenge = client_data_challenge(&credential.response.client_data_json)?;
    if client_challenge != expected_challenge {
        return Err(AppError::bad_request("Passkey 校验失败：challenge 不匹配"));
    }

    let core = build_core(rp_id, rp_name, origin)?;
    let passkey = core
        .register_credential(credential, &state, None)
        .map_err(|err| AppError::bad_request(format!("Passkey 校验失败：{err}")))?;

    // 直接从 attestationObject 提取原始 COSE 公钥字节，保证与 Python 存量格式一致。
    let attested = extract_attested_credential(&credential.response.attestation_object)?;

    Ok(RegistrationResult {
        credential_id: passkey.cred_id.clone(),
        public_key: attested.public_key,
        sign_count: i64::from(passkey.counter),
        aaguid: attested.aaguid,
        device_type: device_type(passkey.backup_eligible).to_string(),
        backed_up: passkey.backup_state,
    })
}

/// 校验断言响应。
pub fn verify_authentication(
    credential: &PublicKeyCredential,
    expected_challenge: &[u8],
    rp_id: &str,
    rp_name: &str,
    origin: &str,
    state_cookie: &str,
    stored: StoredCredential<'_>,
) -> Result<PasskeyAuthentication, AppError> {
    let state: AuthenticationState =
        decode_state(state_cookie).map_err(|_| AppError::bad_request("登录会话已过期，请重试"))?;

    let client_challenge = client_data_challenge(&credential.response.client_data_json)?;
    if client_challenge != expected_challenge {
        return Err(AppError::unauthorized("Passkey 校验失败：challenge 不匹配"));
    }

    // 先做一次显式回滚检测，随后 webauthn-rs 内部还会再校验一次。
    let current = authenticator_sign_count(&credential.response.authenticator_data)
        .ok_or_else(|| AppError::unauthorized("Passkey 校验失败：认证数据格式非法"))?;
    let stored_count = u32::try_from(stored.sign_count)
        .map_err(|_| AppError::unauthorized("Passkey 校验失败：凭据签名计数非法"))?;
    if sign_counter_rollback(current, stored_count) {
        return Err(AppError::unauthorized(
            "Passkey 校验失败：签名计数回退，凭据可能已被复制",
        ));
    }

    let cose_key = cose_key_from_bytes(stored.public_key)
        .map_err(|_| AppError::unauthorized("Passkey 校验失败：公钥解析失败"))?;
    let stored_credential = Credential {
        cred_id: stored.credential_id.to_vec(),
        cred: cose_key,
        counter: stored_count,
        transports: None,
        // 存量数据只有 COSE 公钥；按未做 UV 处理，符合规格书「不要求 uv」。
        user_verified: false,
        backup_eligible: stored.device_type == Some(MULTI_DEVICE),
        backup_state: stored.backed_up,
        registration_policy: UserVerificationPolicy::Preferred,
        extensions: RegisteredExtensions::none(),
        attestation: ParsedAttestation::default(),
        attestation_format: AttestationFormat::None,
    };

    let core = build_core(rp_id, rp_name, origin)?;
    let result = core
        .authenticate_single_credential(credential, &state, &stored_credential)
        .map_err(|err| AppError::unauthorized(format!("Passkey 校验失败：{err}")))?;

    Ok(PasskeyAuthentication {
        new_sign_count: result.counter(),
        device_type: device_type(result.backup_eligible()).to_string(),
        backed_up: result.backup_state(),
        user_verified: result.user_verified(),
    })
}

/// `single_device` / `multi_device`；BACKUP_ELIGIBLE 即多设备凭据。
pub fn device_type(backup_eligible: bool) -> &'static str {
    if backup_eligible {
        MULTI_DEVICE
    } else {
        SINGLE_DEVICE
    }
}

/// 设备类型常量：单设备。
pub const SINGLE_DEVICE: &str = "single_device";
/// 设备类型常量：多设备。
pub const MULTI_DEVICE: &str = "multi_device";

/// 签名计数回退检测（规格书 6.5）。
///
/// 只有在两侧都为 0 时才允许相等；任一非零时 `current <= stored` 视为回退。
pub fn sign_counter_rollback(current: u32, stored: u32) -> bool {
    (current > 0 || stored > 0) && current <= stored
}

/// 解析 RP ID：设置值 → public_base_url 的 hostname → 请求 Host → localhost。
pub fn resolve_rp_id(rp_id_setting: &str, public_base_url: &str, host: Option<&str>) -> String {
    if !rp_id_setting.is_empty() {
        return rp_id_setting.to_string();
    }
    if let Ok(url) = Url::parse(public_base_url)
        && let Some(host) = url.host_str()
    {
        let host = strip_ipv6_brackets(host);
        if !host.is_empty() {
            return host.to_string();
        }
    }
    if let Some(host) = host.map(str::trim).filter(|host| !host.is_empty()) {
        // Host 头可能带端口；IPv6 字面量形如 [::1]:3000。
        if host.starts_with('[')
            && let Some(inner) = host
                .strip_prefix('[')
                .and_then(|rest| rest.split_once(']'))
                .map(|(inner, _)| inner)
        {
            return inner.to_string();
        }
        return host.split(':').next().unwrap_or(host).to_string();
    }
    "localhost".to_string()
}

fn strip_ipv6_brackets(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[')
        && let Some((inner, _)) = rest.split_once(']')
    {
        return inner;
    }
    host
}

/// 解析 origin：public_base_url（去尾部 `/`）或 `{scheme}://{host}`。
pub fn resolve_origin(public_base_url: &str, scheme: &str, host: Option<&str>) -> String {
    if !public_base_url.is_empty() {
        return public_base_url.trim_end_matches('/').to_string();
    }
    format!("{scheme}://{}", host.unwrap_or("localhost"))
}

/// challenge Cookie。
pub fn challenge_cookie(settings: &RuntimeSettings, challenge: &str) -> Cookie<'static> {
    passkey_cookie(CHALLENGE_COOKIE, challenge.to_string(), settings)
}

/// 注册用户 Cookie。
pub fn user_cookie(settings: &RuntimeSettings, user_id: i64) -> Cookie<'static> {
    passkey_cookie(USER_COOKIE, user_id.to_string(), settings)
}

/// ceremony state Cookie。
pub fn state_cookie(settings: &RuntimeSettings, state: &str) -> Cookie<'static> {
    passkey_cookie(STATE_COOKIE, state.to_string(), settings)
}

/// 删除全部 Passkey 临时 Cookie。
pub fn clear_passkey_cookies() -> Vec<Cookie<'static>> {
    [CHALLENGE_COOKIE, USER_COOKIE, STATE_COOKIE]
        .into_iter()
        .map(clear_cookie)
        .collect()
}

/// 构造删除指定 Cookie 的指令。
pub fn clear_cookie(name: &'static str) -> Cookie<'static> {
    Cookie::build(name, String::new())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .finish()
}

fn passkey_cookie(
    name: &'static str,
    value: String,
    settings: &RuntimeSettings,
) -> Cookie<'static> {
    Cookie::build(name, value)
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(COOKIE_MAX_AGE_SECONDS))
        .secure(settings.secure_cookies())
        .finish()
}

fn build_core(rp_id: &str, rp_name: &str, origin: &str) -> Result<WebauthnCore, AppError> {
    let origin = Url::parse(origin).map_err(|_| AppError::internal("WebAuthn origin 配置非法"))?;
    Ok(WebauthnCore::new_unsafe_experts_only(
        rp_name,
        rp_id,
        vec![origin],
        StdDuration::from_secs(WEBAUTHN_TIMEOUT_SECONDS),
        None,
        None,
    ))
}

/// base64url 无填充编码。
pub fn b64url_encode(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

/// base64url 解码；兼容带 `=` 填充的输入。
pub fn b64url_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(value.trim_end_matches('='))
}

fn encode_state(state_json: &str) -> String {
    b64url_encode(state_json.as_bytes())
}

fn decode_state<T: DeserializeOwned>(cookie_value: &str) -> Result<T, AppError> {
    let raw = b64url_decode(cookie_value)
        .map_err(|_| AppError::bad_request("WebAuthn 会话已过期，请重试"))?;
    serde_json::from_slice(&raw).map_err(|_| AppError::bad_request("WebAuthn 会话已过期，请重试"))
}

#[derive(Deserialize)]
struct ClientData {
    challenge: String,
}

fn client_data_challenge(raw: &[u8]) -> Result<Vec<u8>, AppError> {
    let data: ClientData = serde_json::from_slice(raw)
        .map_err(|err| AppError::bad_request(format!("Passkey 校验失败：{err}")))?;
    b64url_decode(&data.challenge)
        .map_err(|_| AppError::bad_request("Passkey 校验失败：challenge 格式非法"))
}

fn authenticator_sign_count(authenticator_data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = authenticator_data.get(33..37)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

struct AttestedCredential {
    aaguid: String,
    public_key: Vec<u8>,
}

/// 从 attestationObject（CBOR）→ authData → attestedCredentialData 中提取
/// AAGUID 与 credentialPublicKey 的原始 COSE 字节。
fn extract_attested_credential(attestation_object: &[u8]) -> Result<AttestedCredential, AppError> {
    let (root, _) = decode_cbor(attestation_object)
        .map_err(|_| AppError::bad_request("Passkey 校验失败：凭证格式非法"))?;
    let CborValue::Map(entries) = root else {
        return Err(AppError::bad_request("Passkey 校验失败：凭证格式非法"));
    };
    let auth_data = entries
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (CborValue::Text(name), CborValue::Bytes(bytes)) if name == "authData" => Some(bytes),
            _ => None,
        })
        .ok_or_else(|| AppError::bad_request("Passkey 校验失败：缺少 authData"))?;

    if auth_data.len() < 55 {
        return Err(AppError::bad_request("Passkey 校验失败：认证数据不完整"));
    }
    // flags 的 AT 位（0x40）表示后面跟 attestedCredentialData。
    if auth_data[32] & 0x40 == 0 {
        return Err(AppError::bad_request("Passkey 校验失败：缺少凭据公钥数据"));
    }
    let aaguid = Uuid::from_slice(&auth_data[37..53])
        .map_err(|_| AppError::bad_request("Passkey 校验失败：AAGUID 非法"))?
        .to_string();
    let credential_id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let public_key_start = 55usize
        .checked_add(credential_id_len)
        .ok_or_else(|| AppError::bad_request("Passkey 校验失败：认证数据非法"))?;
    let public_key_slice = auth_data
        .get(public_key_start..)
        .ok_or_else(|| AppError::bad_request("Passkey 校验失败：认证数据不完整"))?;
    let (_, consumed) = decode_cbor(public_key_slice)
        .map_err(|_| AppError::bad_request("Passkey 校验失败：公钥格式非法"))?;
    if consumed == 0 {
        return Err(AppError::bad_request("Passkey 校验失败：公钥格式非法"));
    }

    Ok(AttestedCredential {
        aaguid,
        public_key: public_key_slice[..consumed].to_vec(),
    })
}

/// 从 COSE 公钥原始字节反序列化出 `COSEKey`。
///
/// Python 存量数据是 `verified.credential_public_key`（CBOR 编码的 COSE_Key），
/// webauthn-rs 0.6.2 没有公开的 `from_cose_bytes`，这里实现所需的 CBOR 子集。
pub fn cose_key_from_bytes(bytes: &[u8]) -> Result<COSEKey, String> {
    let (value, consumed) = decode_cbor(bytes)?;
    if consumed != bytes.len() {
        return Err("COSE 公钥存在多余字节".to_string());
    }
    cose_key_from_value(&value)
}

fn cose_key_from_value(value: &CborValue) -> Result<COSEKey, String> {
    let CborValue::Map(entries) = value else {
        return Err("COSE 公钥不是 CBOR map".to_string());
    };
    let key_type = map_i64(entries, 1).ok_or("COSE 公钥缺少 kty")?;
    let algorithm = map_i64(entries, 3).ok_or("COSE 公钥缺少 alg")?;
    let algorithm = COSEAlgorithm::try_from(i128::from(algorithm))
        .map_err(|()| "不支持的 COSE 算法".to_string())?;
    if !matches!(
        algorithm,
        COSEAlgorithm::EDDSA | COSEAlgorithm::ES256 | COSEAlgorithm::RS256
    ) {
        return Err("不支持的 COSE 算法".to_string());
    }

    match key_type {
        // OKP（EdDSA）
        1 => {
            if algorithm != COSEAlgorithm::EDDSA {
                return Err("COSE 公钥类型与算法不匹配".to_string());
            }
            let curve = match map_i64(entries, -1).ok_or("COSE 公钥缺少 crv")? {
                6 => EDDSACurve::ED25519,
                7 => EDDSACurve::ED448,
                _ => return Err("不支持的 EdDSA 曲线".to_string()),
            };
            let x = map_bytes(entries, -2).ok_or("COSE 公钥缺少 x")?;
            let expected = match curve {
                EDDSACurve::ED25519 => 32,
                EDDSACurve::ED448 => 57,
            };
            if x.len() != expected {
                return Err("COSE 公钥坐标长度非法".to_string());
            }
            Ok(COSEKey {
                type_: algorithm,
                key: COSEKeyType::EC_OKP(COSEOKPKey {
                    curve,
                    x: x.to_vec(),
                }),
            })
        }
        // EC2（ES256）
        2 => {
            if !matches!(
                algorithm,
                COSEAlgorithm::ES256 | COSEAlgorithm::ES384 | COSEAlgorithm::ES521
            ) {
                return Err("COSE 公钥类型与算法不匹配".to_string());
            }
            let curve = match map_i64(entries, -1).ok_or("COSE 公钥缺少 crv")? {
                1 => ECDSACurve::SECP256R1,
                2 => ECDSACurve::SECP384R1,
                3 => ECDSACurve::SECP521R1,
                _ => return Err("不支持的 ECDSA 曲线".to_string()),
            };
            let x = map_bytes(entries, -2).ok_or("COSE 公钥缺少 x")?;
            let y = map_bytes(entries, -3).ok_or("COSE 公钥缺少 y")?;
            let expected = match curve {
                ECDSACurve::SECP256R1 => 32,
                ECDSACurve::SECP384R1 => 48,
                ECDSACurve::SECP521R1 => 66,
            };
            if x.len() != expected || y.len() != expected {
                return Err("COSE 公钥坐标长度非法".to_string());
            }
            Ok(COSEKey {
                type_: algorithm,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve,
                    x: x.to_vec(),
                    y: y.to_vec(),
                }),
            })
        }
        // RSA（RS256）
        3 => {
            if algorithm != COSEAlgorithm::RS256 {
                return Err("COSE 公钥类型与算法不匹配".to_string());
            }
            let n = map_bytes(entries, -1).ok_or("COSE 公钥缺少 n")?;
            let e = map_bytes(entries, -2).ok_or("COSE 公钥缺少 e")?;
            if n.is_empty() {
                return Err("COSE 公钥模数为空".to_string());
            }
            let exponent: [u8; 3] = e
                .try_into()
                .map_err(|_| "COSE RSA 指数长度非法".to_string())?;
            Ok(COSEKey {
                type_: algorithm,
                key: COSEKeyType::RSA(COSERSAKey {
                    n: n.to_vec(),
                    e: exponent,
                }),
            })
        }
        _ => Err("不支持的 COSE 公钥类型".to_string()),
    }
}

fn map_value(entries: &[(CborValue, CborValue)], key: i64) -> Option<&CborValue> {
    entries
        .iter()
        .find(|(entry_key, _)| cbor_i64(entry_key) == Some(key))
        .map(|(_, value)| value)
}

fn map_i64(entries: &[(CborValue, CborValue)], key: i64) -> Option<i64> {
    map_value(entries, key).and_then(cbor_i64)
}

fn map_bytes(entries: &[(CborValue, CborValue)], key: i64) -> Option<&[u8]> {
    match map_value(entries, key) {
        Some(CborValue::Bytes(bytes)) => Some(bytes),
        _ => None,
    }
}

fn cbor_i64(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Unsigned(value) => i64::try_from(*value).ok(),
        CborValue::Negative(value) => Some(*value),
        _ => None,
    }
}

/// CBOR 子集：COSE 公钥与 attestationObject 所需的类型。
#[derive(Debug, Clone, PartialEq)]
enum CborValue {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

fn decode_cbor(data: &[u8]) -> Result<(CborValue, usize), String> {
    let mut reader = CborReader { data, pos: 0 };
    let value = reader.read_value(0)?;
    Ok((value, reader.pos))
}

struct CborReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl CborReader<'_> {
    fn read_value(&mut self, depth: usize) -> Result<CborValue, String> {
        if depth > CBOR_MAX_DEPTH {
            return Err("CBOR 嵌套过深".to_string());
        }
        let (major, head) = self.read_head()?;
        match major {
            0 => Ok(CborValue::Unsigned(head)),
            1 => {
                let value = -1i128 - i128::from(head);
                let value = i64::try_from(value).map_err(|_| "CBOR 负整数越界".to_string())?;
                Ok(CborValue::Negative(value))
            }
            2 => {
                let length = usize::try_from(head).map_err(|_| "CBOR 长度非法".to_string())?;
                Ok(CborValue::Bytes(self.read_bytes(length)?))
            }
            3 => {
                let length = usize::try_from(head).map_err(|_| "CBOR 长度非法".to_string())?;
                let bytes = self.read_bytes(length)?;
                let text =
                    String::from_utf8(bytes).map_err(|_| "CBOR 文本不是合法 UTF-8".to_string())?;
                Ok(CborValue::Text(text))
            }
            4 => {
                let length = usize::try_from(head).map_err(|_| "CBOR 长度非法".to_string())?;
                let mut items = Vec::with_capacity(length.min(64));
                for _ in 0..length {
                    items.push(self.read_value(depth + 1)?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let length = usize::try_from(head).map_err(|_| "CBOR 长度非法".to_string())?;
                let mut entries = Vec::with_capacity(length.min(64));
                for _ in 0..length {
                    let key = self.read_value(depth + 1)?;
                    let value = self.read_value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(CborValue::Map(entries))
            }
            // tag：忽略标签，读取其内容。
            6 => self.read_value(depth + 1),
            7 => Ok(match head {
                20 => CborValue::Bool(false),
                21 => CborValue::Bool(true),
                22 | 23 => CborValue::Null,
                _ => CborValue::Null,
            }),
            _ => Err("非法 CBOR 主类型".to_string()),
        }
    }

    fn read_head(&mut self) -> Result<(u8, u64), String> {
        let initial = *self.data.get(self.pos).ok_or("CBOR 数据不完整")?;
        self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let head = match info {
            0..=23 => u64::from(info),
            24 => self.read_uint(1)?,
            25 => self.read_uint(2)?,
            26 => self.read_uint(4)?,
            27 => self.read_uint(8)?,
            31 => return Err("不支持不定长 CBOR".to_string()),
            _ => return Err("非法 CBOR 头".to_string()),
        };
        Ok((major, head))
    }

    fn read_uint(&mut self, length: usize) -> Result<u64, String> {
        let bytes = self.read_bytes(length)?;
        let mut value = 0u64;
        for byte in bytes {
            value = (value << 8) | u64::from(byte);
        }
        Ok(value)
    }

    fn read_bytes(&mut self, length: usize) -> Result<Vec<u8>, String> {
        let end = self
            .pos
            .checked_add(length)
            .ok_or_else(|| "CBOR 长度溢出".to_string())?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| "CBOR 数据不完整".to_string())?;
        self.pos = end;
        Ok(slice.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor_head(major: u8, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        match value {
            0..=23 => out.push((major << 5) | value as u8),
            24..=0xff => {
                out.push((major << 5) | 24);
                out.push(value as u8);
            }
            0x100..=0xffff => {
                out.push((major << 5) | 25);
                out.extend_from_slice(&(value as u16).to_be_bytes());
            }
            _ => {
                out.push((major << 5) | 26);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
        }
        out
    }

    fn cbor_int(value: i64) -> Vec<u8> {
        if value >= 0 {
            cbor_head(0, value as u64)
        } else {
            cbor_head(1, (-1i128 - i128::from(value)) as u64)
        }
    }

    fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut out = cbor_head(2, bytes.len() as u64);
        out.extend_from_slice(bytes);
        out
    }

    fn cbor_text(text: &str) -> Vec<u8> {
        let mut out = cbor_head(3, text.len() as u64);
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn cbor_map(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
        let mut out = cbor_head(5, entries.len() as u64);
        for (key, value) in entries {
            out.extend_from_slice(&key);
            out.extend_from_slice(&value);
        }
        out
    }

    fn sample_es256_cose() -> Vec<u8> {
        cbor_map(vec![
            (cbor_int(1), cbor_int(2)),
            (cbor_int(3), cbor_int(-7)),
            (cbor_int(-1), cbor_int(1)),
            (cbor_int(-2), cbor_bytes(&[7u8; 32])),
            (cbor_int(-3), cbor_bytes(&[9u8; 32])),
        ])
    }

    #[test]
    fn decodes_python_style_es256_cose_bytes() {
        let bytes = sample_es256_cose();
        let key = cose_key_from_bytes(&bytes).expect("ES256 COSE 应能反序列化");
        assert_eq!(key.type_, COSEAlgorithm::ES256);
        match key.key {
            COSEKeyType::EC_EC2(ec2) => {
                assert_eq!(ec2.curve, ECDSACurve::SECP256R1);
                assert_eq!(ec2.x, vec![7u8; 32]);
                assert_eq!(ec2.y, vec![9u8; 32]);
            }
            other => panic!("应为 EC2 公钥，实际为 {other:?}"),
        }
    }

    #[test]
    fn decodes_rs256_cose_bytes() {
        let modulus = vec![0x5au8; 256];
        let bytes = cbor_map(vec![
            (cbor_int(1), cbor_int(3)),
            (cbor_int(3), cbor_int(-257)),
            (cbor_int(-1), cbor_bytes(&modulus)),
            (cbor_int(-2), cbor_bytes(&[0x01, 0x00, 0x01])),
        ]);
        let key = cose_key_from_bytes(&bytes).expect("RS256 COSE 应能反序列化");
        assert_eq!(key.type_, COSEAlgorithm::RS256);
        match key.key {
            COSEKeyType::RSA(rsa) => {
                assert_eq!(rsa.n, modulus);
                assert_eq!(rsa.e, [0x01, 0x00, 0x01]);
            }
            other => panic!("应为 RSA 公钥，实际为 {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_or_truncated_cose_bytes() {
        assert!(cose_key_from_bytes(&[]).is_err());
        assert!(cose_key_from_bytes(&[0xff]).is_err());
        let truncated = sample_es256_cose();
        assert!(cose_key_from_bytes(&truncated[..truncated.len() - 3]).is_err());
        // 算法不在允许集合内（ES384 = -35）。
        let unsupported = cbor_map(vec![
            (cbor_int(1), cbor_int(2)),
            (cbor_int(3), cbor_int(-35)),
            (cbor_int(-1), cbor_int(2)),
            (cbor_int(-2), cbor_bytes(&[0u8; 48])),
            (cbor_int(-3), cbor_bytes(&[0u8; 48])),
        ]);
        assert!(cose_key_from_bytes(&unsupported).is_err());
    }

    #[test]
    fn sign_counter_rollback_matches_spec() {
        // 首次认证：两侧都为 0，允许。
        assert!(!sign_counter_rollback(0, 0));
        assert!(!sign_counter_rollback(1, 0));
        assert!(!sign_counter_rollback(6, 5));
        assert!(!sign_counter_rollback(5, 4));
        // 任一非零且 current <= stored：回退，拒绝。
        assert!(sign_counter_rollback(1, 1));
        assert!(sign_counter_rollback(0, 5));
        assert!(sign_counter_rollback(4, 5));
    }

    #[test]
    fn extracts_aaguid_and_public_key_from_attestation_object() {
        let cose = sample_es256_cose();
        let credential_id = [0xabu8; 7];
        let mut auth_data = vec![0u8; 32];
        auth_data.push(0x41); // UP + AT
        auth_data.extend_from_slice(&[0, 0, 0, 1]); // sign_count
        auth_data.extend_from_slice(&[0x11u8; 16]); // aaguid
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        auth_data.extend_from_slice(&cose);

        let attestation_object = cbor_map(vec![
            (cbor_text("fmt"), cbor_text("none")),
            (cbor_text("attStmt"), cbor_map(Vec::new())),
            (cbor_text("authData"), cbor_bytes(&auth_data)),
        ]);

        let attested = extract_attested_credential(&attestation_object).unwrap();
        assert_eq!(attested.aaguid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(attested.public_key, cose);
    }

    #[test]
    fn rp_id_and_origin_resolution_follow_spec() {
        assert_eq!(resolve_rp_id("id.example.com", "", None), "id.example.com");
        assert_eq!(
            resolve_rp_id("", "https://app.example.com/", Some("ignored")),
            "app.example.com"
        );
        assert_eq!(
            resolve_rp_id("", "", Some("host.example.com:8080")),
            "host.example.com"
        );
        assert_eq!(resolve_rp_id("", "", Some("[::1]:3000")), "::1");
        assert_eq!(resolve_rp_id("", "", None), "localhost");
        assert_eq!(
            resolve_origin("https://app.example.com/", "https", Some("x")),
            "https://app.example.com"
        );
        assert_eq!(
            resolve_origin("", "http", Some("127.0.0.1:3000")),
            "http://127.0.0.1:3000"
        );
    }

    #[test]
    fn base64url_round_trip_accepts_padding() {
        let raw = vec![0u8, 1, 2, 250, 251, 252];
        let encoded = b64url_encode(&raw);
        assert_eq!(b64url_decode(&encoded).unwrap(), raw);
        assert_eq!(b64url_decode(&format!("{encoded}=")).unwrap(), raw);
    }

    #[test]
    fn authentication_rejects_sign_counter_rollback() {
        let begin =
            authentication_options("example.com", "Example", "https://example.com").unwrap();
        let challenge = b64url_decode(&begin.challenge).unwrap();
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": begin.challenge,
            "origin": "https://example.com",
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        // authData：rpIdHash(32) + UP + signCount=1（小于库内 5）。
        let mut authenticator_data = vec![0u8; 32];
        authenticator_data.push(0x01);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        let credential_id = [1u8, 2, 3];
        let credential: PublicKeyCredential = serde_json::from_value(serde_json::json!({
            "id": b64url_encode(&credential_id),
            "rawId": b64url_encode(&credential_id),
            "response": {
                "authenticatorData": b64url_encode(&authenticator_data),
                "clientDataJSON": b64url_encode(&client_data_json),
                "signature": b64url_encode(&[4u8, 5, 6]),
                "userHandle": null,
            },
            "type": "public-key",
        }))
        .unwrap();

        let stored = StoredCredential {
            credential_id: &credential_id,
            public_key: &[],
            sign_count: 5,
            device_type: None,
            backed_up: false,
        };
        let error = verify_authentication(
            &credential,
            &challenge,
            "example.com",
            "Example",
            "https://example.com",
            &begin.state,
            stored,
        )
        .unwrap_err();
        assert_eq!(
            error.detail(),
            "Passkey 校验失败：签名计数回退，凭据可能已被复制"
        );
    }
}
