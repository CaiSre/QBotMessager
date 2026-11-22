//! Passkey（WebAuthn）注册与断言。
//!
//! 协议要点：
//! - user handle = `str(user_id)` 的 UTF-8 字节；
//! - 支持算法固定为 `[-8 EdDSA, -7 ES256, -257 RS256]`；
//! - challenge = 32 随机字节 → base64url 无填充，放 Cookie `webauthn_challenge`；
//! - 库内 `public_key` 存 COSE 公钥的原始 CBOR 字节，断言时经
//!   `serde_cbor_2::from_slice` + `COSEKey::try_from` 反序列化并校验；
//! - 注册结果的 AAGUID 与 COSE 字节从 `AuthenticatorData::<Registration>` 中提取
//!   （`register_credential` 的返回值在 attestation=None 时不携带 AAGUID）；
//! - 认证成功后回写 sign_count / last_used_at / device_type / backed_up；
//! - 签名计数回退 `(current > 0 || stored > 0) && current <= stored` 一律拒绝。
//!
//! ceremony state（含 challenge）以 base64url JSON 存于 `webauthn_state` Cookie；
//! `webauthn_challenge` 另存一份 challenge，本地校验时两者必须一致。

use std::time::Duration as StdDuration;

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_cbor_2::Value as CborValue;
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::internals::AuthenticatorData;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, AttestationFormat, AuthenticationState, COSEAlgorithm,
    COSEKey, Credential, ParsedAttestation, PublicKeyCredential, RegisterPublicKeyCredential,
    RegisteredExtensions, Registration, RegistrationState, ResidentKeyRequirement,
    UserVerificationPolicy,
};

use crate::error::AppError;
use crate::services::runtime_settings::RuntimeSettings;

/// challenge Cookie 名。
pub const CHALLENGE_COOKIE: &str = "webauthn_challenge";
/// 注册时绑定用户 ID 的 Cookie 名。
pub const USER_COOKIE: &str = "webauthn_user";
/// ceremony state 的附加 Cookie 名。
pub const STATE_COOKIE: &str = "webauthn_state";
/// 临时 Cookie 有效期（秒）。
pub const COOKIE_MAX_AGE_SECONDS: i64 = 300;
/// WebAuthn 超时（秒）。
const WEBAUTHN_TIMEOUT_SECONDS: u64 = 300;

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
    /// COSE 公钥原始字节（attestationObject 内原样格式，不二次编码）。
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
    // webauthn-rs 只能表达 Required/Discouraged；这里统一改写为 PREFERRED，
    // 允许无生物识别的认证器完成登录。
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

    // register_credential 不回传 AAGUID，从 attestationObject 提取原始 COSE 公钥字节。
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
        // 落库只存 COSE 公钥字节，UV 状态不持久化；重建时统一按未做 UV 处理
        //（RP 配置本就不要求 uv）。
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

/// 签名计数回退检测。
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

/// 从 attestationObject 中提取 AAGUID 与 COSE 公钥原始字节。
///
/// `register_credential`（attestation=None）的返回值不携带 AAGUID，因此从公开的
/// `AuthenticatorData::<Registration>` 解析 attestationObject 里的 authData 获得。
fn extract_attested_credential(attestation_object: &[u8]) -> Result<AttestedCredential, AppError> {
    let root = serde_cbor_2::from_slice::<CborValue>(attestation_object)
        .map_err(|_| AppError::bad_request("Passkey 校验失败：凭证格式非法"))?;
    let CborValue::Map(entries) = root else {
        return Err(AppError::bad_request("Passkey 校验失败：凭证格式非法"));
    };
    let auth_data = entries
        .get(&CborValue::Text("authData".to_string()))
        .and_then(|value| match value {
            CborValue::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| AppError::bad_request("Passkey 校验失败：缺少 authData"))?;

    // 解析出的 `ParsedAttestationData::None` 之外的字段不需要，只取 attestedCredentialData。
    let parsed = AuthenticatorData::<Registration>::try_from(auth_data)
        .map_err(|_| AppError::bad_request("Passkey 校验失败：认证数据非法"))?;
    let acd = parsed
        .acd
        .ok_or_else(|| AppError::bad_request("Passkey 校验失败：缺少凭据公钥数据"))?;

    let aaguid = Uuid::from_slice(&acd.aaguid)
        .map_err(|_| AppError::bad_request("Passkey 校验失败：AAGUID 非法"))?
        .to_string();
    let public_key = serde_cbor_2::to_vec(&acd.credential_pk)
        .map_err(|_| AppError::bad_request("Passkey 校验失败：公钥序列化失败"))?;

    Ok(AttestedCredential { aaguid, public_key })
}

/// 从 COSE 公钥原始字节反序列化出 `COSEKey`。
///
/// `serde_cbor_2::from_slice` 拒绝尾部多余字节；`COSEKey::try_from` 校验
/// kty/alg/crv 组合并在椭圆曲线场景验证坐标确在曲线上。
pub fn cose_key_from_bytes(bytes: &[u8]) -> Result<COSEKey, String> {
    let value = serde_cbor_2::from_slice::<CborValue>(bytes)
        .map_err(|err| format!("COSE 公钥不是合法 CBOR：{err}"))?;
    COSEKey::try_from(&value).map_err(|err| format!("COSE 公钥非法：{err}"))
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    fn cbor_map(entries: Vec<(CborValue, CborValue)>) -> Vec<u8> {
        let map = CborValue::Map(
            entries
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>(),
        );
        serde_cbor_2::to_vec(&map).unwrap()
    }

    fn cbor_int(value: i64) -> CborValue {
        CborValue::Integer(value.into())
    }

    fn cbor_bytes(bytes: &[u8]) -> CborValue {
        CborValue::Bytes(bytes.to_vec())
    }

    fn cbor_text(text: &str) -> CborValue {
        CborValue::Text(text.to_string())
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
    fn decodes_es256_cose_bytes() {
        // P-256 生成元坐标（真实曲线点，能通过 COSEKey::try_from 的曲线验证）。
        let gx: &[u8] = &{
            let mut v = Vec::new();
            for pair in [
                "6b17d1f2", "e12c4247", "f8bce6e5", "63a440f2", "77037d81", "2deb33a0", "f4a13945",
                "d898c296",
            ] {
                v.extend_from_slice(&u32::from_str_radix(pair, 16).unwrap().to_be_bytes());
            }
            v
        };
        let gy: &[u8] = &{
            let mut v = Vec::new();
            for pair in [
                "4fe342e2", "fe1a7f9b", "8ee7eb4a", "7c0f9e16", "2bce3357", "6b315ece", "cbb64068",
                "37bf51f5",
            ] {
                v.extend_from_slice(&u32::from_str_radix(pair, 16).unwrap().to_be_bytes());
            }
            v
        };
        let bytes = cbor_map(vec![
            (cbor_int(1), cbor_int(2)),
            (cbor_int(3), cbor_int(-7)),
            (cbor_int(-1), cbor_int(1)),
            (cbor_int(-2), cbor_bytes(gx)),
            (cbor_int(-3), cbor_bytes(gy)),
        ]);
        let key = cose_key_from_bytes(&bytes).expect("ES256 COSE 应能反序列化");
        assert_eq!(key.type_, COSEAlgorithm::ES256);
    }

    #[test]
    fn rejects_non_rsa_modulus() {
        // rsa crate 会拒绝非素数积的伪造模数；这里验证非法输入走错误路径。
        let modulus = vec![0x5au8; 256];
        let bytes = cbor_map(vec![
            (cbor_int(1), cbor_int(3)),
            (cbor_int(3), cbor_int(-257)),
            (cbor_int(-1), cbor_bytes(&modulus)),
            (cbor_int(-2), cbor_bytes(&[0x01, 0x00, 0x01])),
        ]);
        assert!(cose_key_from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_malformed_or_truncated_cose_bytes() {
        assert!(cose_key_from_bytes(&[]).is_err());
        assert!(cose_key_from_bytes(&[0xff]).is_err());
        let truncated = sample_es256_cose();
        assert!(cose_key_from_bytes(&truncated[..truncated.len() - 3]).is_err());
        // 不在曲线上的坐标必须被 COSEKey::try_from 拒绝。
        assert!(cose_key_from_bytes(&sample_es256_cose()).is_err());
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
            (cbor_text("attStmt"), CborValue::Map(Default::default())),
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
