// 浏览器端 WebAuthn 封装：服务端返回的是 options_to_json 的 base64url 文本，
// 使用浏览器内建的 parse*OptionsFromJSON / toJSON 转换，避免手工做 base64 编解码。

interface PublicKeyCredentialJSONHelpers {
  parseCreationOptionsFromJSON?: (json: unknown) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (json: unknown) => PublicKeyCredentialRequestOptions;
}

type SerializableCredential = PublicKeyCredential & {
  toJSON: () => Record<string, unknown>;
};

function helpers(): PublicKeyCredentialJSONHelpers {
  return window.PublicKeyCredential as unknown as PublicKeyCredentialJSONHelpers;
}

// webauthn-rs 的 CreationChallengeResponse / RequestChallengeResponse 外层多包了
// 一个 { publicKey: ... }，而 parse*OptionsFromJSON 期望内层选项对象。
function unwrapPublicKey(parsed: unknown): unknown {
  if (parsed && typeof parsed === "object" && "publicKey" in parsed) {
    const inner = (parsed as { publicKey?: unknown }).publicKey;
    if (inner && typeof inner === "object") return inner;
  }
  return parsed;
}

export function passkeySupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    Boolean(window.PublicKeyCredential) &&
    typeof navigator.credentials !== "undefined" &&
    typeof helpers().parseCreationOptionsFromJSON === "function"
  );
}

export async function createPasskey(optionsJson: string): Promise<Record<string, unknown>> {
  if (!passkeySupported()) throw new Error("当前浏览器不支持通行密钥");
  const parse = helpers().parseCreationOptionsFromJSON;
  if (!parse) throw new Error("当前浏览器不支持通行密钥");
  const publicKey = parse(unwrapPublicKey(JSON.parse(optionsJson)));
  const credential = (await navigator.credentials.create({
    publicKey,
  })) as SerializableCredential | null;
  if (!credential) throw new Error("未创建通行密钥");
  return credential.toJSON();
}

export async function getPasskey(
  optionsJson: string,
  label: string,
): Promise<Record<string, unknown>> {
  if (!passkeySupported()) throw new Error("当前浏览器不支持通行密钥");
  const parse = helpers().parseRequestOptionsFromJSON;
  if (!parse) throw new Error("当前浏览器不支持通行密钥");
  const options = unwrapPublicKey(JSON.parse(optionsJson)) as { allowCredentials?: unknown[] };
  // 空列表等价于“不限制”，部分实现会把它当成“不允许任何凭据”，这里直接去掉。
  if (Array.isArray(options.allowCredentials) && options.allowCredentials.length === 0) {
    delete options.allowCredentials;
  }
  const publicKey = parse(options);
  const credential = (await navigator.credentials.get({
    publicKey,
  })) as SerializableCredential | null;
  if (!credential) throw new Error("未选择通行密钥");
  return { ...credential.toJSON(), label };
}
