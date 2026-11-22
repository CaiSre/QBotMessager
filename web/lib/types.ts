export type Role = "super_admin" | "user";
export type AccountStatus = "active" | "disabled";
export type HookType = "dingtalk" | "wecom" | "feishu" | "github";

export const ROLE_LABELS: Record<Role, string> = {
  super_admin: "超级管理员",
  user: "普通用户",
};

export const HOOK_TYPE_LABELS: Record<HookType, string> = {
  dingtalk: "钉钉",
  wecom: "企业微信",
  feishu: "飞书",
  github: "GitHub",
};

export interface Me {
  id: number;
  email: string;
  name: string;
  role: Role;
  status: AccountStatus;
  passkey_count: number;
  has_password: boolean;
}

export interface OAuthProviderBrief {
  key: string;
  display_name: string;
}

export interface AuthMeta {
  registration_enabled: boolean;
  password_enabled: boolean;
  passkey_enabled: boolean;
  email_code_enabled: boolean;
  rp_id: string;
  oauth_providers: OAuthProviderBrief[];
}

export interface BotProfile {
  id: number;
  owner_user_id: number;
  owner_email: string;
  name: string;
  qq_appid: string;
  qq_app_secret_masked: string;
  has_secret: boolean;
  qq_host: string;
  default_openids: string[];
  default_group_openid: string | null;
  enabled: boolean;
}

export interface Channel {
  id: number;
  owner_user_id: number;
  owner_email: string;
  hook_type: HookType;
  push_source: string;
  bot_profile_id: number;
  webhook_token: string;
  webhook_url: string;
  has_secret: boolean;
  enabled: boolean;
}

export interface PushLog {
  id: number;
  owner_user_id: number | null;
  owner_email: string | null;
  hook_type: HookType;
  push_source: string;
  source_msgtype: string | null;
  target: string | null;
  qq_msg_type: number | null;
  content_preview: string | null;
  content_len: number | null;
  status: string;
  error_code: string | null;
  error_message: string | null;
  duration_ms: number | null;
  request_id: string | null;
  created_at: string | null;
}

export interface LogPage {
  total: number;
  page: number;
  page_size: number;
  items: PushLog[];
}

export interface UserRow {
  id: number;
  email: string;
  name: string;
  role: Role;
  status: AccountStatus;
  last_login_at: string | null;
}

export interface Invite {
  id: number;
  code: string;
  email: string | null;
  max_uses: number;
  used_count: number;
  expires_at: string | null;
  revoked: boolean;
  created_at: string | null;
}

export interface OAuthProvider {
  id: number;
  key: string;
  display_name: string;
  client_id: string;
  client_secret_masked: string;
  authorization_url: string;
  token_url: string;
  userinfo_url: string;
  scopes: string;
  email_field: string;
  id_field: string;
  name_field: string;
  enabled: boolean;
  email_verified: boolean;
}

/** 已绑定的第三方账号（auth_identities 一行）。 */
export interface OAuthIdentity {
  id: number;
  provider: string;
  provider_login: string | null;
  created_at: string | null;
}

export interface SecuritySettings {
  register_enabled: boolean;
  register_enabled_source: "database" | "env";
  env_default: boolean;
}

export type SettingKind = "bool" | "int" | "float" | "string" | "select";

export interface SettingItem {
  key: string;
  label: string;
  description: string;
  kind: SettingKind;
  value: boolean | number | string;
  default: boolean | number | string;
  minimum: number | null;
  maximum: number | null;
  options: string[];
  source: "default" | "environment" | "database";
  secret: boolean;
  has_value: boolean | null;
}

export interface SettingGroup {
  name: string;
  items: SettingItem[];
}

export interface SystemSettings extends SecuritySettings {
  groups: SettingGroup[];
}

export interface Passkey {
  id: number;
  label: string;
  device_type: string | null;
  backed_up: boolean;
  created_at: string | null;
  last_used_at: string | null;
}

export interface Stats {
  scope: "mine" | "all";
  today: { total: number; success: number };
  success_rate: number;
  by_source: { source: string; count: number }[];
  trend: { date: string; count: number }[];
  recent_failures: {
    id: number;
    hook_type: HookType;
    push_source: string;
    target: string | null;
    error_code: string | null;
    error_message: string | null;
    created_at: string | null;
  }[];
}
