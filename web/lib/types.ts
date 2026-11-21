export type Role = "super_admin" | "user";
export type AccountStatus = "active" | "disabled";
export type Platform = "dingtalk" | "wecom" | "feishu";

export const ROLE_LABELS: Record<Role, string> = {
  super_admin: "超级管理员",
  user: "普通用户",
};

export const PLATFORM_LABELS: Record<Platform, string> = {
  dingtalk: "钉钉",
  wecom: "企业微信",
  feishu: "飞书",
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
  platform: Platform;
  bot_profile_id: number;
  webhook_token: string;
  webhook_url: string;
  enabled: boolean;
}

export interface PushLog {
  id: number;
  owner_user_id: number | null;
  owner_email: string | null;
  platform: Platform;
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

export interface EnvConfig {
  id: number;
  owner_user_id: number;
  owner_email: string;
  key: string;
  value: string | null;
  is_secret: boolean;
  description: string | null;
  updated_at: string | null;
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

export interface SecuritySettings {
  register_enabled: boolean;
  register_enabled_source: "database" | "env";
  env_default: boolean;
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
  by_platform: { platform: Platform; count: number }[];
  trend: { date: string; count: number }[];
  recent_failures: {
    id: number;
    platform: Platform;
    target: string | null;
    error_code: string | null;
    error_message: string | null;
    created_at: string | null;
  }[];
}
