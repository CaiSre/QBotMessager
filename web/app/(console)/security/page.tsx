"use client";

import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ConfirmDialog,
  CopyButton,
  EmptyHint,
  ErrorAlert,
  PageHeader,
  SuccessAlert,
} from "@/components/ui";
import { api, messageOf } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { isSuperAdmin, useMe } from "@/lib/me";
import { createPasskey, passkeySupported } from "@/lib/passkey";
import type { OAuthProvider, Passkey, SecuritySettings } from "@/lib/types";

interface OAuthForm {
  key: string;
  displayName: string;
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  scopes: string;
  emailField: string;
  idField: string;
  nameField: string;
  enabled: boolean;
  useGithubPreset: boolean;
}

const EMPTY_OAUTH: OAuthForm = {
  key: "",
  displayName: "",
  clientId: "",
  clientSecret: "",
  authorizationUrl: "",
  tokenUrl: "",
  userinfoUrl: "",
  scopes: "",
  emailField: "email",
  idField: "id",
  nameField: "name",
  enabled: true,
  useGithubPreset: false,
};

export default function SecurityPage() {
  const me = useMe();
  const manage = isSuperAdmin(me.role);

  const settings = useApi<SecuritySettings>(
    manage ? "/api/admin/settings" : null,
  );
  const providers = useApi<OAuthProvider[]>(
    manage ? "/api/admin/oauth-providers" : null,
  );
  const passkeys = useApi<Passkey[]>("/api/auth/passkey");

  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [origin, setOrigin] = useState("");
  useEffect(() => setOrigin(window.location.origin), []);

  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [supported, setSupported] = useState(false);
  useEffect(() => setSupported(passkeySupported()), []);

  const [oauthOpen, setOauthOpen] = useState(false);
  const [editingProvider, setEditingProvider] = useState<OAuthProvider | null>(null);
  const [oauthForm, setOauthForm] = useState<OAuthForm>(EMPTY_OAUTH);
  const [oauthErrors, setOauthErrors] = useState<{
    key?: string;
    displayName?: string;
    clientId?: string;
    clientSecret?: string;
  }>({});

  const [confirm, setConfirm] = useState<{
    title: string;
    description: string;
    action: () => Promise<void>;
  } | null>(null);

  const providerList = providers.data ?? [];
  const passkeyList = passkeys.data ?? [];

  async function toggleRegistration(value: boolean) {
    setError(null);
    setNotice(null);
    try {
      await api("/api/admin/settings", { method: "PATCH", body: { register_enabled: value } });
      await settings.reload();
    } catch (err) {
      setError(messageOf(err));
    }
  }

  function openCreateProvider() {
    setEditingProvider(null);
    setOauthForm(EMPTY_OAUTH);
    setOauthErrors({});
    setError(null);
    setOauthOpen(true);
  }

  function openEditProvider(provider: OAuthProvider) {
    setEditingProvider(provider);
    setOauthForm({
      key: provider.key,
      displayName: provider.display_name,
      clientId: provider.client_id,
      clientSecret: "",
      authorizationUrl: provider.authorization_url,
      tokenUrl: provider.token_url,
      userinfoUrl: provider.userinfo_url,
      scopes: provider.scopes,
      emailField: provider.email_field,
      idField: provider.id_field,
      nameField: provider.name_field,
      enabled: provider.enabled,
      useGithubPreset: false,
    });
    setOauthErrors({});
    setError(null);
    setOauthOpen(true);
  }

  async function saveProvider(event: React.FormEvent) {
    event.preventDefault();
    const next: {
      key?: string;
      displayName?: string;
      clientId?: string;
      clientSecret?: string;
    } = {};
    if (!editingProvider && !oauthForm.key.trim()) next.key = "请填写标识";
    if (!oauthForm.displayName.trim()) next.displayName = "请填写显示名称";
    if (!oauthForm.clientId.trim()) next.clientId = "请填写 Client ID";
    if (!editingProvider && !oauthForm.clientSecret.trim()) next.clientSecret = "请填写 Client Secret";
    setOauthErrors(next);
    if (next.key || next.displayName || next.clientId || next.clientSecret) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const body: Record<string, unknown> = {
        display_name: oauthForm.displayName.trim(),
        client_id: oauthForm.clientId.trim(),
        authorization_url: oauthForm.authorizationUrl.trim(),
        token_url: oauthForm.tokenUrl.trim(),
        userinfo_url: oauthForm.userinfoUrl.trim(),
        scopes: oauthForm.scopes.trim(),
        email_field: oauthForm.emailField.trim() || "email",
        id_field: oauthForm.idField.trim() || "id",
        name_field: oauthForm.nameField.trim() || "name",
        enabled: oauthForm.enabled,
      };
      if (oauthForm.clientSecret.trim()) body.client_secret = oauthForm.clientSecret.trim();
      if (editingProvider) {
        await api(`/api/admin/oauth-providers/${editingProvider.id}`, { method: "PATCH", body });
      } else {
        body.key = oauthForm.key.trim();
        body.use_github_preset = oauthForm.useGithubPreset;
        await api("/api/admin/oauth-providers", { method: "POST", body });
      }
      setOauthOpen(false);
      await providers.reload();
      setNotice("OAuth2 提供方已保存");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setSaving(false);
    }
  }

  async function addPasskey() {
    setPasskeyBusy(true);
    setError(null);
    setNotice(null);
    try {
      const options = await api<unknown>("/api/auth/passkey/register/begin", { method: "POST" });
      const credential = await createPasskey(JSON.stringify(options));
      await api("/api/auth/passkey/register/finish", { method: "POST", body: { credential } });
      await passkeys.reload();
      setNotice("通行密钥已添加");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setPasskeyBusy(false);
    }
  }

  return (
    <div>
      <PageHeader title="安全设置" description="注册开关、OAuth2 登录与通行密钥" />
      <ErrorAlert message={error ?? settings.error ?? providers.error ?? passkeys.error} />
      <SuccessAlert message={notice} />

      <div className="flex flex-col gap-6">
        {manage ? (
          <Card>
            <CardHeader>
              <CardTitle>注册入口</CardTitle>
              <CardDescription>
                默认关闭；开启后持有邀请码的用户才能注册
                {settings.data
                  ? settings.data.register_enabled_source === "database"
                    ? "（当前由管理后台覆盖）"
                    : "（当前取环境变量默认值）"
                  : ""}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <Switch
                  checked={settings.data?.register_enabled ?? false}
                  id="register-enabled"
                  onCheckedChange={(value) => void toggleRegistration(value)}
                />
                <Label htmlFor="register-enabled">允许凭邀请码注册</Label>
              </div>
            </CardContent>
          </Card>
        ) : null}

        {manage ? (
          <Card>
            <CardHeader>
              <CardTitle>OAuth2 提供方</CardTitle>
              <CardDescription>
                采用授权码模式；每个提供方的完整回调地址见列表，可原样填入平台后台。
              </CardDescription>
              <CardAction>
                <Button size="sm" onClick={openCreateProvider}>
                  新增提供方
                </Button>
              </CardAction>
            </CardHeader>
            <CardContent>
              {providerList.length === 0 ? (
                <EmptyHint>还没有配置 OAuth2 登录</EmptyHint>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>标识</TableHead>
                      <TableHead>显示名称</TableHead>
                      <TableHead>Client ID</TableHead>
                      <TableHead>回调地址</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {providerList.map((provider) => (
                      <TableRow key={provider.id}>
                        <TableCell>
                          <code className="text-xs">{provider.key}</code>
                        </TableCell>
                        <TableCell>{provider.display_name}</TableCell>
                        <TableCell>
                          <span className="block max-w-56 truncate text-xs">
                            {provider.client_id}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <span
                              className="min-w-0 max-w-56 truncate text-xs"
                              title={`${origin}/api/auth/oauth/${provider.key}/callback`}
                            >
                              {origin}/api/auth/oauth/{provider.key}/callback
                            </span>
                            <CopyButton
                              value={`${origin}/api/auth/oauth/${provider.key}/callback`}
                            />
                          </div>
                        </TableCell>
                        <TableCell>
                          {provider.enabled ? (
                            <Badge className="bg-emerald-600/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400">
                              启用
                            </Badge>
                          ) : (
                            <Badge variant="outline">停用</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => openEditProvider(provider)}
                            >
                              编辑
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() =>
                                setConfirm({
                                  title: "删除提供方",
                                  description: `删除「${provider.display_name}」后，该方式将无法登录。`,
                                  action: async () => {
                                    await api(
                                      `/api/admin/oauth-providers/${provider.id}`,
                                      { method: "DELETE" },
                                    );
                                    await providers.reload();
                                  },
                                })
                              }
                            >
                              删除
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        ) : null}

        <Card>
          <CardHeader>
            <CardTitle>通行密钥</CardTitle>
            <CardDescription>当前账号已绑定 {passkeyList.length} 个凭据</CardDescription>
            <CardAction>
              <Button
                disabled={!supported || passkeyBusy}
                size="sm"
                onClick={() => void addPasskey()}
              >
                {passkeyBusy ? "等待浏览器…" : "添加通行密钥"}
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {!supported ? (
              <p className="text-sm text-muted-foreground">
                当前浏览器不支持 WebAuthn，无法使用通行密钥。
              </p>
            ) : passkeyList.length === 0 ? (
              <EmptyHint>还没有绑定通行密钥</EmptyHint>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>名称</TableHead>
                    <TableHead>设备类型</TableHead>
                    <TableHead>创建时间</TableHead>
                    <TableHead>最近使用</TableHead>
                    <TableHead>操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {passkeyList.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell>{item.label}</TableCell>
                      <TableCell>
                        {item.backed_up ? "可同步" : item.device_type || "本机"}
                      </TableCell>
                      <TableCell>{formatDateTime(item.created_at)}</TableCell>
                      <TableCell>{formatDateTime(item.last_used_at)}</TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            setConfirm({
                              title: "删除通行密钥",
                              description: `删除「${item.label}」后将无法再用它登录。`,
                              action: async () => {
                                await api(`/api/auth/passkey/${item.id}`, { method: "DELETE" });
                                await passkeys.reload();
                              },
                            })
                          }
                        >
                          删除
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={oauthOpen} onOpenChange={setOauthOpen}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{editingProvider ? "编辑提供方" : "新增提供方"}</DialogTitle>
          </DialogHeader>
          <form noValidate onSubmit={saveProvider}>
            <FieldGroup className="gap-4">
              <Field data-invalid={Boolean(oauthErrors.key)}>
                <FieldLabel htmlFor="oauth-key">标识</FieldLabel>
                <Input
                  aria-invalid={Boolean(oauthErrors.key) || undefined}
                  disabled={editingProvider !== null}
                  id="oauth-key"
                  placeholder="例如：github"
                  value={oauthForm.key}
                  onChange={(event) => {
                    setOauthForm((prev) => ({ ...prev, key: event.target.value }));
                    if (oauthErrors.key) setOauthErrors((prev) => ({ ...prev, key: undefined }));
                  }}
                />
                <FieldError>{oauthErrors.key}</FieldError>
              </Field>
              <Field data-invalid={Boolean(oauthErrors.displayName)}>
                <FieldLabel htmlFor="oauth-display-name">显示名称</FieldLabel>
                <Input
                  aria-invalid={Boolean(oauthErrors.displayName) || undefined}
                  id="oauth-display-name"
                  placeholder="例如：GitHub"
                  value={oauthForm.displayName}
                  onChange={(event) => {
                    setOauthForm((prev) => ({ ...prev, displayName: event.target.value }));
                    if (oauthErrors.displayName) {
                      setOauthErrors((prev) => ({ ...prev, displayName: undefined }));
                    }
                  }}
                />
                <FieldError>{oauthErrors.displayName}</FieldError>
              </Field>
              <Field data-invalid={Boolean(oauthErrors.clientId)}>
                <FieldLabel htmlFor="oauth-client-id">Client ID</FieldLabel>
                <Input
                  aria-invalid={Boolean(oauthErrors.clientId) || undefined}
                  id="oauth-client-id"
                  value={oauthForm.clientId}
                  onChange={(event) => {
                    setOauthForm((prev) => ({ ...prev, clientId: event.target.value }));
                    if (oauthErrors.clientId) {
                      setOauthErrors((prev) => ({ ...prev, clientId: undefined }));
                    }
                  }}
                />
                <FieldError>{oauthErrors.clientId}</FieldError>
              </Field>
              <Field data-invalid={Boolean(oauthErrors.clientSecret)}>
                <FieldLabel htmlFor="oauth-client-secret">Client Secret</FieldLabel>
                <Input
                  aria-invalid={Boolean(oauthErrors.clientSecret) || undefined}
                  autoComplete="new-password"
                  id="oauth-client-secret"
                  placeholder={editingProvider ? "留空表示不修改" : ""}
                  value={oauthForm.clientSecret}
                  onChange={(event) => {
                    setOauthForm((prev) => ({ ...prev, clientSecret: event.target.value }));
                    if (oauthErrors.clientSecret) {
                      setOauthErrors((prev) => ({ ...prev, clientSecret: undefined }));
                    }
                  }}
                />
                <FieldError>{oauthErrors.clientSecret}</FieldError>
              </Field>
              {editingProvider ? null : (
                <div className="flex items-start gap-2">
                  <Switch
                    checked={oauthForm.useGithubPreset}
                    id="oauth-github-preset"
                    onCheckedChange={(value) =>
                      setOauthForm((prev) => ({ ...prev, useGithubPreset: value }))
                    }
                  />
                  <Label className="leading-snug" htmlFor="oauth-github-preset">
                    使用 GitHub 预设（标识须为 github，留空的地址自动补齐）
                  </Label>
                </div>
              )}
              <Field>
                <FieldLabel htmlFor="oauth-authorization-url">授权地址</FieldLabel>
                <Input
                  id="oauth-authorization-url"
                  placeholder="https://..."
                  value={oauthForm.authorizationUrl}
                  onChange={(event) =>
                    setOauthForm((prev) => ({ ...prev, authorizationUrl: event.target.value }))
                  }
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="oauth-token-url">Token 地址</FieldLabel>
                <Input
                  id="oauth-token-url"
                  placeholder="https://..."
                  value={oauthForm.tokenUrl}
                  onChange={(event) =>
                    setOauthForm((prev) => ({ ...prev, tokenUrl: event.target.value }))
                  }
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="oauth-userinfo-url">用户信息地址</FieldLabel>
                <Input
                  id="oauth-userinfo-url"
                  placeholder="https://..."
                  value={oauthForm.userinfoUrl}
                  onChange={(event) =>
                    setOauthForm((prev) => ({ ...prev, userinfoUrl: event.target.value }))
                  }
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="oauth-scopes">Scopes</FieldLabel>
                <Input
                  id="oauth-scopes"
                  placeholder="以空格分隔，例如：read:user user:email"
                  value={oauthForm.scopes}
                  onChange={(event) =>
                    setOauthForm((prev) => ({ ...prev, scopes: event.target.value }))
                  }
                />
              </Field>
              <div className="grid grid-cols-3 gap-3">
                <Field>
                  <FieldLabel htmlFor="oauth-email-field">邮箱字段</FieldLabel>
                  <Input
                    id="oauth-email-field"
                    value={oauthForm.emailField}
                    onChange={(event) =>
                      setOauthForm((prev) => ({ ...prev, emailField: event.target.value }))
                    }
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="oauth-id-field">ID 字段</FieldLabel>
                  <Input
                    id="oauth-id-field"
                    value={oauthForm.idField}
                    onChange={(event) =>
                      setOauthForm((prev) => ({ ...prev, idField: event.target.value }))
                    }
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="oauth-name-field">名称字段</FieldLabel>
                  <Input
                    id="oauth-name-field"
                    value={oauthForm.nameField}
                    onChange={(event) =>
                      setOauthForm((prev) => ({ ...prev, nameField: event.target.value }))
                    }
                  />
                </Field>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={oauthForm.enabled}
                  id="oauth-enabled"
                  onCheckedChange={(value) =>
                    setOauthForm((prev) => ({ ...prev, enabled: value }))
                  }
                />
                <Label htmlFor="oauth-enabled">在登录页展示</Label>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setOauthOpen(false)}>
                  取消
                </Button>
                <Button disabled={saving} type="submit">
                  {saving ? "保存中…" : "保存"}
                </Button>
              </div>
            </FieldGroup>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        description={confirm?.description ?? ""}
        onConfirm={async () => {
          if (!confirm) return;
          const action = confirm.action;
          setConfirm(null);
          setError(null);
          try {
            await action();
          } catch (err) {
            setError(messageOf(err));
          }
        }}
        onOpenChange={(open) => {
          if (!open) setConfirm(null);
        }}
        open={confirm !== null}
        title={confirm?.title ?? ""}
      />
    </div>
  );
}
