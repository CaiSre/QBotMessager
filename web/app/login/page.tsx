"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { KeyRoundIcon } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { api, messageOf } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { getPasskey, passkeySupported } from "@/lib/passkey";
import type { AuthMeta, Me } from "@/lib/types";

export default function LoginPage() {
  const router = useRouter();
  const meta = useApi<AuthMeta>("/api/auth/providers");
  const [account, setAccount] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{ account?: string; password?: string }>({});
  const [busy, setBusy] = useState<"password" | "passkey" | null>(null);
  const [supported, setSupported] = useState(false);

  useEffect(() => {
    setSupported(passkeySupported());
  }, []);

  async function submitPassword(event: React.FormEvent) {
    event.preventDefault();
    const next: { account?: string; password?: string } = {};
    if (!account.trim()) next.account = "请填写用户名或邮箱";
    if (!password) next.password = "请填写密码";
    setFieldErrors(next);
    if (next.account || next.password) return;
    setBusy("password");
    setError(null);
    try {
      await api<Me>("/api/auth/login", {
        method: "POST",
        body: { account: account.trim(), password },
      });
      router.replace("/dashboard");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(null);
    }
  }

  async function loginWithPasskey() {
    setBusy("passkey");
    setError(null);
    try {
      const options = await api<unknown>("/api/auth/passkey/login/begin", { method: "POST" });
      const credential = await getPasskey(JSON.stringify(options), "登录");
      await api("/api/auth/passkey/login/finish", { method: "POST", body: { credential } });
      router.replace("/dashboard");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="font-heading text-2xl font-medium tracking-tight">QBotMessager</h1>
          <p className="mt-1 text-sm text-muted-foreground">登录后管理机器人、通道与推送日志</p>
        </div>

        <Card>
          <CardContent className="flex flex-col gap-4">
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}

            <form noValidate onSubmit={submitPassword}>
              <FieldGroup className="gap-4">
                <Field data-invalid={Boolean(fieldErrors.account)}>
                  <FieldLabel htmlFor="account">用户名或邮箱</FieldLabel>
                  <Input
                    aria-invalid={Boolean(fieldErrors.account) || undefined}
                    autoComplete="username"
                    id="account"
                    placeholder="用户名或 you@example.com"
                    type="text"
                    value={account}
                    onChange={(event) => {
                      setAccount(event.target.value);
                      if (fieldErrors.account) {
                        setFieldErrors((prev) => ({ ...prev, account: undefined }));
                      }
                    }}
                  />
                  <FieldError>{fieldErrors.account}</FieldError>
                </Field>
                <Field data-invalid={Boolean(fieldErrors.password)}>
                  <div className="flex items-center justify-between">
                    <FieldLabel htmlFor="password">密码</FieldLabel>
                    <Link
                      className="text-xs text-muted-foreground hover:text-foreground hover:underline"
                      href="/forgot-password"
                    >
                      忘记密码？
                    </Link>
                  </div>
                  <Input
                    aria-invalid={Boolean(fieldErrors.password) || undefined}
                    autoComplete="current-password"
                    id="password"
                    type="password"
                    value={password}
                    onChange={(event) => {
                      setPassword(event.target.value);
                      if (fieldErrors.password) {
                        setFieldErrors((prev) => ({ ...prev, password: undefined }));
                      }
                    }}
                  />
                  <FieldError>{fieldErrors.password}</FieldError>
                </Field>
                <Button className="w-full" disabled={busy !== null} type="submit">
                  {busy === "password" ? "登录中…" : "登录"}
                </Button>
              </FieldGroup>
            </form>

            {supported ? (
              <Button
                className="w-full"
                disabled={busy !== null}
                variant="secondary"
                onClick={() => void loginWithPasskey()}
              >
                <KeyRoundIcon data-icon="inline-start" />
                {busy === "passkey" ? "等待通行密钥…" : "使用通行密钥登录"}
              </Button>
            ) : null}

            {meta.data && meta.data.oauth_providers.length > 0 ? (
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="h-px flex-1 bg-border" />
                  第三方登录
                  <span className="h-px flex-1 bg-border" />
                </div>
                {meta.data.oauth_providers.map((provider) => (
                  <Button
                    key={provider.key}
                    className="w-full"
                    variant="outline"
                    onClick={() => {
                      window.location.href = `/api/auth/oauth/${provider.key}/start`;
                    }}
                  >
                    {provider.display_name}
                  </Button>
                ))}
              </div>
            ) : null}
          </CardContent>
        </Card>

        <div className="mt-4 text-center text-sm text-muted-foreground">
          {meta.data?.registration_enabled ? (
            <Link className="text-primary hover:underline" href="/register">
              使用邀请码注册
            </Link>
          ) : (
            <span>注册入口已关闭，请联系管理员获取邀请</span>
          )}
        </div>
      </div>
    </main>
  );
}
