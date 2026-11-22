"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmailCodeField, useEmailCode } from "@/components/email-code-field";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { api, messageOf } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import type { AuthMeta, Me } from "@/lib/types";
import { isEmail } from "@/lib/validation";

export default function RegisterPage() {
  const router = useRouter();
  const meta = useApi<AuthMeta>("/api/auth/providers");
  const [inviteCode, setInviteCode] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [codeError, setCodeError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{
    inviteCode?: string;
    email?: string;
    password?: string;
  }>({});
  const [busy, setBusy] = useState(false);
  const emailCodeSender = useEmailCode();
  const emailCodeEnabled = meta.data?.email_code_enabled ?? false;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const next: { inviteCode?: string; email?: string; password?: string } = {};
    if (!inviteCode.trim()) next.inviteCode = "请填写邀请码";
    if (!email.trim()) next.email = "请填写邮箱";
    else if (!isEmail(email)) next.email = "邮箱格式不正确";
    if (!password) next.password = "请填写密码";
    else if (password.length < 8) next.password = "密码至少 8 位";
    setFieldErrors(next);
    const missingCode = emailCodeEnabled && !emailCode.trim();
    setCodeError(missingCode ? "请填写邮箱验证码" : null);
    if (next.inviteCode || next.email || next.password || missingCode) return;
    setBusy(true);
    setError(null);
    try {
      await api<Me>("/api/auth/register", {
        method: "POST",
        body: {
          invite_code: inviteCode.trim(),
          email: email.trim(),
          name: name.trim(),
          password,
          email_code: emailCode.trim(),
        },
      });
      router.replace("/dashboard");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  if (meta.data && !meta.data.registration_enabled) {
    return (
      <main className="flex min-h-screen items-center justify-center px-4">
        <div className="w-full max-w-sm text-center">
          <h1 className="font-heading text-xl font-medium">注册入口已关闭</h1>
          <p className="mt-2 text-sm text-muted-foreground">请联系管理员获取邀请码。</p>
          <Link className="mt-6 inline-block text-sm text-primary hover:underline" href="/login">
            返回登录
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="font-heading text-2xl font-medium tracking-tight">接受邀请</h1>
          <p className="mt-1 text-sm text-muted-foreground">使用管理员提供的邀请码创建账号</p>
        </div>
        <Card>
          <CardContent className="flex flex-col gap-4">
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            <form noValidate onSubmit={submit}>
              <FieldGroup className="gap-4">
                <Field data-invalid={Boolean(fieldErrors.inviteCode)}>
                  <FieldLabel htmlFor="invite_code">邀请码</FieldLabel>
                  <Input
                    aria-invalid={Boolean(fieldErrors.inviteCode) || undefined}
                    autoComplete="off"
                    id="invite_code"
                    placeholder="粘贴管理员提供的邀请码"
                    value={inviteCode}
                    onChange={(event) => {
                      setInviteCode(event.target.value);
                      if (fieldErrors.inviteCode) {
                        setFieldErrors(({ inviteCode, ...rest }) => rest);
                      }
                    }}
                  />
                  <FieldError>{fieldErrors.inviteCode}</FieldError>
                </Field>
                <Field data-invalid={Boolean(fieldErrors.email)}>
                  <FieldLabel htmlFor="email">邮箱</FieldLabel>
                  <Input
                    aria-invalid={Boolean(fieldErrors.email) || undefined}
                    autoComplete="username"
                    id="email"
                    placeholder="you@example.com"
                    type="email"
                    value={email}
                    onChange={(event) => {
                      setEmail(event.target.value);
                      if (fieldErrors.email) {
                        setFieldErrors(({ email, ...rest }) => rest);
                      }
                    }}
                  />
                  <FieldError>{fieldErrors.email}</FieldError>
                </Field>
                {emailCodeEnabled ? (
                  <>
                    <EmailCodeField
                      cooldown={emailCodeSender.cooldown}
                      error={codeError ?? emailCodeSender.error}
                      id="register-email-code"
                      sending={emailCodeSender.sending}
                      value={emailCode}
                      onChange={(value) => {
                        setEmailCode(value);
                        if (codeError) setCodeError(null);
                      }}
                      onSend={() => {
                        if (!email.trim() || !isEmail(email)) {
                          setFieldErrors((prev) => ({
                            ...prev,
                            email: "请先填写正确的邮箱",
                          }));
                          return;
                        }
                        void emailCodeSender.send("/api/auth/email-code", {
                          email: email.trim(),
                          purpose: "register",
                        });
                      }}
                    />
                    {emailCodeSender.notice ? (
                      <p className="text-xs text-muted-foreground">
                        {emailCodeSender.notice}
                      </p>
                    ) : null}
                  </>
                ) : null}
                <Field>
                  <FieldLabel htmlFor="name">用户名</FieldLabel>
                  <Input
                    id="name"
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                  />
                </Field>
                <Field data-invalid={Boolean(fieldErrors.password)}>
                  <FieldLabel htmlFor="password">密码</FieldLabel>
                  <Input
                    aria-invalid={Boolean(fieldErrors.password) || undefined}
                    autoComplete="new-password"
                    id="password"
                    placeholder="至少 8 位"
                    type="password"
                    value={password}
                    onChange={(event) => {
                      setPassword(event.target.value);
                      if (fieldErrors.password) {
                        setFieldErrors(({ password, ...rest }) => rest);
                      }
                    }}
                  />
                  <FieldError>{fieldErrors.password}</FieldError>
                </Field>
                <Button className="w-full" disabled={busy} type="submit">
                  {busy ? "注册中…" : "注册并登录"}
                </Button>
              </FieldGroup>
            </form>
          </CardContent>
        </Card>
        <div className="mt-4 text-center text-sm text-muted-foreground">
          <Link className="text-primary hover:underline" href="/login">
            已有账号，返回登录
          </Link>
        </div>
      </div>
    </main>
  );
}
