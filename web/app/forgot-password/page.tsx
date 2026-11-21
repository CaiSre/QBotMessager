"use client";

import Link from "next/link";
import { useState } from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmailCodeField, useEmailCode } from "@/components/email-code-field";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { api, messageOf } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import type { AuthMeta } from "@/lib/types";
import { isEmail } from "@/lib/validation";

export default function ForgotPasswordPage() {
  const meta = useApi<AuthMeta>("/api/auth/providers");
  const sender = useEmailCode();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{
    email?: string;
    code?: string;
    password?: string;
  }>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function sendCode() {
    if (!email.trim() || !isEmail(email)) {
      setFieldErrors((prev) => ({ ...prev, email: "请先填写正确的邮箱" }));
      return;
    }
    await sender.send("/api/auth/email-code", {
      email: email.trim(),
      purpose: "reset_password",
    });
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const next: { email?: string; code?: string; password?: string } = {};
    if (!email.trim()) next.email = "请填写邮箱";
    else if (!isEmail(email)) next.email = "邮箱格式不正确";
    if (!/^\d{6}$/.test(code.trim())) next.code = "请填写 6 位验证码";
    if (password.length < 8) next.password = "新密码至少 8 位";
    else if (password !== confirm) next.password = "两次输入的新密码不一致";
    setFieldErrors(next);
    if (next.email || next.code || next.password) return;

    setBusy(true);
    setError(null);
    try {
      await api("/api/auth/password/reset", {
        method: "POST",
        body: {
          email: email.trim(),
          code: code.trim(),
          new_password: password,
        },
      });
      setDone(true);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  if (meta.data && !meta.data.email_code_enabled) {
    return (
      <main className="flex min-h-screen items-center justify-center px-4">
        <div className="w-full max-w-sm text-center">
          <h1 className="font-heading text-xl font-medium">暂不支持自助找回</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            管理员尚未配置邮件服务，请联系管理员重置密码。
          </p>
          <Link className="mt-6 inline-block text-sm text-primary hover:underline" href="/login">
            返回登录
          </Link>
        </div>
      </main>
    );
  }

  if (done) {
    return (
      <main className="flex min-h-screen items-center justify-center px-4">
        <div className="w-full max-w-sm text-center">
          <h1 className="font-heading text-xl font-medium">密码已重置</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            旧密码已失效，其他设备上的登录也已退出。
          </p>
          <Link className="mt-6 inline-block text-sm text-primary hover:underline" href="/login">
            使用新密码登录
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="font-heading text-2xl font-medium tracking-tight">找回密码</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            验证邮箱后设置新的登录密码
          </p>
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
                <Field data-invalid={Boolean(fieldErrors.email)}>
                  <FieldLabel htmlFor="forgot-email">邮箱</FieldLabel>
                  <Input
                    aria-invalid={Boolean(fieldErrors.email) || undefined}
                    autoComplete="username"
                    id="forgot-email"
                    placeholder="you@example.com"
                    type="email"
                    value={email}
                    onChange={(event) => {
                      setEmail(event.target.value);
                      if (fieldErrors.email) {
                        setFieldErrors((prev) => ({ ...prev, email: undefined }));
                      }
                    }}
                  />
                  <FieldError>{fieldErrors.email}</FieldError>
                </Field>
                <EmailCodeField
                  cooldown={sender.cooldown}
                  error={fieldErrors.code ?? sender.error}
                  id="forgot-email-code"
                  sending={sender.sending}
                  value={code}
                  onChange={(value) => {
                    setCode(value);
                    if (fieldErrors.code) {
                      setFieldErrors((prev) => ({ ...prev, code: undefined }));
                    }
                  }}
                  onSend={() => void sendCode()}
                />
                {sender.notice ? (
                  <p className="-mt-2 text-xs text-muted-foreground">{sender.notice}</p>
                ) : null}
                <Field data-invalid={Boolean(fieldErrors.password)}>
                  <FieldLabel htmlFor="forgot-password">新密码</FieldLabel>
                  <Input
                    aria-invalid={Boolean(fieldErrors.password) || undefined}
                    autoComplete="new-password"
                    id="forgot-password"
                    placeholder="至少 8 位"
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
                <Field data-invalid={Boolean(fieldErrors.password)}>
                  <FieldLabel htmlFor="forgot-confirm">确认新密码</FieldLabel>
                  <Input
                    aria-invalid={Boolean(fieldErrors.password) || undefined}
                    autoComplete="new-password"
                    id="forgot-confirm"
                    type="password"
                    value={confirm}
                    onChange={(event) => {
                      setConfirm(event.target.value);
                      if (fieldErrors.password) {
                        setFieldErrors((prev) => ({ ...prev, password: undefined }));
                      }
                    }}
                  />
                </Field>
                <Button className="w-full" disabled={busy} type="submit">
                  {busy ? "提交中…" : "重置密码"}
                </Button>
              </FieldGroup>
            </form>
          </CardContent>
        </Card>
        <div className="mt-4 text-center text-sm text-muted-foreground">
          <Link className="text-primary hover:underline" href="/login">
            返回登录
          </Link>
        </div>
      </div>
    </main>
  );
}
