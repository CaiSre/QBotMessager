"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { ErrorAlert, PageHeader, SuccessAlert } from "@/components/ui";
import { api, messageOf } from "@/lib/api";
import { useMe, useRefreshMe } from "@/lib/me";
import { ROLE_LABELS } from "@/lib/types";
import { isEmail } from "@/lib/validation";

type Busy = "name" | "email" | "password" | null;

export default function AccountPage() {
  const me = useMe();
  const refreshMe = useRefreshMe();

  const [busy, setBusy] = useState<Busy>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [name, setName] = useState(me.name);
  const [nameError, setNameError] = useState<string | null>(null);

  const [email, setEmail] = useState(me.email);
  const [emailPassword, setEmailPassword] = useState("");
  const [emailError, setEmailError] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const initial = (me.name || me.email).slice(0, 1).toUpperCase();

  async function saveName(event: React.FormEvent) {
    event.preventDefault();
    const value = name.trim();
    if (!value) {
      setNameError("请填写用户名");
      return;
    }
    setNameError(null);
    setError(null);
    setNotice(null);
    setBusy("name");
    try {
      await api("/api/auth/me/name", { method: "PATCH", body: { name: value } });
      setName(value);
      await refreshMe();
      setNotice("用户名已更新");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(null);
    }
  }

  async function saveEmail(event: React.FormEvent) {
    event.preventDefault();
    const value = email.trim();
    if (!isEmail(value)) {
      setEmailError("邮箱格式不正确");
      return;
    }
    if (me.has_password && !emailPassword) {
      setEmailError("请输入当前密码");
      return;
    }
    setEmailError(null);
    setError(null);
    setNotice(null);
    setBusy("email");
    try {
      const updated = await api<{ email: string }>("/api/auth/me/email", {
        method: "PATCH",
        body: { email: value, current_password: emailPassword },
      });
      setEmail(updated.email);
      setEmailPassword("");
      await refreshMe();
      setNotice("邮箱已更新，之后请使用新邮箱登录");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(null);
    }
  }

  async function savePassword(event: React.FormEvent) {
    event.preventDefault();
    if (me.has_password && !currentPassword) {
      setPasswordError("请输入当前密码");
      return;
    }
    if (newPassword.length < 8) {
      setPasswordError("新密码至少 8 位");
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError("两次输入的新密码不一致");
      return;
    }
    setPasswordError(null);
    setError(null);
    setNotice(null);
    setBusy("password");
    try {
      await api("/api/auth/me/password", {
        method: "PATCH",
        body: {
          current_password: currentPassword,
          new_password: newPassword,
        },
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      await refreshMe();
      setNotice(
        me.has_password ? "密码已修改，其他设备已退出登录" : "密码已设置，现在可以使用邮箱登录",
      );
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="max-w-4xl">
      <PageHeader
        title="个人中心"
        description="管理账号的显示名称、登录邮箱与密码"
      />
      <ErrorAlert message={error} />
      <SuccessAlert message={notice} />

      <Card className="mb-6">
        <CardContent className="flex flex-wrap items-center gap-4">
          <div className="flex size-12 shrink-0 items-center justify-center rounded-full bg-primary/10 text-lg font-medium text-primary">
            {initial}
          </div>
          <div className="min-w-0">
            <p className="truncate font-heading text-base font-medium">
              {me.name || me.email}
            </p>
            <p className="truncate text-sm text-muted-foreground">{me.email}</p>
          </div>
          <Badge className="ml-auto" variant="secondary">
            {ROLE_LABELS[me.role]}
          </Badge>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>用户名</CardTitle>
            <CardDescription>显示在侧边栏与控制台中的名称。</CardDescription>
          </CardHeader>
          <CardContent>
            <form noValidate onSubmit={saveName}>
              <FieldGroup className="gap-4">
                <Field data-invalid={Boolean(nameError)}>
                  <FieldLabel htmlFor="account-name">用户名</FieldLabel>
                  <Input
                    aria-invalid={Boolean(nameError) || undefined}
                    autoComplete="nickname"
                    id="account-name"
                    maxLength={128}
                    value={name}
                    onChange={(event) => {
                      setName(event.target.value);
                      if (nameError) setNameError(null);
                    }}
                  />
                  <FieldError>{nameError}</FieldError>
                </Field>
                <div className="flex justify-end">
                  <Button disabled={busy !== null} type="submit">
                    {busy === "name" ? "保存中…" : "保存用户名"}
                  </Button>
                </div>
              </FieldGroup>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>登录邮箱</CardTitle>
            <CardDescription>修改后请使用新邮箱与密码登录。</CardDescription>
          </CardHeader>
          <CardContent>
            <form noValidate onSubmit={saveEmail}>
              <FieldGroup className="gap-4">
                <Field data-invalid={Boolean(emailError)}>
                  <FieldLabel htmlFor="account-email">邮箱</FieldLabel>
                  <Input
                    aria-invalid={Boolean(emailError) || undefined}
                    autoComplete="email"
                    id="account-email"
                    maxLength={255}
                    type="email"
                    value={email}
                    onChange={(event) => {
                      setEmail(event.target.value);
                      if (emailError) setEmailError(null);
                    }}
                  />
                  <FieldError>{emailError}</FieldError>
                </Field>
                {me.has_password ? (
                  <Field>
                    <FieldLabel htmlFor="account-email-password">当前密码</FieldLabel>
                    <Input
                      autoComplete="current-password"
                      id="account-email-password"
                      maxLength={256}
                      type="password"
                      value={emailPassword}
                      onChange={(event) => setEmailPassword(event.target.value)}
                    />
                    <FieldDescription>修改邮箱需要验证当前密码。</FieldDescription>
                  </Field>
                ) : (
                  <FieldDescription>
                    该账号通过第三方登录创建，尚未设置密码，修改邮箱无需验证密码。
                  </FieldDescription>
                )}
                <div className="flex justify-end">
                  <Button disabled={busy !== null} type="submit">
                    {busy === "email" ? "保存中…" : "保存邮箱"}
                  </Button>
                </div>
              </FieldGroup>
            </form>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>{me.has_password ? "修改密码" : "设置密码"}</CardTitle>
          <CardDescription>
            密码至少 8 位。修改密码后，其他设备上的登录会退出。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form noValidate onSubmit={savePassword}>
            <FieldGroup className="gap-4">
              {me.has_password ? (
                <Field>
                  <FieldLabel htmlFor="account-current-password">当前密码</FieldLabel>
                  <Input
                    autoComplete="current-password"
                    id="account-current-password"
                    maxLength={256}
                    type="password"
                    value={currentPassword}
                    onChange={(event) => {
                      setCurrentPassword(event.target.value);
                      if (passwordError) setPasswordError(null);
                    }}
                  />
                </Field>
              ) : (
                <FieldDescription>
                  该账号尚未设置密码，设置后即可使用邮箱与密码登录。
                </FieldDescription>
              )}
              <div className="grid gap-4 sm:grid-cols-2">
                <Field data-invalid={Boolean(passwordError)}>
                  <FieldLabel htmlFor="account-new-password">新密码</FieldLabel>
                  <Input
                    aria-invalid={Boolean(passwordError) || undefined}
                    autoComplete="new-password"
                    id="account-new-password"
                    maxLength={256}
                    type="password"
                    value={newPassword}
                    onChange={(event) => {
                      setNewPassword(event.target.value);
                      if (passwordError) setPasswordError(null);
                    }}
                  />
                </Field>
                <Field data-invalid={Boolean(passwordError)}>
                  <FieldLabel htmlFor="account-confirm-password">确认新密码</FieldLabel>
                  <Input
                    aria-invalid={Boolean(passwordError) || undefined}
                    autoComplete="new-password"
                    id="account-confirm-password"
                    maxLength={256}
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => {
                      setConfirmPassword(event.target.value);
                      if (passwordError) setPasswordError(null);
                    }}
                  />
                </Field>
              </div>
              <FieldError>{passwordError}</FieldError>
              <div className="flex justify-end">
                <Button disabled={busy !== null} type="submit">
                  {busy === "password"
                    ? "保存中…"
                    : me.has_password
                      ? "修改密码"
                      : "设置密码"}
                </Button>
              </div>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
