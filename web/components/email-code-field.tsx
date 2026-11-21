"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { api, messageOf } from "@/lib/api";

/** 发码按钮的倒计时与状态；请求路径由调用方按用途提供。 */
export function useEmailCode() {
  const [cooldown, setCooldown] = useState(0);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = window.setTimeout(() => setCooldown((value) => value - 1), 1000);
    return () => window.clearTimeout(timer);
  }, [cooldown]);

  async function send(path: string, body?: unknown) {
    setSending(true);
    setError(null);
    setNotice(null);
    try {
      const data = await api<{ resend_after?: number }>(path, {
        method: "POST",
        body,
      });
      setCooldown(data.resend_after ?? 60);
      setNotice("验证码已发送，请查收邮箱");
      return true;
    } catch (err) {
      setError(messageOf(err));
      return false;
    } finally {
      setSending(false);
    }
  }

  return { cooldown, sending, error, notice, send };
}

export function EmailCodeField({
  id,
  value,
  onChange,
  onSend,
  cooldown,
  sending,
  error,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  onSend: () => void;
  cooldown: number;
  sending: boolean;
  error: string | null;
}) {
  return (
    <Field data-invalid={Boolean(error)}>
      <FieldLabel htmlFor={id}>邮箱验证码</FieldLabel>
      <div className="flex gap-2">
        <Input
          aria-invalid={Boolean(error) || undefined}
          autoComplete="one-time-code"
          className="flex-1"
          id={id}
          inputMode="numeric"
          maxLength={6}
          placeholder="6 位数字"
          value={value}
          onChange={(event) => onChange(event.target.value.replace(/\D/g, ""))}
        />
        <Button
          disabled={sending || cooldown > 0}
          onClick={onSend}
          type="button"
          variant="outline"
        >
          {cooldown > 0 ? `${cooldown} 秒` : sending ? "发送中…" : "发送验证码"}
        </Button>
      </div>
      <FieldError>{error}</FieldError>
    </Field>
  );
}
