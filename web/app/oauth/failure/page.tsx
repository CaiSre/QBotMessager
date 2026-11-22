"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

// URL 参数由外链可控，渲染前截断长度上限，避免异常超长文案破坏版面。
const PARAM_MAX_CHARS = 200;

function truncateParam(value: string | null): string | null {
  if (value === null) return null;
  return value.length > PARAM_MAX_CHARS ? `${value.slice(0, PARAM_MAX_CHARS)}…` : value;
}

function FailureContent() {
  const searchParams = useSearchParams();
  const message = truncateParam(searchParams.get("message")) ?? "第三方授权未完成";
  const detail = truncateParam(searchParams.get("detail"));

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="font-heading text-2xl font-medium tracking-tight">QBotMessager</h1>
          <p className="mt-1 text-sm text-muted-foreground">第三方账号授权</p>
        </div>

        <Card>
          <CardContent className="flex flex-col gap-4">
            <p className="text-xs text-muted-foreground">以下信息来自登录跳转参数</p>
            <Alert variant="destructive">
              <AlertTitle>授权未完成</AlertTitle>
              <AlertDescription>
                {message}
                {detail ? <span className="mt-1 block break-all text-xs opacity-70">{detail}</span> : null}
              </AlertDescription>
            </Alert>

            <div className="flex flex-col gap-2">
              <Link className="w-full" href="/login">
                <Button className="w-full">返回登录</Button>
              </Link>
              <Link className="w-full" href="/">
                <Button className="w-full" variant="outline">
                  回到首页
                </Button>
              </Link>
            </div>

            <p className="text-center text-xs text-muted-foreground">
              如果反复失败，请联系管理员，或先用账户密码登录后在
              「安全设置」中绑定该第三方账号。
            </p>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}

export default function OAuthFailurePage() {
  return (
    <Suspense>
      <FailureContent />
    </Suspense>
  );
}
