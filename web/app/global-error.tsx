"use client";

import "./globals.css";

import { useEffect } from "react";

// global-error 替换根布局渲染，必须自带 html/body，样式需显式引入。
export default function GlobalError({
  error,
  retry,
}: {
  error: unknown;
  retry: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <html lang="zh-CN">
      <body className="bg-background text-foreground antialiased">
        <main className="flex min-h-screen items-center justify-center px-4">
          <div className="max-w-md text-center">
            <h1 className="font-heading text-lg font-medium">服务暂时不可用</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              页面渲染失败，请重试；若持续出现，请联系管理员。
            </p>
            <button
              className="mt-5 inline-flex h-9 items-center rounded-4xl border border-border bg-background px-3 text-sm font-medium hover:bg-muted"
              type="button"
              onClick={() => retry()}
            >
              重试
            </button>
          </div>
        </main>
      </body>
    </html>
  );
}
