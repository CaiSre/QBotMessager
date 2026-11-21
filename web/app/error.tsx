"use client";

import { useEffect } from "react";

import { Button } from "@/components/ui/button";

export default function RootError({
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
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="max-w-md text-center">
        <h1 className="font-heading text-lg font-medium">页面出现异常</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          页面加载失败，请重试；若持续出现，请联系管理员。
        </p>
        <Button className="mt-5" variant="secondary" onClick={() => retry()}>
          重试
        </Button>
      </div>
    </main>
  );
}
