"use client";

import { useEffect } from "react";

import { Button } from "@/components/ui/button";

export default function ConsoleError({
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
    <div className="rounded-2xl border bg-card px-6 py-10 text-center">
      <h1 className="font-heading text-base font-medium">此页面加载失败</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        可以重试，或从左侧导航切换到其他页面。
      </p>
      <Button className="mt-5" variant="secondary" onClick={() => retry()}>
        重试
      </Button>
    </div>
  );
}
