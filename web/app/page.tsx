"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

// 静态导出下无法在服务端 redirect，改为客户端替换路由到 /dashboard。
// 渲染空容器，交接期间不出现可见内容闪烁。
export default function Home() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/dashboard");
  }, [router]);

  return <div className="min-h-screen" />;
}
