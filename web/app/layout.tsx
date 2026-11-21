import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";
import { Inter } from "next/font/google";
import { cn } from "@/lib/utils";

const inter = Inter({subsets:['latin'],variable:'--font-sans'});

export const metadata: Metadata = {
  title: "QBotMessager",
  description: "钉钉 / 企业微信 / 飞书 Webhook 统一转换并推送至 QQ 机器人",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="zh-CN" className={cn("font-sans", inter.variable)}>
      <body className="min-h-screen bg-background text-foreground antialiased">{children}</body>
    </html>
  );
}
