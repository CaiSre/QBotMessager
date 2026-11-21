import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";
import { Inter } from "next/font/google";
import { AuthThemeToggle } from "@/components/theme-toggle";
import { ThemeProvider } from "@/lib/theme";
import { cn } from "@/lib/utils";

const inter = Inter({subsets:['latin'],variable:'--font-sans'});

export const metadata: Metadata = {
  title: "QBotMessager",
  description: "钉钉 / 企业微信 / 飞书 Webhook 统一转换并推送至 QQ 机器人",
};

// 在水合前按本地偏好上好色，避免刷新时先闪一下浅色
const THEME_SCRIPT = `(function(){try{var m=localStorage.getItem("theme");if(m!=="light"&&m!=="dark")m="system";var d=m==="dark"||(m==="system"&&window.matchMedia("(prefers-color-scheme: dark)").matches);var r=document.documentElement;r.classList.toggle("dark",d);r.style.colorScheme=d?"dark":"light";}catch(e){}})();`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="zh-CN"
      suppressHydrationWarning
      className={cn("font-sans", inter.variable)}
    >
      <body className="min-h-screen bg-background text-foreground antialiased">
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        <ThemeProvider>
          {children}
          <AuthThemeToggle />
        </ThemeProvider>
      </body>
    </html>
  );
}
