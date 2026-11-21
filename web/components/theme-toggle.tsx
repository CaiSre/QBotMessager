"use client";

import { usePathname } from "next/navigation";
import {
  MonitorIcon,
  MoonIcon,
  SunIcon,
  type LucideIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { useTheme, type ThemeMode } from "@/lib/theme";

const NEXT_MODE: Record<ThemeMode, ThemeMode> = {
  system: "light",
  light: "dark",
  dark: "system",
};

const MODE_LABELS: Record<ThemeMode, string> = {
  system: "跟随系统",
  light: "浅色",
  dark: "深色",
};

const MODE_ICONS: Record<ThemeMode, LucideIcon> = {
  system: MonitorIcon,
  light: SunIcon,
  dark: MoonIcon,
};

export function ThemeToggle({ className }: { className?: string }) {
  const { mode, setMode } = useTheme();
  const Icon = MODE_ICONS[mode];
  const label = `主题：${MODE_LABELS[mode]}，点击切换`;

  return (
    <Button
      aria-label={label}
      className={className}
      size="icon-sm"
      title={label}
      type="button"
      variant="ghost"
      onClick={() => setMode(NEXT_MODE[mode])}
    >
      <Icon />
    </Button>
  );
}

/** 登录、注册、找回密码等控制台之外的页面显示浮动切换按钮。 */
export function AuthThemeToggle() {
  const pathname = usePathname();
  const isAuthPage =
    pathname === "/login" ||
    pathname === "/register" ||
    pathname === "/forgot-password";

  if (!isAuthPage) return null;

  return (
    <div className="fixed top-3 right-3 z-50">
      <ThemeToggle />
    </div>
  );
}
