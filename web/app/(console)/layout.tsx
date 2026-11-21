"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  BotIcon,
  LayoutDashboardIcon,
  ScrollTextIcon,
  Settings2Icon,
  ShieldCheckIcon,
  UsersIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, isUnauthorized, messageOf } from "@/lib/api";
import { MeProvider, isSuperAdmin } from "@/lib/me";
import { ROLE_LABELS, type Me } from "@/lib/types";

const NAV = [
  { href: "/dashboard", label: "概览", icon: LayoutDashboardIcon },
  { href: "/bots", label: "机器人", icon: BotIcon },
  { href: "/logs", label: "推送日志", icon: ScrollTextIcon },
  { href: "/env", label: "环境配置", icon: Settings2Icon },
  { href: "/security", label: "安全设置", icon: ShieldCheckIcon },
];

const ADMIN_NAV = [{ href: "/users", label: "用户管理", icon: UsersIcon }];

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setMe(await api<Me>("/api/auth/me"));
    } catch (err) {
      if (isUnauthorized(err)) {
        router.replace("/login");
        return;
      }
      setError(messageOf(err));
    }
  }, [router]);

  useEffect(() => {
    void load();
  }, [load]);

  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch {
      // 忽略退出失败，本地仍跳回登录页
    }
    router.replace("/login");
  }

  if (!me) {
    return (
      <main className="flex min-h-screen items-center justify-center px-4">
        <div className="text-center">
          {error ? (
            <>
              <p className="text-sm text-destructive">{error}</p>
              <Button className="mt-4" variant="secondary" onClick={() => void load()}>
                重试
              </Button>
            </>
          ) : (
            <p className="text-sm text-muted-foreground">正在校验登录状态…</p>
          )}
        </div>
      </main>
    );
  }

  return (
    <MeProvider value={me}>
      <div className="flex min-h-screen flex-col lg:flex-row">
        <aside className="flex shrink-0 flex-col gap-4 border-b bg-sidebar px-4 py-4 text-sidebar-foreground lg:w-60 lg:border-r lg:border-b-0 lg:px-3 lg:py-6">
          <div className="px-2">
            <p className="font-heading text-base leading-snug font-medium tracking-tight">QBotMessager</p>
            <div className="mt-2 flex items-center gap-2">
              <span className="truncate text-xs text-muted-foreground">{me.email}</span>
              <Badge variant="secondary">{ROLE_LABELS[me.role]}</Badge>
            </div>
          </div>

          <nav className="flex gap-1 overflow-x-auto lg:flex-col lg:overflow-visible">
            {(isSuperAdmin(me.role) ? [...NAV, ...ADMIN_NAV] : NAV).map((item) => {
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  className={[
                    "flex shrink-0 items-center gap-2.5 rounded-2xl px-3 py-2 text-sm font-medium transition-colors",
                    active
                      ? "bg-sidebar-accent text-sidebar-accent-foreground"
                      : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
                  ].join(" ")}
                  href={item.href}
                >
                  <Icon className="size-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="mt-auto hidden flex-col gap-3 border-t pt-4 lg:flex">
            <div className="px-2">
              <p className="truncate text-sm font-medium">{me.name || me.email}</p>
              <p className="truncate text-xs text-muted-foreground">{me.email}</p>
            </div>
            <Button variant="outline" onClick={logout}>
              退出登录
            </Button>
          </div>
        </aside>

        <main className="min-w-0 flex-1 px-4 py-6 lg:px-8 lg:py-8">
          <div className="mx-auto w-full max-w-[1400px]">{children}</div>
        </main>
      </div>
    </MeProvider>
  );
}
