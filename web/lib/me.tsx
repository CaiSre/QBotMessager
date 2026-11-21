"use client";

import { createContext, useContext, type ReactNode } from "react";

import type { Me } from "./types";

const MeContext = createContext<Me | null>(null);
const MeRefreshContext = createContext<() => Promise<void>>(async () => {});

export function MeProvider({
  me,
  refresh,
  children,
}: {
  me: Me;
  refresh: () => Promise<void>;
  children: ReactNode;
}) {
  return (
    <MeContext.Provider value={me}>
      <MeRefreshContext.Provider value={refresh}>{children}</MeRefreshContext.Provider>
    </MeContext.Provider>
  );
}

export function useMe(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useMe 只能在控制台布局内使用");
  return me;
}

export function useRefreshMe(): () => Promise<void> {
  return useContext(MeRefreshContext);
}

export function isSuperAdmin(role: string): boolean {
  return role === "super_admin";
}
