"use client";

import { createContext, useContext } from "react";

import type { Me } from "./types";

const MeContext = createContext<Me | null>(null);

export const MeProvider = MeContext.Provider;

export function useMe(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useMe 只能在控制台布局内使用");
  return me;
}

export function isSuperAdmin(role: string): boolean {
  return role === "super_admin";
}
