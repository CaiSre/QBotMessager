"use client";

import { useCallback, useEffect, useState } from "react";

import { api, messageOf } from "./api";

/** 读取一个 GET 接口；key 变化时重新拉取（用于筛选条件）。 */
export function useApi<T>(path: string | null, key = "") {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState(0);

  const reload = useCallback(async () => {
    if (!path) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      setData(await api<T>(path));
      setError(null);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setLoading(false);
    }
  }, [path, key, version]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return {
    data,
    error,
    loading,
    reload,
    refresh: () => setVersion((v) => v + 1),
    setData,
  };
}
