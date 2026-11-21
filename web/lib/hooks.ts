"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api, isUnauthorized, messageOf } from "./api";

/** 读取一个 GET 接口；key 变化时重新拉取（用于筛选条件）。 */
export function useApi<T>(path: string | null, key = "") {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState(0);
  const requestSeq = useRef(0);
  const controllerRef = useRef<AbortController | null>(null);

  const reload = useCallback(async () => {
    if (!path) {
      setLoading(false);
      return;
    }
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const seq = ++requestSeq.current;
    setLoading(true);
    try {
      const result = await api<T>(path, { signal: controller.signal });
      // 只接受最新一次请求的结果，避免旧响应覆盖新筛选条件
      if (seq !== requestSeq.current) return;
      setData(result);
      setError(null);
    } catch (err) {
      if (seq !== requestSeq.current || controller.signal.aborted) return;
      if (isUnauthorized(err)) {
        window.location.replace("/login");
        return;
      }
      setError(messageOf(err));
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [path, key, version]);

  useEffect(() => {
    void reload();
    return () => {
      controllerRef.current?.abort();
    };
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
