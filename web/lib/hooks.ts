"use client";

import useSWR from "swr";

import { api, isUnauthorized, messageOf } from "./api";

/**
 * 读取一个 GET 接口；`path` 变化（或为 null）时重新拉取。
 *
 * 由 SWR 驱动：按请求路径去重并发、保留上一份数据避免筛选切换闪白、
 * 卸载后过期响应自动丢弃；`reload()` 绕过去重窗口强制刷新。
 */
export function useApi<T>(path: string | null) {
  const { data, error, isLoading, mutate } = useSWR<T, Error>(
    path,
    (requestPath) =>
      api<T>(requestPath).catch((err: unknown) => {
        if (isUnauthorized(err)) {
          window.location.replace("/login");
        }
        throw err;
      }),
    {
      shouldRetryOnError: false,
      revalidateOnFocus: false,
      keepPreviousData: true,
    },
  );

  return {
    data: data ?? null,
    error: error ? messageOf(error) : null,
    loading: isLoading,
    reload: () => mutate(),
    refresh: () => mutate(),
    setData: (value: T) => void mutate(value, { revalidate: false }),
  };
}
