export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
}

function detailOf(payload: unknown): string {
  if (!payload || typeof payload !== "object") return "";
  const detail = (payload as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (item && typeof item === "object" && "msg" in item) {
          return String((item as { msg: unknown }).msg);
        }
        return String(item);
      })
      .join("；");
  }
  return "";
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, signal } = options;
  const hasBody = body !== undefined;
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers: hasBody ? { "Content-Type": "application/json" } : undefined,
      body: hasBody ? JSON.stringify(body) : undefined,
      credentials: "include",
      cache: "no-store",
      signal,
    });
  } catch (error) {
    if ((error as Error).name === "AbortError") throw error;
    throw new ApiError(0, "网络异常，无法连接服务");
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    const timedOut = response.status === 408 || response.status === 504;
    const fallback = timedOut
      ? "请求超时，请稍后重试"
      : `请求失败（HTTP ${response.status}）`;
    const message = detailOf(payload) || fallback;
    throw new ApiError(response.status, message);
  }
  return payload as T;
}

// 浏览器 WebAuthn 把“用户取消/拒绝”与“超时”统一抛为 NotAllowedError，
// 原生 message 是英文长文本，这里替换成可直接展示的中文。
const READABLE_ERRORS: Record<string, string> = {
  NotAllowedError: "操作已超时或被取消，请重试",
  AbortError: "操作已取消",
  TimeoutError: "操作超时，请重试",
};

export function messageOf(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return READABLE_ERRORS[error.name] ?? (error.message || "操作失败");
  return String(error);
}

export function isUnauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}
