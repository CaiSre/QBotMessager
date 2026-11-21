export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  // MySQL DATETIME 丢时区，后端返回的是不带偏移的 UTC 时间，按 UTC 解析后再转本地时区
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(value);
  const date = new Date(hasZone ? value : `${value}Z`);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

export function truncate(value: string | null | undefined, limit = 60): string {
  if (!value) return "—";
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

export const STATUS_LABELS: Record<string, string> = {
  success: "成功",
  failed: "失败",
  partial: "部分成功",
};

export const STATUS_COLORS: Record<string, "success" | "danger" | "warning" | "default"> = {
  success: "success",
  failed: "danger",
  partial: "warning",
};
