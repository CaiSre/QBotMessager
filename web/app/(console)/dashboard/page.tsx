"use client";

import Link from "next/link";

import { PushTrendChart } from "@/components/charts/push-trend-chart";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyHint, ErrorAlert, PageHeader } from "@/components/ui";
import { formatDateTime, formatPercent, truncate } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useMe } from "@/lib/me";
import { HOOK_TYPE_LABELS, type Stats } from "@/lib/types";

function Metric({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card size="sm">
      <CardContent className="flex flex-col gap-1">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="font-heading text-3xl font-medium tabular-nums tracking-tight">{value}</p>
        {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

export default function DashboardPage() {
  const me = useMe();
  const { data, error, loading } = useApi<Stats>("/api/admin/stats");

  // 后端异常响应可能缺 trend，兜底避免渲染时 TypeError 白屏。
  const trend = data?.trend ?? [];
  const weekTotal = trend.reduce((sum, day) => sum + day.count, 0);

  return (
    <div>
      <PageHeader
        title="概览"
        description={me.role === "super_admin" ? "全站今日的推送情况" : "我的今日推送情况"}
      />
      <ErrorAlert message={error} />

      {loading && !data ? <p className="text-sm text-muted-foreground">加载中…</p> : null}

      {data ? (
        <div className="flex flex-col gap-6">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Metric label="今日推送" value={String(data.today.total)} hint="含成功与失败" />
            <Metric label="今日成功" value={String(data.today.success)} />
            <Metric label="今日成功率" value={formatPercent(data.success_rate)} />
            <Metric label="近 7 日推送" value={String(weekTotal)} />
          </div>

          <div className="grid gap-4 lg:grid-cols-5">
            <PushTrendChart className="lg:col-span-3" data={trend} />

            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>今日推送来源</CardTitle>
              </CardHeader>
              <CardContent>
                {data.by_source.length === 0 ? (
                  <EmptyHint>今日暂无推送</EmptyHint>
                ) : (
                  <ul className="flex flex-col gap-3">
                    {data.by_source.map((row) => (
                      <li className="flex items-center justify-between" key={row.source}>
                        <span className="text-sm">{row.source || "未设置"}</span>
                        <Badge variant="secondary">{row.count}</Badge>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>最近失败</CardTitle>
              <CardDescription>
                查看完整记录请前往{" "}
                <Link className="text-primary hover:underline" href="/logs">
                  推送日志
                </Link>
              </CardDescription>
            </CardHeader>
            <CardContent>
              {data.recent_failures.length === 0 ? (
                <EmptyHint>没有失败记录</EmptyHint>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>时间</TableHead>
                      <TableHead>钩子类型</TableHead>
                      <TableHead>目标</TableHead>
                      <TableHead>错误码</TableHead>
                      <TableHead>错误信息</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.recent_failures.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell>{formatDateTime(row.created_at)}</TableCell>
                        <TableCell>
                          {HOOK_TYPE_LABELS[row.hook_type] ?? row.hook_type}
                        </TableCell>
                        <TableCell>{row.target ?? "—"}</TableCell>
                        <TableCell>{row.error_code ?? "—"}</TableCell>
                        <TableCell>{truncate(row.error_message, 48)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </div>
  );
}
