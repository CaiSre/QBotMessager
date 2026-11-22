"use client";

import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyHint, ErrorAlert, PageHeader } from "@/components/ui";
import { STATUS_LABELS, formatDateTime, truncate } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { isSuperAdmin, useMe } from "@/lib/me";
import { PLATFORM_LABELS, type LogPage, type Platform, type PushLog } from "@/lib/types";

const PAGE_SIZE = 20;

const PLATFORM_OPTIONS: { id: string; label: string }[] = [
  { id: "all", label: "全部平台" },
  { id: "dingtalk", label: PLATFORM_LABELS.dingtalk },
  { id: "wecom", label: PLATFORM_LABELS.wecom },
  { id: "feishu", label: PLATFORM_LABELS.feishu },
  { id: "github", label: PLATFORM_LABELS.github },
];

const STATUS_OPTIONS = [
  { id: "all", label: "全部状态" },
  { id: "success", label: "成功" },
  { id: "partial", label: "部分成功" },
  { id: "failed", label: "失败" },
];

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { id: string; label: string }[];
  onChange: (value: string) => void;
}) {
  const items = options.map((option) => ({ label: option.label, value: option.id }));
  return (
    <div className="flex flex-col gap-2">
      <Label>{label}</Label>
      <Select
        items={items}
        value={value}
        onValueChange={(next) => onChange(String(next))}
      >
        <SelectTrigger className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent alignItemWithTrigger={false}>
          <SelectGroup>
            {items.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  );
}

const STATUS_VARIANTS: Record<string, "default" | "destructive" | "secondary" | "outline"> = {
  success: "default",
  failed: "destructive",
  partial: "secondary",
};

/** 最多 7 个页码位，超出部分用省略号折叠。 */
function pageWindow(current: number, total: number): (number | "gap-start" | "gap-end")[] {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const start = Math.max(2, Math.min(current - 1, total - 3));
  const end = Math.min(total - 1, Math.max(current + 1, 4));
  const items: (number | "gap-start" | "gap-end")[] = [1];
  if (start > 2) items.push("gap-start");
  for (let value = start; value <= end; value += 1) items.push(value);
  if (end < total - 1) items.push("gap-end");
  items.push(total);
  return items;
}

export default function LogsPage() {
  const me = useMe();
  const superAdmin = isSuperAdmin(me.role);
  const [platform, setPlatform] = useState("all");
  const [status, setStatus] = useState("all");
  const [keyword, setKeyword] = useState("");
  const [appliedKeyword, setAppliedKeyword] = useState("");
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<PushLog | null>(null);

  const query = useMemo(() => {
    const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (platform !== "all") params.set("platform", platform);
    if (status !== "all") params.set("status", status);
    if (appliedKeyword) params.set("keyword", appliedKeyword);
    return `/api/admin/logs?${params.toString()}`;
  }, [page, platform, status, appliedKeyword]);

  const { data, error, loading } = useApi<LogPage>(query);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;
  const currentPage = data?.page ?? page;

  function applyFilters() {
    setAppliedKeyword(keyword.trim());
    setPage(1);
  }

  function goTo(next: number) {
    if (next < 1 || next > totalPages || next === page) return;
    setPage(next);
  }

  return (
    <div className="flex flex-col lg:h-[calc(100dvh-4rem)]">
      <PageHeader title="推送日志" description="记录每一次 Webhook 转换与 QQ 推送的结果" />
      <ErrorAlert message={error} />

      <Card className="mb-4 shrink-0" size="sm">
        <CardContent>
          <div className="flex flex-row flex-wrap items-end gap-4">
            <div className="w-44">
              <FilterSelect
                label="平台"
                options={PLATFORM_OPTIONS}
                value={platform}
                onChange={(value) => {
                  setPlatform(value);
                  setPage(1);
                }}
              />
            </div>
            <div className="w-44">
              <FilterSelect
                label="状态"
                options={STATUS_OPTIONS}
                value={status}
                onChange={(value) => {
                  setStatus(value);
                  setPage(1);
                }}
              />
            </div>
            <div className="min-w-56 flex-1">
              <Field>
                <FieldLabel htmlFor="keyword">内容关键字</FieldLabel>
                <Input
                  id="keyword"
                  placeholder="按消息内容片段筛选"
                  value={keyword}
                  onChange={(event) => setKeyword(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") applyFilters();
                  }}
                />
              </Field>
            </div>
            <Button variant="secondary" onClick={applyFilters}>
              筛选
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card className="min-h-[24rem] flex-1">
        <CardHeader className="shrink-0">
          <CardTitle>记录</CardTitle>
        </CardHeader>
        <CardContent className="flex min-h-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 overflow-auto max-lg:max-h-[60dvh]">
            {loading && !data ? (
              <p className="py-6 text-sm text-muted-foreground">加载中…</p>
            ) : null}
            {data && data.items.length === 0 ? (
              <EmptyHint>没有符合条件的日志</EmptyHint>
            ) : null}
            {data && data.items.length > 0 ? (
              <Table containerClassName="overflow-visible">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>时间</TableHead>
                    {superAdmin ? <TableHead>所属用户</TableHead> : null}
                    <TableHead>平台</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>目标</TableHead>
                    <TableHead>内容</TableHead>
                    <TableHead>耗时</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell>{formatDateTime(row.created_at)}</TableCell>
                      {superAdmin ? (
                        <TableCell>
                          <span className="text-xs">{row.owner_email ?? "—"}</span>
                        </TableCell>
                      ) : null}
                      <TableCell>
                        {PLATFORM_LABELS[row.platform as Platform] ?? row.platform}
                      </TableCell>
                      <TableCell>
                        <Badge variant={STATUS_VARIANTS[row.status] ?? "outline"}>
                          {STATUS_LABELS[row.status] ?? row.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{row.target ?? "—"}</TableCell>
                      <TableCell>
                        <Button
                          className="block h-auto max-w-80 justify-start truncate p-0 text-left"
                          size="xs"
                          type="button"
                          variant="link"
                          onClick={() => setDetail(row)}
                        >
                          {truncate(row.content_preview, 50)}
                        </Button>
                      </TableCell>
                      <TableCell>
                        {row.duration_ms != null ? `${row.duration_ms.toFixed(1)} ms` : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : null}
          </div>

          <div className="mt-4 flex shrink-0 flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">
              共 {data?.total ?? 0} 条 · 第 {currentPage} / {totalPages} 页
            </p>
            <Pagination className="mx-0 w-auto">
              <PaginationContent>
                <PaginationItem>
                  <PaginationPrevious
                    aria-disabled={page <= 1}
                    aria-label="上一页"
                    className={page <= 1 ? "pointer-events-none opacity-50" : undefined}
                    href="#"
                    text="上一页"
                    onClick={(event) => {
                      event.preventDefault();
                      goTo(page - 1);
                    }}
                  />
                </PaginationItem>
                {pageWindow(currentPage, totalPages).map((item) =>
                  typeof item === "number" ? (
                    <PaginationItem key={item}>
                      <PaginationLink
                        aria-label={`第 ${item} 页`}
                        href="#"
                        isActive={item === currentPage}
                        onClick={(event) => {
                          event.preventDefault();
                          goTo(item);
                        }}
                      >
                        {item}
                      </PaginationLink>
                    </PaginationItem>
                  ) : (
                    <PaginationItem key={item}>
                      <PaginationEllipsis />
                    </PaginationItem>
                  ),
                )}
                <PaginationItem>
                  <PaginationNext
                    aria-disabled={page >= totalPages}
                    aria-label="下一页"
                    className={page >= totalPages ? "pointer-events-none opacity-50" : undefined}
                    href="#"
                    text="下一页"
                    onClick={(event) => {
                      event.preventDefault();
                      goTo(page + 1);
                    }}
                  />
                </PaginationItem>
              </PaginationContent>
            </Pagination>
          </div>
        </CardContent>
      </Card>

      <Dialog open={detail !== null} onOpenChange={(open) => !open && setDetail(null)}>
        <DialogContent className="grid-cols-[minmax(0,1fr)] sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>推送详情 #{detail?.id}</DialogTitle>
          </DialogHeader>
          {detail ? (
            <>
              <dl className="grid grid-cols-[7rem_minmax(0,1fr)] gap-y-3 text-sm">
                <dt className="text-muted-foreground">时间</dt>
                <dd>{formatDateTime(detail.created_at)}</dd>
                <dt className="text-muted-foreground">平台</dt>
                <dd>{PLATFORM_LABELS[detail.platform] ?? detail.platform}</dd>
                <dt className="text-muted-foreground">来源类型</dt>
                <dd>{detail.source_msgtype ?? "—"}</dd>
                <dt className="text-muted-foreground">状态</dt>
                <dd>{STATUS_LABELS[detail.status] ?? detail.status}</dd>
                <dt className="text-muted-foreground">接收目标</dt>
                <dd className="break-all">{detail.target ?? "—"}</dd>
                <dt className="text-muted-foreground">QQ msg_type</dt>
                <dd>{detail.qq_msg_type ?? "—"}</dd>
                <dt className="text-muted-foreground">内容长度</dt>
                <dd>{detail.content_len ?? "—"}</dd>
                <dt className="text-muted-foreground">耗时</dt>
                <dd>{detail.duration_ms != null ? `${detail.duration_ms.toFixed(1)} ms` : "—"}</dd>
                <dt className="text-muted-foreground">错误码</dt>
                <dd>{detail.error_code ?? "—"}</dd>
                <dt className="text-muted-foreground">错误信息</dt>
                <dd className="break-all">{detail.error_message ?? "—"}</dd>
                <dt className="text-muted-foreground">请求 ID</dt>
                <dd className="break-all text-xs">{detail.request_id ?? "—"}</dd>
              </dl>
              <Field className="min-w-0 gap-2">
                <FieldLabel>内容预览</FieldLabel>
                <div className="max-h-64 overflow-y-auto rounded-2xl border bg-muted/20 p-3 text-xs whitespace-pre-wrap wrap-anywhere">
                  {detail.content_preview ?? "—"}
                </div>
              </Field>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
