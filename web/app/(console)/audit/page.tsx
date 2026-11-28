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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyHint, ErrorAlert, PageHeader } from "@/components/ui";
import { formatDateTime, truncate } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { AuditLog, AuditPage } from "@/lib/types";

const PAGE_SIZE = 50;

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

function detailText(detail: unknown): string {
  if (detail == null) return "—";
  if (typeof detail === "string") return detail;
  try {
    return JSON.stringify(detail, null, 2);
  } catch {
    return String(detail);
  }
}

export default function AuditPage() {
  const [action, setAction] = useState("");
  const [actorId, setActorId] = useState("");
  const [keyword, setKeyword] = useState("");
  const [applied, setApplied] = useState({ action: "", actorId: "", keyword: "" });
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<AuditLog | null>(null);

  const query = useMemo(() => {
    const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (applied.action) params.set("action", applied.action);
    if (applied.actorId) params.set("actor_user_id", applied.actorId);
    if (applied.keyword) params.set("keyword", applied.keyword);
    return `/api/admin/audit?${params.toString()}`;
  }, [page, applied]);

  const { data, error, loading } = useApi<AuditPage>(query);
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;
  const currentPage = data?.page ?? page;

  function applyFilters() {
    setApplied({ action: action.trim(), actorId: actorId.trim(), keyword: keyword.trim() });
    setPage(1);
  }

  function goTo(next: number) {
    if (next < 1 || next > totalPages || next === page) return;
    setPage(next);
  }

  return (
    <div className="flex flex-col lg:h-[calc(100dvh-4rem)]">
      <PageHeader
        title="审计日志"
        description="管理操作与认证敏感事件；仅超级管理员可见"
      />
      <ErrorAlert message={error} />

      <Card className="mb-4 shrink-0" size="sm">
        <CardContent>
          <div className="flex flex-row flex-wrap items-end gap-4">
            <div className="w-56">
              <Field>
                <FieldLabel htmlFor="audit-action">动作</FieldLabel>
                <Input
                  id="audit-action"
                  placeholder="例如 auth.login"
                  value={action}
                  onChange={(event) => setAction(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") applyFilters();
                  }}
                />
              </Field>
            </div>
            <div className="w-40">
              <Field>
                <FieldLabel htmlFor="audit-actor">操作者 ID</FieldLabel>
                <Input
                  id="audit-actor"
                  inputMode="numeric"
                  placeholder="用户 ID"
                  value={actorId}
                  onChange={(event) => setActorId(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") applyFilters();
                  }}
                />
              </Field>
            </div>
            <div className="min-w-56 flex-1">
              <Field>
                <FieldLabel htmlFor="audit-keyword">关键词</FieldLabel>
                <Input
                  id="audit-keyword"
                  placeholder="动作、目标或 IP 片段"
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
              <EmptyHint>没有符合条件的审计记录</EmptyHint>
            ) : null}
            {data && data.items.length > 0 ? (
              <Table containerClassName="overflow-visible">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>时间</TableHead>
                    <TableHead>操作者</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead>目标</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead>详情</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell>{formatDateTime(row.created_at)}</TableCell>
                      <TableCell>{row.actor_user_id ?? "系统"}</TableCell>
                      <TableCell>
                        <Badge variant={row.action.startsWith("auth.") ? "secondary" : "outline"}>
                          {row.action}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs">
                          {row.target_type ?? "—"}
                          {row.target_id ? ` / ${truncate(row.target_id, 28)}` : ""}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs">{row.ip ?? "—"}</span>
                      </TableCell>
                      <TableCell>
                        <Button
                          className="block h-auto justify-start p-0 text-left"
                          size="xs"
                          type="button"
                          variant="link"
                          onClick={() => setDetail(row)}
                        >
                          查看
                        </Button>
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
            <DialogTitle>审计详情 #{detail?.id}</DialogTitle>
          </DialogHeader>
          {detail ? (
            <>
              <dl className="grid grid-cols-[7rem_minmax(0,1fr)] gap-y-3 text-sm">
                <dt className="text-muted-foreground">时间</dt>
                <dd>{formatDateTime(detail.created_at)}</dd>
                <dt className="text-muted-foreground">操作者</dt>
                <dd>{detail.actor_user_id ?? "系统"}</dd>
                <dt className="text-muted-foreground">动作</dt>
                <dd className="break-all">{detail.action}</dd>
                <dt className="text-muted-foreground">目标</dt>
                <dd className="break-all">
                  {detail.target_type ?? "—"}
                  {detail.target_id ? ` / ${detail.target_id}` : ""}
                </dd>
                <dt className="text-muted-foreground">IP</dt>
                <dd className="break-all">{detail.ip ?? "—"}</dd>
              </dl>
              <Field className="min-w-0 gap-2">
                <FieldLabel>详情</FieldLabel>
                <div className="max-h-64 overflow-y-auto rounded-2xl border bg-muted/20 p-3 text-xs whitespace-pre-wrap wrap-anywhere">
                  {detailText(detail.detail)}
                </div>
              </Field>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
