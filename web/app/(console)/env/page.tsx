"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ConfirmDialog, EmptyHint, ErrorAlert, PageHeader } from "@/components/ui";
import { api, messageOf } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { isSuperAdmin, useMe } from "@/lib/me";
import type { EnvConfig } from "@/lib/types";

const DEPLOYMENT_VARS: Array<{ name: string; purpose: string }> = [
  { name: "MYSQL_URL", purpose: "数据库连接串，docker compose 注入" },
  { name: "APP_SECRET_KEY", purpose: "加密库内敏感字段的主密钥" },
  { name: "PUBLIC_BASE_URL", purpose: "对外访问地址，用于生成 Webhook 地址与 OAuth 回调" },
  { name: "SESSION_TTL_HOURS", purpose: "登录会话有效期（小时）" },
  { name: "COOKIE_SECURE", purpose: "会话 Cookie 是否仅限 HTTPS" },
  { name: "RP_ID / RP_NAME", purpose: "通行密钥（WebAuthn）的依赖方标识与名称" },
  {
    name: "BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD",
    purpose: "首次启动创建超级管理员；账号已存在时不生效",
  },
  { name: "QQ_APPID / QQ_APP_SECRET / OPENID", purpose: "首次启动导入的机器人凭据与默认目标" },
  { name: "QQ_HOST", purpose: "QQ 开放平台地址" },
  { name: "QQ_QPS / QQ_QPM / QQ_MIN_INTERVAL", purpose: "QQ 接口频控" },
  { name: "MARKDOWN_MAX_LEN / TEXT_MAX_LEN", purpose: "下发内容的长度上限" },
  { name: "MAX_BODY_BYTES", purpose: "Webhook 请求体上限" },
  { name: "LOG_LEVEL", purpose: "日志级别" },
];

export default function EnvPage() {
  const me = useMe();
  const superAdmin = isSuperAdmin(me.role);
  const configs = useApi<EnvConfig[]>("/api/admin/env-configs");

  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<EnvConfig | null>(null);
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [isSecret, setIsSecret] = useState(false);
  const [description, setDescription] = useState("");
  const [confirmId, setConfirmId] = useState<EnvConfig | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);

  const list = configs.data ?? [];

  function openCreate() {
    setEditing(null);
    setKey("");
    setValue("");
    setIsSecret(false);
    setDescription("");
    setError(null);
    setKeyError(null);
    setOpen(true);
  }

  function openEdit(item: EnvConfig) {
    setEditing(item);
    setKey(item.key);
    setValue(item.is_secret ? "" : (item.value ?? ""));
    setIsSecret(item.is_secret);
    setDescription(item.description ?? "");
    setError(null);
    setKeyError(null);
    setOpen(true);
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!editing && !key.trim()) {
      setKeyError("请填写键");
      return;
    }
    setKeyError(null);
    setSaving(true);
    setError(null);
    try {
      if (editing) {
        const body: Record<string, unknown> = { is_secret: isSecret, description };
        if (value !== "" || !editing.is_secret) body.value = value;
        await api(`/api/admin/env-configs/${editing.id}`, { method: "PATCH", body });
      } else {
        await api("/api/admin/env-configs", {
          method: "POST",
          body: { key: key.trim(), value, is_secret: isSecret, description },
        });
      }
      setOpen(false);
      await configs.reload();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setSaving(false);
    }
  }

  async function remove(item: EnvConfig) {
    setError(null);
    try {
      await api(`/api/admin/env-configs/${item.id}`, { method: "DELETE" });
      await configs.reload();
    } catch (err) {
      setError(messageOf(err));
    }
  }

  return (
    <div>
      <PageHeader title="环境配置" description="按用户保存的业务配置项，敏感值加密入库" />
      <ErrorAlert message={error ?? configs.error} />

      <Card>
        <CardHeader>
          <CardTitle>配置项</CardTitle>
          <CardDescription>如需修改部署级环境变量，请调整容器 .env 后重启服务</CardDescription>
          <CardAction>
            <Button size="sm" onClick={openCreate}>
              新增配置
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <EmptyHint>还没有配置项</EmptyHint>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>键</TableHead>
                  <TableHead>值</TableHead>
                  <TableHead>说明</TableHead>
                  <TableHead>更新时间</TableHead>
                  {superAdmin ? <TableHead>所属用户</TableHead> : null}
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      <code className="text-xs">{item.key}</code>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="max-w-60 truncate text-xs">{item.value ?? ""}</span>
                        {item.is_secret ? <Badge variant="secondary">加密</Badge> : null}
                      </div>
                    </TableCell>
                    <TableCell>{item.description || "—"}</TableCell>
                    <TableCell>{formatDateTime(item.updated_at)}</TableCell>
                    {superAdmin ? (
                      <TableCell>
                        <span className="text-xs">{item.owner_email}</span>
                      </TableCell>
                    ) : null}
                    <TableCell>
                      <div className="flex gap-1">
                        <Button size="sm" variant="ghost" onClick={() => openEdit(item)}>
                          编辑
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setConfirmId(item)}>
                          删除
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <section className="mt-6 space-y-5 rounded-2xl border bg-muted/30 p-5 text-sm">
        <div>
          <h2 className="font-heading text-base font-medium">配置说明</h2>
          <p className="mt-1 text-muted-foreground">
            本页保存的是用户级配置记录；部署参数只能通过容器环境变量修改。
          </p>
        </div>

        <div>
          <h3 className="font-medium">部署级环境变量</h3>
          <p className="mt-1 text-muted-foreground">
            在容器 <code className="text-xs">.env</code> 中设置，修改后需重启服务，本页面无法修改。
          </p>
          <dl className="mt-2 grid gap-2 sm:grid-cols-2">
            {DEPLOYMENT_VARS.map((item) => (
              <div key={item.name}>
                <dt>
                  <code className="text-xs">{item.name}</code>
                </dt>
                <dd className="text-muted-foreground">{item.purpose}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div>
          <h3 className="font-medium">本页可修改</h3>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-muted-foreground">
            <li>
              <span className="text-foreground">键</span>：用户内唯一，建议使用大写加下划线
            </li>
            <li>
              <span className="text-foreground">值</span>：勾选「作为敏感值加密存储」后以密文入库，列表只显示 ******
            </li>
            <li>
              <span className="text-foreground">说明</span>：备注用途，最长 255 字
            </li>
          </ul>
          <p className="mt-2 text-muted-foreground">
            这些键值目前只做保存，不会覆盖或注入进程环境变量；QQ 凭据与注册开关请到对应页面修改。
          </p>
        </div>

        <div>
          <h3 className="font-medium">其他界面可修改</h3>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-muted-foreground">
            <li>「机器人」：QQ AppID、AppSecret、API 域名、默认 openid / group_openid</li>
            <li>「安全」：注册开关，写入数据库后优先于 REGISTER_ENABLED 环境变量</li>
          </ul>
        </div>
      </section>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editing ? "编辑配置" : "新增配置"}</DialogTitle>
          </DialogHeader>
          <form noValidate onSubmit={save}>
            <FieldGroup className="gap-4">
              <Field data-invalid={Boolean(keyError)}>
                <FieldLabel htmlFor="env-key">键</FieldLabel>
                <Input
                  aria-invalid={Boolean(keyError) || undefined}
                  disabled={editing !== null}
                  id="env-key"
                  placeholder="例如：DEFAULT_GROUP_OPENID"
                  value={key}
                  onChange={(event) => {
                    setKey(event.target.value);
                    if (keyError) setKeyError(null);
                  }}
                />
                <FieldError>{keyError}</FieldError>
              </Field>
              <Field>
                <FieldLabel htmlFor="env-value">值</FieldLabel>
                <Input
                  id="env-value"
                  placeholder={editing?.is_secret ? "留空表示不修改" : ""}
                  value={value}
                  onChange={(event) => setValue(event.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="env-description">说明</FieldLabel>
                <Input
                  id="env-description"
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                />
              </Field>
              <div className="flex items-center gap-2">
                <Switch checked={isSecret} id="env-secret" onCheckedChange={setIsSecret} />
                <Label htmlFor="env-secret">作为敏感值加密存储</Label>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                  取消
                </Button>
                <Button disabled={saving} type="submit">
                  {saving ? "保存中…" : "保存"}
                </Button>
              </div>
            </FieldGroup>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        description={confirmId ? `将删除配置项「${confirmId.key}」。` : ""}
        onConfirm={() => {
          const target = confirmId;
          setConfirmId(null);
          if (target) void remove(target);
        }}
        onOpenChange={(value) => {
          if (!value) setConfirmId(null);
        }}
        open={confirmId !== null}
        title="删除配置项"
      />
    </div>
  );
}
