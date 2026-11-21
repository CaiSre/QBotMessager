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
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import {
  ConfirmDialog,
  CopyButton,
  EmptyHint,
  ErrorAlert,
  PageHeader,
  SuccessAlert,
} from "@/components/ui";
import { api, messageOf } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { isSuperAdmin, useMe } from "@/lib/me";
import { ROLE_LABELS, type Invite, type Role, type UserRow } from "@/lib/types";

const ROLE_OPTIONS: { id: Role; label: string }[] = [
  { id: "user", label: ROLE_LABELS.user },
  { id: "super_admin", label: ROLE_LABELS.super_admin },
];

const STATUS_OPTIONS = [
  { id: "active", label: "正常" },
  { id: "disabled", label: "停用" },
];

function SelectField({
  label,
  value,
  options,
  onChange,
  disabled = false,
}: {
  label: string;
  value: string;
  options: { id: string; label: string }[];
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const items = options.map((option) => ({ label: option.label, value: option.id }));
  return (
    <div className="flex flex-col gap-2">
      <Label>{label}</Label>
      <Select
        disabled={disabled}
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

export default function UsersPage() {
  const me = useMe();
  const superAdmin = isSuperAdmin(me.role);
  const users = useApi<UserRow[]>(superAdmin ? "/api/admin/users" : null);
  const invites = useApi<Invite[]>(superAdmin ? "/api/admin/invites" : null);

  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [editing, setEditing] = useState<UserRow | null>(null);
  const [editName, setEditName] = useState("");
  const [editRole, setEditRole] = useState<Role>("user");
  const [editStatus, setEditStatus] = useState("active");

  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteUses, setInviteUses] = useState("1");
  const [inviteDays, setInviteDays] = useState("7");

  const [confirm, setConfirm] = useState<{
    title: string;
    description: string;
    action: () => Promise<void>;
  } | null>(null);

  const userList = users.data ?? [];
  const inviteList = invites.data ?? [];

  function openEdit(user: UserRow) {
    setEditing(user);
    setEditName(user.name);
    setEditRole(user.role);
    setEditStatus(user.status);
    setError(null);
  }

  async function saveUser(event: React.FormEvent) {
    event.preventDefault();
    if (!editing) return;
    setSaving(true);
    setError(null);
    try {
      await api(`/api/admin/users/${editing.id}`, {
        method: "PATCH",
        body: { name: editName.trim(), role: editRole, status: editStatus },
      });
      setEditing(null);
      await users.reload();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setSaving(false);
    }
  }

  async function createInvite(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const result = await api<{ code: string }>("/api/admin/invites", {
        method: "POST",
        body: {
          email: inviteEmail.trim() || null,
          max_uses: Number(inviteUses) || 1,
          expires_in_days: Number(inviteDays) || 7,
        },
      });
      setInviteOpen(false);
      setNotice(`邀请码已生成：${result.code}`);
      await invites.reload();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setSaving(false);
    }
  }

  if (!superAdmin) {
    return (
      <div>
        <PageHeader title="用户管理" description="管理用户账号与邀请码" />
        <EmptyHint>仅超级管理员可访问。</EmptyHint>
      </div>
    );
  }

  return (
    <div>
      <PageHeader title="用户管理" description="管理用户账号与邀请码" />
      <ErrorAlert message={error ?? users.error ?? invites.error} />
      <SuccessAlert message={notice} />

      <div className="flex flex-col gap-6">
        <Card>
          <CardHeader>
            <CardTitle>用户</CardTitle>
            <CardDescription>超级管理员可调整角色与账号状态</CardDescription>
          </CardHeader>
          <CardContent>
            {userList.length === 0 ? (
              <EmptyHint>暂无用户</EmptyHint>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>用户</TableHead>
                    <TableHead>角色</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>最近登录</TableHead>
                    <TableHead>操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {userList.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <div>
                          <p className="text-sm font-medium">
                            {user.name || user.email.split("@")[0]}
                            {user.id === me.id ? (
                              <span className="ml-2 text-xs text-muted-foreground">（我）</span>
                            ) : null}
                          </p>
                          <p className="text-xs text-muted-foreground">{user.email}</p>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={user.role === "super_admin" ? "default" : "secondary"}>
                          {ROLE_LABELS[user.role]}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {user.status === "active" ? (
                          <Badge className="bg-emerald-600/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400">
                            正常
                          </Badge>
                        ) : (
                          <Badge variant="outline">停用</Badge>
                        )}
                      </TableCell>
                      <TableCell>{formatDateTime(user.last_login_at)}</TableCell>
                      <TableCell>
                        <Button size="sm" variant="ghost" onClick={() => openEdit(user)}>
                          编辑
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>邀请码</CardTitle>
            <CardDescription>
              注册入口需在「安全设置」中开启后，受邀人才能注册
            </CardDescription>
            <CardAction>
              <Button
                size="sm"
                onClick={() => {
                  setInviteEmail("");
                  setInviteUses("1");
                  setInviteDays("7");
                  setError(null);
                  setInviteOpen(true);
                }}
              >
                生成邀请码
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {inviteList.length === 0 ? (
              <EmptyHint>还没有邀请码</EmptyHint>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>邀请码</TableHead>
                    <TableHead>限定邮箱</TableHead>
                    <TableHead>使用情况</TableHead>
                    <TableHead>过期时间</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {inviteList.map((invite) => {
                    const expired =
                      invite.expires_at !== null && new Date(invite.expires_at) < new Date();
                    const exhausted = invite.used_count >= invite.max_uses;
                    const disabled = invite.revoked || expired || exhausted;
                    return (
                      <TableRow key={invite.id}>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <code className="text-xs">{invite.code}</code>
                            <CopyButton value={invite.code} />
                          </div>
                        </TableCell>
                        <TableCell>{invite.email ?? "不限"}</TableCell>
                        <TableCell>
                          {invite.used_count} / {invite.max_uses}
                        </TableCell>
                        <TableCell>{formatDateTime(invite.expires_at)}</TableCell>
                        <TableCell>
                          <Badge variant={disabled ? "outline" : "default"}>
                            {invite.revoked
                              ? "已作废"
                              : expired
                                ? "已过期"
                                : exhausted
                                  ? "已用尽"
                                  : "可用"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {invite.revoked ? null : (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() =>
                                setConfirm({
                                  title: "作废邀请码",
                                  description: "作废后该邀请码无法再用于注册。",
                                  action: async () => {
                                    await api(`/api/admin/invites/${invite.id}`, {
                                      method: "DELETE",
                                    });
                                    await invites.reload();
                                  },
                                })
                              }
                            >
                              作废
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={editing !== null} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>编辑用户</DialogTitle>
          </DialogHeader>
          <form onSubmit={saveUser}>
            <FieldGroup className="gap-4">
              <p className="text-sm font-medium">{editing?.email}</p>
              <Field>
                <FieldLabel htmlFor="user-name">用户名</FieldLabel>
                <Input
                  id="user-name"
                  value={editName}
                  onChange={(event) => setEditName(event.target.value)}
                />
              </Field>
              <SelectField
                disabled={editing?.id === me.id}
                label="角色"
                options={ROLE_OPTIONS}
                value={editRole}
                onChange={(value) => setEditRole(value as Role)}
              />
              <SelectField
                disabled={editing?.id === me.id}
                label="账号状态"
                options={STATUS_OPTIONS}
                value={editStatus}
                onChange={(value) => setEditStatus(value)}
              />
              {editing && editing.id === me.id ? (
                <p className="text-xs text-muted-foreground">不能修改自己的角色与账号状态。</p>
              ) : null}
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setEditing(null)}>
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

      <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>生成邀请码</DialogTitle>
          </DialogHeader>
          <form onSubmit={createInvite}>
            <FieldGroup className="gap-4">
              <p className="text-sm text-muted-foreground">受邀人注册后角色为普通用户。</p>
              <Field>
                <FieldLabel htmlFor="invite-email">限定邮箱</FieldLabel>
                <Input
                  id="invite-email"
                  placeholder="留空表示不限邮箱"
                  type="email"
                  value={inviteEmail}
                  onChange={(event) => setInviteEmail(event.target.value)}
                />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field>
                  <FieldLabel htmlFor="invite-uses">可用次数</FieldLabel>
                  <Input
                    id="invite-uses"
                    min="1"
                    type="number"
                    value={inviteUses}
                    onChange={(event) => setInviteUses(event.target.value)}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="invite-days">有效天数</FieldLabel>
                  <Input
                    id="invite-days"
                    min="1"
                    type="number"
                    value={inviteDays}
                    onChange={(event) => setInviteDays(event.target.value)}
                  />
                </Field>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setInviteOpen(false)}>
                  取消
                </Button>
                <Button disabled={saving} type="submit">
                  {saving ? "生成中…" : "生成"}
                </Button>
              </div>
            </FieldGroup>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        description={confirm?.description ?? ""}
        onConfirm={async () => {
          if (!confirm) return;
          const action = confirm.action;
          setConfirm(null);
          setError(null);
          try {
            await action();
          } catch (err) {
            setError(messageOf(err));
          }
        }}
        onOpenChange={(open) => {
          if (!open) setConfirm(null);
        }}
        open={confirm !== null}
        title={confirm?.title ?? ""}
      />
    </div>
  );
}
