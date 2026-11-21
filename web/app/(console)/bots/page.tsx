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
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
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
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { ConfirmDialog, CopyButton, EmptyHint, ErrorAlert, PageHeader } from "@/components/ui";
import { api, messageOf } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { isSuperAdmin, useMe } from "@/lib/me";
import {
  PLATFORM_LABELS,
  type BotProfile,
  type Channel,
  type Platform,
} from "@/lib/types";

const PLATFORMS: Platform[] = ["dingtalk", "wecom", "feishu", "github"];

interface BotForm {
  name: string;
  appid: string;
  secret: string;
  host: string;
  openids: string;
  group: string;
  enabled: boolean;
}

const EMPTY_BOT: BotForm = {
  name: "",
  appid: "",
  secret: "",
  host: "https://api.bot.qq.com",
  openids: "",
  group: "",
  enabled: true,
};

export default function BotsPage() {
  const me = useMe();
  const superAdmin = isSuperAdmin(me.role);
  const bots = useApi<BotProfile[]>("/api/admin/bot-profiles");
  const channels = useApi<Channel[]>("/api/admin/channels");

  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [botOpen, setBotOpen] = useState(false);
  const [editingBot, setEditingBot] = useState<BotProfile | null>(null);
  const [botForm, setBotForm] = useState<BotForm>(EMPTY_BOT);
  const [botErrors, setBotErrors] = useState<{ name?: string; appid?: string; secret?: string }>({});

  const [channelOpen, setChannelOpen] = useState(false);
  const [channelPlatform, setChannelPlatform] = useState<Platform>("dingtalk");
  const [channelBotId, setChannelBotId] = useState<string>("");
  const [channelEnabled, setChannelEnabled] = useState(true);
  const [channelSecret, setChannelSecret] = useState("");
  const [channelResult, setChannelResult] = useState<{
    webhookUrl: string;
    secret: string;
    rotated: boolean;
  } | null>(null);

  const [confirm, setConfirm] = useState<{
    title: string;
    description: string;
    action: () => Promise<void>;
  } | null>(null);

  const botList = bots.data ?? [];

  function openCreateBot() {
    setEditingBot(null);
    setBotForm(EMPTY_BOT);
    setBotErrors({});
    setError(null);
    setBotOpen(true);
  }

  function openEditBot(bot: BotProfile) {
    setEditingBot(bot);
    setBotForm({
      name: bot.name,
      appid: bot.qq_appid,
      secret: "",
      host: bot.qq_host,
      openids: bot.default_openids.join("\n"),
      group: bot.default_group_openid ?? "",
      enabled: bot.enabled,
    });
    setBotErrors({});
    setError(null);
    setBotOpen(true);
  }

  async function saveBot(event: React.FormEvent) {
    event.preventDefault();
    const next: { name?: string; appid?: string; secret?: string } = {};
    if (!botForm.name.trim()) next.name = "请填写名称";
    if (!botForm.appid.trim()) next.appid = "请填写 AppID";
    if (!editingBot && !botForm.secret.trim()) next.secret = "请填写 AppSecret";
    setBotErrors(next);
    if (next.name || next.appid || next.secret) return;
    setSaving(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        name: botForm.name.trim(),
        qq_appid: botForm.appid.trim(),
        qq_host: botForm.host.trim() || "https://api.bot.qq.com",
        default_openids: botForm.openids
          .split(/[\s,，]+/)
          .map((item) => item.trim())
          .filter(Boolean),
        default_group_openid: botForm.group.trim() || null,
        enabled: botForm.enabled,
      };
      if (botForm.secret.trim()) body.qq_app_secret = botForm.secret.trim();
      if (editingBot) {
        await api(`/api/admin/bot-profiles/${editingBot.id}`, { method: "PATCH", body });
      } else {
        await api("/api/admin/bot-profiles", { method: "POST", body });
      }
      setBotOpen(false);
      await bots.reload();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setSaving(false);
    }
  }

  async function toggleBot(bot: BotProfile) {
    try {
      await api(`/api/admin/bot-profiles/${bot.id}`, {
        method: "PATCH",
        body: { enabled: !bot.enabled },
      });
      await bots.reload();
    } catch (err) {
      setError(messageOf(err));
    }
  }

  async function createChannel(event: React.FormEvent) {
    event.preventDefault();
    if (!channelBotId) {
      setError("请选择机器人");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const result = await api<{ webhook_url?: string; secret?: string }>(
        "/api/admin/channels",
        {
          method: "POST",
          body: {
            platform: channelPlatform,
            bot_profile_id: Number(channelBotId),
            enabled: channelEnabled,
            ...(channelPlatform === "github" && channelSecret.trim()
              ? { secret: channelSecret.trim() }
              : {}),
          },
        },
      );
      setChannelOpen(false);
      setChannelSecret("");
      await channels.reload();
      if (result.webhook_url && result.secret) {
        setChannelResult({
          webhookUrl: result.webhook_url,
          secret: result.secret,
          rotated: false,
        });
      }
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setSaving(false);
    }
  }

  async function toggleChannel(channel: Channel) {
    try {
      await api(`/api/admin/channels/${channel.id}`, {
        method: "PATCH",
        body: { enabled: !channel.enabled },
      });
      await channels.reload();
    } catch (err) {
      setError(messageOf(err));
    }
  }

  async function rotateChannel(channel: Channel) {
    setError(null);
    try {
      const result = await api<{ webhook_url?: string; secret?: string }>(
        `/api/admin/channels/${channel.id}/rotate`,
        { method: "POST" },
      );
      await channels.reload();
      if (result.webhook_url && result.secret) {
        setChannelResult({
          webhookUrl: result.webhook_url,
          secret: result.secret,
          rotated: true,
        });
      }
    } catch (err) {
      setError(messageOf(err));
    }
  }

  function botName(id: number): string {
    return botList.find((item) => item.id === id)?.name ?? `#${id}`;
  }

  const platformItems = PLATFORMS.map((platform) => ({
    label: PLATFORM_LABELS[platform],
    value: platform,
  }));
  const botItems = botList.map((bot) => ({ label: bot.name, value: String(bot.id) }));

  return (
    <div>
      <PageHeader title="机器人" description="配置 QQ 机器人凭据与对外 Webhook 通道" />
      <ErrorAlert message={error ?? bots.error ?? channels.error} />

      <div className="flex flex-col gap-6">
        <Card>
          <CardHeader>
            <CardTitle>机器人配置</CardTitle>
            <CardDescription>每个用户可维护多套 QQ 机器人凭据</CardDescription>
            <CardAction>
              <Button size="sm" onClick={openCreateBot}>
                新增机器人
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {botList.length === 0 ? (
              <EmptyHint>还没有机器人配置</EmptyHint>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>名称</TableHead>
                    <TableHead>AppID</TableHead>
                    <TableHead>AppSecret</TableHead>
                    <TableHead>API 域名</TableHead>
                    <TableHead>默认接收方</TableHead>
                    <TableHead>状态</TableHead>
                    {superAdmin ? <TableHead>所属用户</TableHead> : null}
                    <TableHead>操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {botList.map((bot) => (
                    <TableRow key={bot.id}>
                      <TableCell>{bot.name}</TableCell>
                      <TableCell>
                        <span className="block max-w-32 truncate text-xs">{bot.qq_appid}</span>
                      </TableCell>
                      <TableCell>
                        <span className="block max-w-32 truncate text-xs">
                          {bot.has_secret ? bot.qq_app_secret_masked : "未设置"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="block max-w-44 truncate text-xs">{bot.qq_host}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs">
                          {bot.default_group_openid
                            ? `群 ${bot.default_group_openid}`
                            : bot.default_openids.length > 0
                              ? `${bot.default_openids.length} 个用户`
                              : "未设置"}
                        </span>
                      </TableCell>
                      <TableCell>
                        {bot.enabled ? (
                          <Badge className="bg-emerald-600/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400">
                            启用
                          </Badge>
                        ) : (
                          <Badge variant="outline">停用</Badge>
                        )}
                      </TableCell>
                      {superAdmin ? (
                        <TableCell>
                          <span className="text-xs">{bot.owner_email}</span>
                        </TableCell>
                      ) : null}
                      <TableCell>
                        <div className="flex gap-1">
                          <Button size="sm" variant="ghost" onClick={() => openEditBot(bot)}>
                            编辑
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => void toggleBot(bot)}>
                            {bot.enabled ? "停用" : "启用"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              setConfirm({
                                title: "删除机器人",
                                description: `将同时删除「${bot.name}」关联的所有通道，操作不可恢复。`,
                                action: async () => {
                                  await api(`/api/admin/bot-profiles/${bot.id}`, {
                                    method: "DELETE",
                                  });
                                  await Promise.all([bots.reload(), channels.reload()]);
                                },
                              })
                            }
                          >
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

        <Card>
          <CardHeader>
            <CardTitle>Webhook 通道</CardTitle>
            <CardDescription>
              按平台接入：钉钉 /webhook/dingtalk、企业微信 /webhook/wecom、飞书
              /webhook/feishu；GitHub 使用 /webhook/github/{"{token}"}，token 已包含在 Payload URL
              中，并需在 GitHub 侧配置 Secret
            </CardDescription>
            <CardAction>
              <Button
                disabled={botList.length === 0}
                size="sm"
                onClick={() => {
                  setChannelPlatform("dingtalk");
                  setChannelBotId(botList[0] ? String(botList[0].id) : "");
                  setChannelEnabled(true);
                  setChannelSecret("");
                  setError(null);
                  setChannelOpen(true);
                }}
              >
                新增通道
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {(channels.data ?? []).length === 0 ? (
              <EmptyHint>还没有接入通道</EmptyHint>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>平台</TableHead>
                    <TableHead>机器人</TableHead>
                    <TableHead>Token</TableHead>
                    <TableHead>Webhook 地址</TableHead>
                    <TableHead>状态</TableHead>
                    {superAdmin ? <TableHead>所属用户</TableHead> : null}
                    <TableHead>操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(channels.data ?? []).map((channel) => (
                    <TableRow key={channel.id}>
                      <TableCell>{PLATFORM_LABELS[channel.platform]}</TableCell>
                      <TableCell>{botName(channel.bot_profile_id)}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <span className="block max-w-32 truncate text-xs">
                            {channel.webhook_token}
                          </span>
                          <CopyButton value={channel.webhook_token} />
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <span
                            className="min-w-0 max-w-56 truncate text-xs"
                            title={channel.webhook_url}
                          >
                            {channel.webhook_url}
                          </span>
                          <CopyButton value={channel.webhook_url} />
                        </div>
                      </TableCell>
                      <TableCell>
                        {channel.enabled ? (
                          <Badge className="bg-emerald-600/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400">
                            启用
                          </Badge>
                        ) : (
                          <Badge variant="outline">停用</Badge>
                        )}
                      </TableCell>
                      {superAdmin ? (
                        <TableCell>
                          <span className="text-xs">{channel.owner_email}</span>
                        </TableCell>
                      ) : null}
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void rotateChannel(channel)}
                          >
                            轮换
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void toggleChannel(channel)}
                          >
                            {channel.enabled ? "停用" : "启用"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              setConfirm({
                                title: "删除通道",
                                description: "删除后该平台的推送会立即失败。",
                                action: async () => {
                                  await api(`/api/admin/channels/${channel.id}`, {
                                    method: "DELETE",
                                  });
                                  await channels.reload();
                                },
                              })
                            }
                          >
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
      </div>

      <Dialog open={botOpen} onOpenChange={setBotOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{editingBot ? "编辑机器人" : "新增机器人"}</DialogTitle>
          </DialogHeader>
          <form noValidate onSubmit={saveBot}>
            <FieldGroup className="gap-4">
              <Field data-invalid={Boolean(botErrors.name)}>
                <FieldLabel htmlFor="bot-name">名称</FieldLabel>
                <Input
                  aria-invalid={Boolean(botErrors.name) || undefined}
                  id="bot-name"
                  placeholder="例如：生产机器人"
                  value={botForm.name}
                  onChange={(event) => {
                    setBotForm((prev) => ({ ...prev, name: event.target.value }));
                    if (botErrors.name) setBotErrors((prev) => ({ ...prev, name: undefined }));
                  }}
                />
                <FieldError>{botErrors.name}</FieldError>
              </Field>
              <Field data-invalid={Boolean(botErrors.appid)}>
                <FieldLabel htmlFor="bot-appid">AppID</FieldLabel>
                <Input
                  aria-invalid={Boolean(botErrors.appid) || undefined}
                  id="bot-appid"
                  value={botForm.appid}
                  onChange={(event) => {
                    setBotForm((prev) => ({ ...prev, appid: event.target.value }));
                    if (botErrors.appid) setBotErrors((prev) => ({ ...prev, appid: undefined }));
                  }}
                />
                <FieldError>{botErrors.appid}</FieldError>
              </Field>
              <Field data-invalid={Boolean(botErrors.secret)}>
                <FieldLabel htmlFor="bot-secret">AppSecret</FieldLabel>
                <Input
                  aria-invalid={Boolean(botErrors.secret) || undefined}
                  autoComplete="new-password"
                  id="bot-secret"
                  type="password"
                  placeholder={editingBot?.has_secret ? "留空表示不修改" : "QQ 机器人 AppSecret"}
                  value={botForm.secret}
                  onChange={(event) => {
                    setBotForm((prev) => ({ ...prev, secret: event.target.value }));
                    if (botErrors.secret) setBotErrors((prev) => ({ ...prev, secret: undefined }));
                  }}
                />
                <FieldDescription>密钥加密后入库，页面只显示掩码。</FieldDescription>
                <FieldError>{botErrors.secret}</FieldError>
              </Field>
              <Field>
                <FieldLabel htmlFor="bot-host">API 域名</FieldLabel>
                <Input
                  id="bot-host"
                  value={botForm.host}
                  onChange={(event) =>
                    setBotForm((prev) => ({ ...prev, host: event.target.value }))
                  }
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="bot-openids">默认用户 openid</FieldLabel>
                <Textarea
                  id="bot-openids"
                  placeholder="每行一个；推送请求未带 openid 时使用"
                  rows={2}
                  value={botForm.openids}
                  onChange={(event) =>
                    setBotForm((prev) => ({ ...prev, openids: event.target.value }))
                  }
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="bot-group">默认群 group_openid</FieldLabel>
                <Input
                  id="bot-group"
                  placeholder="可选；优先级高于默认用户"
                  value={botForm.group}
                  onChange={(event) =>
                    setBotForm((prev) => ({ ...prev, group: event.target.value }))
                  }
                />
              </Field>
              <div className="flex items-center gap-2">
                <Switch
                  checked={botForm.enabled}
                  id="bot-enabled"
                  onCheckedChange={(value) =>
                    setBotForm((prev) => ({ ...prev, enabled: value }))
                  }
                />
                <Label htmlFor="bot-enabled">启用该机器人</Label>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setBotOpen(false)}>
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

      <Dialog open={channelOpen} onOpenChange={setChannelOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>新增 Webhook 通道</DialogTitle>
          </DialogHeader>
          <form onSubmit={createChannel}>
            <FieldGroup className="gap-4">
              <div className="flex flex-col gap-2">
                <Label>来源平台</Label>
                <Select
                  items={platformItems}
                  value={channelPlatform}
                  onValueChange={(value) => setChannelPlatform(String(value) as Platform)}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent alignItemWithTrigger={false}>
                    <SelectGroup>
                      {platformItems.map((item) => (
                        <SelectItem key={item.value} value={item.value}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-2">
                <Label>推送目标机器人</Label>
                <Select
                  items={botItems}
                  value={channelBotId}
                  onValueChange={(value) => setChannelBotId(String(value))}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="选择机器人" />
                  </SelectTrigger>
                  <SelectContent alignItemWithTrigger={false}>
                    <SelectGroup>
                      {botItems.map((item) => (
                        <SelectItem key={item.value} value={item.value}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
              {channelPlatform === "github" ? (
                <Field>
                  <FieldLabel htmlFor="channel-secret">签名密钥 Secret</FieldLabel>
                  <Input
                    autoComplete="new-password"
                    id="channel-secret"
                    type="password"
                    placeholder="留空时自动生成"
                    value={channelSecret}
                    onChange={(event) => setChannelSecret(event.target.value)}
                  />
                  <FieldDescription>
                    GitHub 的 Webhook 设置里没有 token 输入框，token 会包含在创建后生成的
                    Payload URL 中；这里填写或自动生成的密钥用来对应 GitHub 的 Secret，用于校验
                    X-Hub-Signature-256。
                  </FieldDescription>
                </Field>
              ) : null}
              <div className="flex items-center gap-2">
                <Switch
                  checked={channelEnabled}
                  id="channel-enabled"
                  onCheckedChange={setChannelEnabled}
                />
                <Label htmlFor="channel-enabled">创建后立即启用</Label>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setChannelOpen(false)}>
                  取消
                </Button>
                <Button disabled={saving} type="submit">
                  {saving ? "创建中…" : "创建"}
                </Button>
              </div>
            </FieldGroup>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={channelResult !== null}
        onOpenChange={(open) => {
          if (!open) setChannelResult(null);
        }}
      >
        <DialogContent className="grid-cols-[minmax(0,1fr)] sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {channelResult?.rotated ? "GitHub 通道已轮换" : "GitHub 通道已创建"}
            </DialogTitle>
          </DialogHeader>
          <div className="flex min-w-0 flex-col gap-4 text-sm">
            <p className="text-muted-foreground">
              请在 GitHub 仓库 Settings → Webhooks → Add webhook 中填写以下两项，Content type
              选择 application/json，SSL verification 保持启用，再选择要订阅的事件。
            </p>
            <Field className="min-w-0 gap-1.5">
              <FieldLabel>Payload URL（token 已包含在地址中）</FieldLabel>
              <div className="flex min-w-0 items-center gap-2">
                <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded bg-muted px-2 py-1 font-mono text-xs">
                  {channelResult?.webhookUrl}
                </code>
                <CopyButton value={channelResult?.webhookUrl ?? ""} />
              </div>
            </Field>
            <Field className="min-w-0 gap-1.5">
              <FieldLabel>Secret</FieldLabel>
              <div className="flex min-w-0 items-center gap-2">
                <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded bg-muted px-2 py-1 font-mono text-xs">
                  {channelResult?.secret}
                </code>
                <CopyButton value={channelResult?.secret ?? ""} />
              </div>
            </Field>
            <FieldDescription>
              密钥只显示这一次，关闭后无法再次查看；如需更换请使用通道列表中的「轮换」。
            </FieldDescription>
            <div className="flex justify-end">
              <Button onClick={() => setChannelResult(null)}>知道了</Button>
            </div>
          </div>
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
