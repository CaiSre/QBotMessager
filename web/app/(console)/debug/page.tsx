"use client";

import { useEffect, useRef, useState } from "react";
import { SendIcon } from "lucide-react";

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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { CopyButton, EmptyHint, ErrorAlert, PageHeader } from "@/components/ui";
import { messageOf } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { HOOK_TYPE_LABELS, type Channel, type HookType } from "@/lib/types";

interface MsgTypeDef {
  value: string;
  label: string;
  showTitle?: boolean;
  showUrl?: boolean;
  showContent?: boolean;
  showAtAll?: boolean;
  contentLabel?: string;
  contentPlaceholder?: string;
  urlLabel?: string;
}

const MSG_TYPES: Record<HookType, MsgTypeDef[]> = {
  dingtalk: [
    { value: "text", label: "文本 text", showAtAll: true },
    { value: "markdown", label: "Markdown", showTitle: true, showAtAll: true },
    { value: "link", label: "链接 link", showTitle: true, showUrl: true, urlLabel: "跳转链接" },
    {
      value: "actionCard",
      label: "卡片 actionCard",
      showTitle: true,
      showUrl: true,
      urlLabel: "按钮链接",
    },
    {
      value: "feedCard",
      label: "多卡 feedCard",
      showTitle: true,
      showUrl: true,
      showContent: false,
      urlLabel: "卡片链接",
    },
  ],
  wecom: [
    { value: "text", label: "文本 text", showAtAll: true },
    { value: "markdown", label: "Markdown" },
    { value: "markdown_v2", label: "Markdown v2" },
    {
      value: "news",
      label: "图文 news",
      showTitle: true,
      showUrl: true,
      urlLabel: "文章链接",
      contentLabel: "文章描述",
    },
  ],
  feishu: [
    { value: "text", label: "文本 text", showAtAll: true },
    {
      value: "post",
      label: "富文本 post",
      showTitle: true,
      contentLabel: "正文（按行分段）",
    },
  ],
  // GitHub 事件需要真实事件结构并通过 X-Hub-Signature-256 校验，不在调试页构造
  github: [],
};

const HOOK_TYPES: HookType[] = ["dingtalk", "wecom", "feishu"];

// GitHub 不参与调试页，其消息类型列表为空；兜底常量保证取默认类型时不会越界。
const FALLBACK_MSG_TYPE: MsgTypeDef = { value: "text", label: "文本 text" };

/** 取该钩子类型的默认消息类型（各列表的首项）。 */
function defaultMsgType(hookType: HookType): MsgTypeDef {
  return MSG_TYPES[hookType].at(0) ?? FALLBACK_MSG_TYPE;
}

const TARGET_OPTIONS = [
  { value: "default", label: "机器人默认目标" },
  { value: "group", label: "指定群 group_openid" },
  { value: "openid", label: "指定用户 openid" },
];

type TargetKind = "default" | "group" | "openid";

interface PushResult {
  status: number;
  ok: boolean;
  durationMs: number;
  body: string;
}

function prettyBody(text: string): string {
  if (!text.trim()) return "(空响应体)";
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function buildPayload(form: {
  hookType: HookType;
  msgType: string;
  title: string;
  content: string;
  url: string;
  atAll: boolean;
}): Record<string, unknown> {
  const title = form.title.trim();
  const content = form.content.trim();
  const url = form.url.trim();
  const at = form.atAll ? { at: { isAtAll: true } } : {};
  const key = `${form.hookType}:${form.msgType}`;

  switch (key) {
    case "dingtalk:text":
      return { msgtype: "text", text: { content }, ...at };
    case "dingtalk:markdown":
      return { msgtype: "markdown", markdown: { title, text: content }, ...at };
    case "dingtalk:link":
      return { msgtype: "link", link: { title, text: content, messageUrl: url } };
    case "dingtalk:actionCard":
      return {
        msgtype: "actionCard",
        actionCard: { title, text: content, singleTitle: "查看详情", singleURL: url },
      };
    case "dingtalk:feedCard":
      return { msgtype: "feedCard", feedCard: { links: [{ title, messageURL: url }] } };
    case "wecom:text":
      return {
        msgtype: "text",
        text: { content, ...(form.atAll ? { mentioned_list: ["@all"] } : {}) },
      };
    case "wecom:markdown":
      return { msgtype: "markdown", markdown: { content } };
    case "wecom:markdown_v2":
      return { msgtype: "markdown_v2", markdown_v2: { content } };
    case "wecom:news":
      return { msgtype: "news", news: { articles: [{ title, description: content, url }] } };
    case "feishu:text":
      return {
        msg_type: "text",
        content: { text: form.atAll ? `${content} <at user_id="all">所有人</at>` : content },
      };
    case "feishu:post": {
      const lines = content.split(/\r?\n/).filter((line) => line.trim());
      return {
        msg_type: "post",
        content: {
          post: { zh_cn: { title, content: lines.map((line) => [{ tag: "text", text: line }]) } },
        },
      };
    }
    default:
      return {};
  }
}

export default function DebugPage() {
  const channels = useApi<Channel[]>("/api/admin/channels");
  const channelList = channels.data ?? [];

  const [hookType, setHookType] = useState<HookType>("dingtalk");
  const [channelId, setChannelId] = useState("");
  const [token, setToken] = useState("");
  const [msgType, setMsgType] = useState("text");
  const [title, setTitle] = useState("QBotMessager 调试消息");
  const [content, setContent] = useState("这是一条来自 QBotMessager 的调试消息。");
  const [url, setUrl] = useState("https://example.com");
  const [atAll, setAtAll] = useState(false);
  const [targetKind, setTargetKind] = useState<TargetKind>("default");
  const [targetValue, setTargetValue] = useState("");

  const [origin, setOrigin] = useState("");
  const [codeTab, setCodeTab] = useState("curl");

  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PushResult | null>(null);

  const initialized = useRef(false);

  useEffect(() => {
    setOrigin(window.location.origin);
  }, []);

  useEffect(() => {
    if (initialized.current) return;
    const first =
      channelList.find((item) => HOOK_TYPES.includes(item.hook_type) && item.enabled) ??
      channelList.find((item) => HOOK_TYPES.includes(item.hook_type));
    if (!first) return;
    initialized.current = true;
    setHookType(first.hook_type);
    setChannelId(String(first.id));
    setMsgType(defaultMsgType(first.hook_type).value);
  }, [channelList]);

  const hookTypeChannels = channelList.filter((item) => item.hook_type === hookType);
  const typeDef =
    MSG_TYPES[hookType].find((item) => item.value === msgType) ?? defaultMsgType(hookType);

  function changeHookType(next: HookType) {
    setHookType(next);
    if (!MSG_TYPES[next].some((item) => item.value === msgType)) {
      setMsgType(defaultMsgType(next).value);
    }
    setChannelId("");
    setResult(null);
    setError(null);
  }

  function changeChannel(next: string) {
    setChannelId(next);
    const channel = channelList.find((item) => String(item.id) === next);
    if (!channel) return;
    setHookType(channel.hook_type);
    if (!MSG_TYPES[channel.hook_type].some((item) => item.value === msgType)) {
      setMsgType(defaultMsgType(channel.hook_type).value);
    }
    setResult(null);
    setError(null);
  }

  const payload = buildPayload({ hookType, msgType, title, content, url, atAll });
  if (targetKind === "group" && targetValue.trim()) {
    payload.group_openid = targetValue.trim();
  }
  if (targetKind === "openid" && targetValue.trim()) {
    payload.openid = targetValue.trim();
  }

  const endpoint = `${origin}/webhook/${hookType}`;
  const tokenText = token.trim() || "<YOUR_TOKEN>";
  const payloadJson = JSON.stringify(payload, null, 2);

  const curlCode = [
    `curl -X POST '${endpoint}' \\`,
    `  -H 'Authorization: Bearer ${tokenText}' \\`,
    `  -H 'Content-Type: application/json' \\`,
    `  -d '${payloadJson.replace(/'/g, "'\\''")}'`,
  ].join("\n");

  const powershellCode = [
    `$headers = @{ Authorization = "Bearer ${tokenText}" }`,
    `$body = @'`,
    payloadJson,
    `'@`,
    `Invoke-RestMethod -Method Post -Uri "${endpoint}" \``,
    `  -Headers $headers -ContentType "application/json; charset=utf-8" \``,
    `  -Body ([System.Text.Encoding]::UTF8.GetBytes($body))`,
  ].join("\n");

  const pythonCode = [
    "import json",
    "import requests",
    "",
    `url = "${endpoint}"`,
    `headers = {"Authorization": "Bearer ${tokenText}"}`,
    `payload = json.loads(r'''`,
    payloadJson,
    `''')`,
    "",
    'resp = requests.post(url, headers=headers, json=payload)',
    "print(resp.status_code, resp.text)",
  ].join("\n");

  const codeSamples: Record<string, string> = {
    curl: curlCode,
    powershell: powershellCode,
    python: pythonCode,
  };

  function validate(): string | null {
    if (!token.trim()) return "请选择通道或填写 Webhook Token";
    if (typeDef.showContent !== false && !content.trim()) return "请填写消息内容";
    if (hookType === "dingtalk" && msgType === "feedCard") {
      if (!title.trim()) return "feedCard 需要填写标题";
      if (!url.trim()) return "feedCard 需要填写链接";
    }
    if (targetKind !== "default" && !targetValue.trim()) {
      return `请填写${targetKind === "group" ? " group_openid" : " openid"}`;
    }
    return null;
  }

  async function sendPush() {
    const invalid = validate();
    setError(invalid);
    if (invalid) return;

    setSending(true);
    setResult(null);
    const started = performance.now();
    try {
      const response = await fetch(`/webhook/${hookType}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token.trim()}`,
          "X-QBot-Debug": "1",
        },
        body: JSON.stringify(payload),
      });
      const text = await response.text();
      setResult({
        status: response.status,
        ok: response.ok,
        durationMs: performance.now() - started,
        body: prettyBody(text),
      });
    } catch (err) {
      setResult({
        status: 0,
        ok: false,
        durationMs: performance.now() - started,
        body: messageOf(err),
      });
    } finally {
      setSending(false);
    }
  }

  const hookTypeItems = HOOK_TYPES.map((item) => ({
    label: HOOK_TYPE_LABELS[item],
    value: item,
  }));
  const typeItems = MSG_TYPES[hookType].map((item) => ({ label: item.label, value: item.value }));
  const channelItems = hookTypeChannels.map((item) => ({
    label: `${HOOK_TYPE_LABELS[item.hook_type]} #${item.id}${item.enabled ? "" : "（停用）"}`,
    value: String(item.id),
  }));
  const targetItems = TARGET_OPTIONS.map((item) => ({ label: item.label, value: item.value }));

  return (
    <div>
      <PageHeader
        title="推送调试"
        description="按钩子类型填写参数，右侧实时生成推送代码，并可直接向 QQ 试发一条消息"
      />
      <ErrorAlert message={error ?? channels.error} />

      <div className="grid gap-6 lg:grid-cols-2">
        {/* 左侧：参数表单 */}
        <Card className="self-start">
          <CardHeader>
            <CardTitle>推送参数</CardTitle>
            <CardDescription>调试请求会真实推送到所选机器人的 QQ 目标</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col gap-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="flex flex-col gap-2">
                  <Label>钩子类型</Label>
                  <Select
                    items={hookTypeItems}
                    value={hookType}
                    onValueChange={(value) => changeHookType(String(value) as HookType)}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent alignItemWithTrigger={false}>
                      <SelectGroup>
                        {hookTypeItems.map((item) => (
                          <SelectItem key={item.value} value={item.value}>
                            {item.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex flex-col gap-2">
                  <Label>消息类型</Label>
                  <Select
                    items={typeItems}
                    value={msgType}
                    onValueChange={(value) => {
                      setMsgType(String(value));
                      setResult(null);
                    }}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent alignItemWithTrigger={false}>
                      <SelectGroup>
                        {typeItems.map((item) => (
                          <SelectItem key={item.value} value={item.value}>
                            {item.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="flex flex-col gap-2">
                <Label>Webhook 通道</Label>
                <Select
                  items={channelItems}
                  value={channelId}
                  onValueChange={(value) => changeChannel(String(value))}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="选择通道以自动填入 Token" />
                  </SelectTrigger>
                  <SelectContent alignItemWithTrigger={false}>
                    <SelectGroup>
                      {channelItems.map((item) => (
                        <SelectItem key={item.value} value={item.value}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  当前钩子类型还没有通道？先到「机器人」页面新增。
                </p>
              </div>

              <div className="flex flex-col gap-2">
                <Label htmlFor="debug-token">Webhook Token</Label>
                <Input
                  id="debug-token"
                  placeholder="粘贴通道令牌"
                  value={token}
                  onChange={(event) => {
                    setToken(event.target.value);
                    setResult(null);
                  }}
                />
                <p className="text-xs text-muted-foreground">
                  令牌只在创建/轮换通道时展示一次，请从当时的窗口复制到这里。
                </p>
              </div>

              {typeDef.showTitle ? (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="debug-title">标题</Label>
                  <Input
                    id="debug-title"
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                  />
                </div>
              ) : null}

              {typeDef.showContent !== false ? (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="debug-content">{typeDef.contentLabel ?? "消息内容"}</Label>
                  <Textarea
                    id="debug-content"
                    rows={6}
                    placeholder={typeDef.contentPlaceholder}
                    value={content}
                    onChange={(event) => setContent(event.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    支持 Markdown；实际渲染取决于钩子适配器与 QQ 消息限制。
                  </p>
                </div>
              ) : null}

              {typeDef.showUrl ? (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="debug-url">{typeDef.urlLabel ?? "链接"}</Label>
                  <Input
                    id="debug-url"
                    value={url}
                    onChange={(event) => setUrl(event.target.value)}
                  />
                </div>
              ) : null}

              {typeDef.showAtAll ? (
                <div className="flex items-center gap-2">
                  <Switch
                    checked={atAll}
                    id="debug-at-all"
                    onCheckedChange={(value) => {
                      setAtAll(value);
                      setResult(null);
                    }}
                  />
                  <Label htmlFor="debug-at-all">@ 所有人</Label>
                </div>
              ) : null}

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="flex flex-col gap-2">
                  <Label>推送目标</Label>
                  <Select
                    items={targetItems}
                    value={targetKind}
                    onValueChange={(value) => {
                      setTargetKind(String(value) as TargetKind);
                      setTargetValue("");
                      setResult(null);
                    }}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent alignItemWithTrigger={false}>
                      <SelectGroup>
                        {targetItems.map((item) => (
                          <SelectItem key={item.value} value={item.value}>
                            {item.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>
                {targetKind !== "default" ? (
                  <div className="flex flex-col gap-2">
                    <Label htmlFor="debug-target">
                      {targetKind === "group" ? "group_openid" : "openid"}
                    </Label>
                    <Input
                      id="debug-target"
                      placeholder={targetKind === "group" ? "群 OpenID" : "用户 OpenID"}
                      value={targetValue}
                      onChange={(event) => setTargetValue(event.target.value)}
                    />
                  </div>
                ) : null}
              </div>

              <Button className="mt-1" disabled={sending} onClick={() => void sendPush()}>
                <SendIcon />
                {sending ? "发送中…" : "发送调试推送"}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* 右侧：代码 + 结果 */}
        <div className="flex min-w-0 flex-col gap-6">
          <Card>
            <CardHeader>
              <CardTitle>推送代码</CardTitle>
              <CardDescription>按左侧参数生成，可直接复制到终端执行</CardDescription>
              <CardAction>
                <CopyButton value={codeSamples[codeTab] ?? curlCode} />
              </CardAction>
            </CardHeader>
            <CardContent>
              <Tabs value={codeTab} onValueChange={(value) => setCodeTab(String(value))}>
                <TabsList>
                  <TabsTrigger value="curl">cURL</TabsTrigger>
                  <TabsTrigger value="powershell">PowerShell</TabsTrigger>
                  <TabsTrigger value="python">Python</TabsTrigger>
                </TabsList>
                {Object.entries(codeSamples).map(([key, code]) => (
                  <TabsContent key={key} value={key}>
                    <pre className="max-h-[420px] overflow-auto rounded-2xl bg-muted p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
                      <code>{code}</code>
                    </pre>
                  </TabsContent>
                ))}
              </Tabs>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>推送结果</CardTitle>
              <CardDescription>此处在服务端实际发送后显示 Webhook 响应</CardDescription>
              {result ? (
                <CardAction>
                  <div className="flex items-center gap-2">
                    <Badge
                      className={
                        result.ok
                          ? "bg-emerald-600/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400"
                          : undefined
                      }
                      variant={result.ok ? undefined : "destructive"}
                    >
                      {result.status === 0 ? "网络异常" : `HTTP ${result.status}`}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {result.durationMs.toFixed(0)} ms
                    </span>
                  </div>
                </CardAction>
              ) : null}
            </CardHeader>
            <CardContent>
              {result ? (
                <pre className="max-h-[360px] overflow-auto rounded-2xl bg-muted p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
                  <code>{result.body}</code>
                </pre>
              ) : (
                <EmptyHint>还没有发送调试推送</EmptyHint>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
