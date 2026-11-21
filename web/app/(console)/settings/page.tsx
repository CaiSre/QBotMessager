"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
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
import { ErrorAlert, PageHeader, SuccessAlert } from "@/components/ui";
import { api, messageOf } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import type { SettingItem, SystemSettings } from "@/lib/types";

type Draft = Record<string, string | number | boolean>;

const TIMEZONE_SUGGESTIONS = [
  "Asia/Shanghai",
  "Asia/Hong_Kong",
  "Asia/Singapore",
  "Asia/Tokyo",
  "UTC",
  "Europe/London",
  "Europe/Berlin",
  "America/New_York",
  "America/Los_Angeles",
];

export default function SettingsPage() {
  const settings = useApi<SystemSettings>("/api/admin/settings");
  const [draft, setDraft] = useState<Draft>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    const data = settings.data;
    if (!data) return;
    const next: Draft = {};
    for (const group of data.groups) {
      for (const item of group.items) next[item.key] = item.value;
    }
    setDraft(next);
  }, [settings.data]);

  function update(key: string, value: string | number | boolean) {
    setDraft((previous) => ({ ...previous, [key]: value }));
  }

  async function save() {
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const secretKeys = new Set(
        settings.data?.groups.flatMap((group) =>
          group.items.filter((item) => item.secret).map((item) => item.key),
        ) ?? [],
      );
      const body: Draft = {};
      for (const [key, value] of Object.entries(draft)) {
        // 敏感项留空表示不修改，避免页面回显误清空已保存的密码
        if (secretKeys.has(key) && value === "") continue;
        body[key] = value;
      }
      const data = await api<SystemSettings>("/api/admin/settings", {
        method: "PATCH",
        body,
      });
      settings.setData(data);
      setNotice("设置已保存并立即生效");
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setSaving(false);
    }
  }

  function renderControl(item: SettingItem) {
    const value = draft[item.key];

    if (item.kind === "bool") {
      return (
        <div
          key={item.key}
          className="flex items-start justify-between gap-4 rounded-3xl border bg-muted/20 p-4"
        >
          <div>
            <p className="text-sm font-medium">{item.label}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{item.description}</p>
          </div>
          <Switch
            checked={Boolean(value)}
            id={`setting-${item.key}`}
            onCheckedChange={(checked) => update(item.key, checked)}
          />
        </div>
      );
    }

    return (
      <div key={item.key}>
        <Label htmlFor={`setting-${item.key}`}>{item.label}</Label>
        {item.kind === "select" ? (
          <Select
            items={item.options.map((option) => ({ value: option, label: option }))}
            value={String(value ?? "")}
            onValueChange={(next) => update(item.key, String(next))}
          >
            <SelectTrigger className="mt-2 w-full" id={`setting-${item.key}`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent alignItemWithTrigger={false}>
              <SelectGroup>
                {item.options.map((option) => (
                  <SelectItem key={option} value={option}>
                    {option}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        ) : (
          <Input
            className="mt-2"
            id={`setting-${item.key}`}
            list={item.key === "timezone" ? "settings-timezone" : undefined}
            max={item.maximum ?? undefined}
            min={item.minimum ?? undefined}
            placeholder={
              item.secret
                ? item.has_value
                  ? "已设置，留空保持不变"
                  : "未设置"
                : undefined
            }
            step={item.kind === "float" ? "0.01" : item.kind === "int" ? "1" : undefined}
            type={
              item.secret
                ? "password"
                : item.kind === "float" || item.kind === "int"
                  ? "number"
                  : item.key === "public_base_url"
                    ? "url"
                    : "text"
            }
            value={String(value ?? "")}
            onChange={(event) => update(item.key, event.target.value)}
          />
        )}
        <p className="mt-1.5 text-xs text-muted-foreground">{item.description}</p>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="系统设置"
        description="非敏感运行配置保存在数据库中，保存后立即生效，无需重启容器"
        action={
          <Button disabled={saving || !settings.data} onClick={() => void save()}>
            {saving ? "保存中…" : "保存设置"}
          </Button>
        }
      />
      <ErrorAlert message={error ?? settings.error} />
      <SuccessAlert message={notice} />

      {!settings.data ? (
        <p className="py-10 text-center text-sm text-muted-foreground">
          {settings.loading ? "正在读取系统设置…" : "暂无设置数据"}
        </p>
      ) : (
        <div className="grid items-start gap-6 xl:grid-cols-2">
          {settings.data.groups.map((group) => (
            <Card key={group.name}>
              <CardHeader>
                <CardTitle>{group.name}</CardTitle>
                <CardDescription>
                  共 {group.items.length} 项，修改后点击右上角保存
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col gap-4">
                  {group.items.map((item) => renderControl(item))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <datalist id="settings-timezone">
        {TIMEZONE_SUGGESTIONS.map((zone) => (
          <option key={zone} value={zone} />
        ))}
      </datalist>

      <section className="mt-6 space-y-2 rounded-3xl border bg-muted/30 p-5 text-sm">
        <h2 className="font-heading text-base font-medium">仍由环境变量提供</h2>
        <p className="text-muted-foreground">
          数据库连接信息、加密主密钥、初始管理员账号与 QQ 引导凭据属于敏感或启动依赖项，
          不在本页修改；机器人凭据请到「机器人」页面维护。SMTP 密码在本页填写后会加密入库，
          不会回显明文。
        </p>
      </section>
    </div>
  );
}
