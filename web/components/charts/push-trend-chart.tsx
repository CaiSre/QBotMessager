"use client";

import * as React from "react";
import { Area, AreaChart, CartesianGrid, XAxis } from "recharts";

import { EmptyHint } from "@/components/ui";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export interface PushTrendPoint {
  date: string;
  count: number;
}

const RANGE_ITEMS = [
  { value: "7d", label: "近 7 日", days: 7 },
  { value: "3d", label: "近 3 日", days: 3 },
];

const chartConfig = {
  push: {
    label: "推送量",
    color: "var(--color-chart-1)",
  },
} satisfies ChartConfig;

export function PushTrendChart({
  data,
  className,
}: {
  data: PushTrendPoint[];
  className?: string;
}) {
  const [range, setRange] = React.useState("7d");
  const gradientId = React.useId().replace(/[^a-zA-Z0-9]/g, "");
  const days = RANGE_ITEMS.find((item) => item.value === range)?.days ?? 7;

  const chartData = React.useMemo(
    () =>
      data.slice(-days).map((day) => ({
        date: day.date,
        push: day.count,
      })),
    [data, days],
  );

  return (
    <Card className={className}>
      <CardHeader className="flex items-center gap-2 space-y-0 border-b py-5 sm:flex-row">
        <div className="grid flex-1 gap-1 text-center sm:text-left">
          <CardTitle>近 7 日推送量</CardTitle>
        </div>
        <Select
          items={RANGE_ITEMS}
          value={range}
          onValueChange={(value) => value && setRange(String(value))}
        >
          <SelectTrigger className="w-[110px] sm:ml-auto" aria-label="选择时间范围">
            <SelectValue />
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false}>
            {RANGE_ITEMS.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </CardHeader>
      <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
        {chartData.length === 0 ? (
          <EmptyHint>暂无推送数据</EmptyHint>
        ) : (
          <ChartContainer
            config={chartConfig}
            className="aspect-auto h-[220px] w-full"
          >
            <AreaChart data={chartData} margin={{ left: 12, right: 12 }}>
              <defs>
                <linearGradient
                  id={`fill-push-${gradientId}`}
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="5%"
                    stopColor="var(--color-push)"
                    stopOpacity={0.8}
                  />
                  <stop
                    offset="95%"
                    stopColor="var(--color-push)"
                    stopOpacity={0.1}
                  />
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} />
              <XAxis
                dataKey="date"
                tickLine={false}
                axisLine={false}
                tickMargin={8}
                minTickGap={32}
                tickFormatter={(value) => String(value).slice(5)}
              />
              <ChartTooltip
                cursor={false}
                content={
                  <ChartTooltipContent
                    indicator="dot"
                    labelFormatter={(value) => String(value)}
                  />
                }
              />
              <Area
                dataKey="push"
                type="natural"
                fill={`url(#fill-push-${gradientId})`}
                stroke="var(--color-push)"
              />
              <ChartLegend content={<ChartLegendContent />} />
            </AreaChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}
