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
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";

export interface PushTrendPoint {
  date: string;
  count: number;
}

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
  const gradientId = React.useId().replace(/[^a-zA-Z0-9]/g, "");

  const chartData = React.useMemo(
    () =>
      data.map((day) => ({
        date: day.date,
        push: day.count,
      })),
    [data],
  );

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>近 7 日推送量</CardTitle>
      </CardHeader>
      <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
        {chartData.length === 0 ? (
          <EmptyHint>暂无推送数据</EmptyHint>
        ) : (
          <ChartContainer
            config={chartConfig}
            className="aspect-auto h-[220px] w-full"
          >
            <AreaChart
              accessibilityLayer
              data={chartData}
              margin={{ left: 12, right: 12 }}
            >
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
                    labelFormatter={(value) => String(value)}
                  />
                }
              />
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
              <Area
                dataKey="push"
                type="natural"
                fill={`url(#fill-push-${gradientId})`}
                fillOpacity={0.4}
                stroke="var(--color-push)"
              />
            </AreaChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}
