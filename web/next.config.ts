import type { NextConfig } from "next";

// 前端改为静态导出（output: "export"），产物由 Rust 进程托管：
// - /api 与 /webhook 的反代职责已迁到 Rust 端（静态导出不支持 rewrites）
// - 5 个安全响应头已迁到 Rust 中间件（静态导出不支持 headers）
const nextConfig: NextConfig = {
  output: "export",
  reactStrictMode: true,
};

export default nextConfig;
