import type { NextConfig } from "next";

// 前端为静态导出（output: "export"），产物由 Rust 进程托管：
// - /api 与 /webhook 的反代职责在 Rust 端（静态导出不支持 rewrites）
// - 安全响应头由 Rust 中间件注入（静态导出不支持 headers）
const nextConfig: NextConfig = {
  output: "export",
  reactStrictMode: true,
  compiler: {
    // 生产构建剥离应用代码中的 console.*（错误边界仍通过 error.tsx 显示）
    removeConsole: process.env.NODE_ENV === "production" ? { exclude: ["error"] } : false,
  },
  // turbopack 已按路由自动拆 chunk；lucide-react 在默认优化列表里
};

export default nextConfig;
