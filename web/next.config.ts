import type { NextConfig } from "next";

// 容器内 supervisord 同时拉起 uvicorn(8000) 与 Next(3000)，
// 浏览器只访问 Next，由这里把接口与 Webhook 反代到后端。
const backend = process.env.BACKEND_ORIGIN ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${backend}/api/:path*` },
      { source: "/webhook/:path*", destination: `${backend}/webhook/:path*` },
    ];
  },
};

export default nextConfig;
