import { NextResponse, type NextRequest } from "next/server";

// 反代到后端时，浏览器自带的代理头可被伪造（uvicorn 默认信任 127.0.0.1 传来的
// X-Forwarded-For），会导致审计日志与按 IP 限流被绕过，这里统一丢弃。
const STRIPPED = [
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
];

export function proxy(request: NextRequest) {
  // 必须基于完整请求头克隆再删除：只传部分头会让 Next 丢弃其余请求头
  const headers = new Headers(request.headers);
  for (const name of STRIPPED) headers.delete(name);
  return NextResponse.next({ request: { headers } });
}

export const config = {
  matcher: ["/api/:path*", "/webhook/:path*"],
};
