import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="max-w-md text-center">
        <p className="font-heading text-3xl font-medium tracking-tight">404</p>
        <p className="mt-2 text-sm text-muted-foreground">
          页面不存在，可能已被移除或链接有误。
        </p>
        <Link
          className="mt-5 inline-block text-sm font-medium text-primary underline-offset-4 hover:underline"
          href="/"
        >
          返回首页
        </Link>
      </div>
    </main>
  );
}
