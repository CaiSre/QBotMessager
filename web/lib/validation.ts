// 与后端 _EMAIL_RE 保持一致，避免提交后才拿到 422。
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function isEmail(value: string): boolean {
  return EMAIL_RE.test(value.trim());
}
