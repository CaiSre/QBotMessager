//! 静态资源托管 + SPA 回退 + 安全响应头。
//!
//! 解析顺序：原路径 → `{path}.html` → `{path}/index.html` → 404。
//! 安全响应头从旧 `web/next.config.ts` 的 `headers()` 原样搬到 Rust 中间件：
//! `X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy`、
//! `Permissions-Policy`、`Content-Security-Policy`，作用于每个响应。

use std::future::{Future, Ready, ready};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use actix_files::NamedFile;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName, HeaderValue};
use actix_web::{Error, HttpRequest, HttpResponse, web};

use crate::state::AppState;

///
/// 名称必须全小写：`HeaderName::from_static` 只接受小写（HTTP 头名本身大小写不敏感，
/// HTTP/2 也要求小写）。
pub const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    ),
    (
        "content-security-policy",
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    ),
];

/// 给每个响应追加安全响应头的中间件。
///
/// 用法：`App::new().wrap(SecurityHeaders)`。
#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware { service }))
    }
}

/// [`SecurityHeaders`] 的中间件实现。
pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let future = self.service.call(req);
        Box::pin(async move {
            let mut response = future.await?;
            let headers = response.headers_mut();
            for (name, value) in SECURITY_HEADERS {
                headers.insert(
                    HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                );
            }
            Ok(response)
        })
    }
}

/// 注册静态资源兜底处理器（应放在所有 API 路由之后）。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.default_service(web::to(serve_static));
}

/// 静态资源请求处理。
pub async fn serve_static(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let requested = req.path().trim_start_matches('/');
    let Some(file_path) = resolve_file(state.config.static_dir.as_path(), requested) else {
        return not_found();
    };

    let open_path = file_path.clone();
    let file = match web::block(move || NamedFile::open(&open_path)).await {
        Ok(Ok(file)) => file,
        Ok(Err(err)) => {
            tracing::warn!(path = %file_path.display(), error = %err, "静态资源读取失败");
            return not_found();
        }
        Err(err) => {
            tracing::warn!(path = %file_path.display(), error = %err, "静态资源读取任务失败");
            return not_found();
        }
    };

    let mut response = file.into_response(&req);
    let cache_control = if requested.starts_with("_next/static/") {
        // Next 的构建产物带内容哈希，可长期缓存
        Some("public, max-age=31536000, immutable")
    } else if is_html(&file_path) {
        Some("no-cache")
    } else {
        Some("public, max-age=3600")
    };
    if let Some(value) = cache_control {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static(value));
    }
    response
}

/// 按 SPA 回退顺序查找文件。
fn resolve_file(root: &Path, requested: &str) -> Option<PathBuf> {
    // 拒绝路径穿越与 Windows 分隔符；静态导出不会产生这类路径
    if requested
        .split('/')
        .any(|segment| segment == ".." || segment.contains('\\') || segment.contains('\0'))
    {
        return None;
    }

    let relative = requested.trim_end_matches('/');
    let base = if relative.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };

    let mut candidates = Vec::with_capacity(3);
    candidates.push(base.clone());
    if relative.is_empty() {
        candidates.push(root.join("index.html"));
    } else {
        candidates.push(PathBuf::from(format!("{}.html", base.display())));
        candidates.push(base.join("index.html"));
    }

    candidates.into_iter().find(|path| path.is_file())
}

/// 是否为 HTML 文件。
fn is_html(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("html"))
}

/// 统一 404 响应。
fn not_found() -> HttpResponse {
    HttpResponse::NotFound()
        .insert_header((CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body("Not Found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_header_names_are_static_valid() {
        // `HeaderName::from_static` 对非法名称（含大写、空串）会直接 panic。
        // 这条测试保证常量在启动前就是合法的，避免运行期每个响应都 panic。
        for (name, value) in SECURITY_HEADERS {
            let header = HeaderName::from_static(name);
            assert_eq!(header.as_str(), name);
            HeaderValue::from_static(value);
        }
    }

    #[test]
    fn resolve_file_follows_spa_fallback_order() {
        let root = std::env::temp_dir().join("qbot-web-resolve-test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dashboard")).unwrap();
        std::fs::write(root.join("index.html"), b"root").unwrap();
        std::fs::write(root.join("dashboard.html"), b"flat").unwrap();
        std::fs::write(root.join("dashboard").join("index.html"), b"nested").unwrap();

        assert_eq!(resolve_file(&root, ""), Some(root.join("index.html")));
        assert_eq!(
            resolve_file(&root, "dashboard"),
            Some(root.join("dashboard.html"))
        );
        assert_eq!(resolve_file(&root, "../etc/passwd"), None);
        assert_eq!(resolve_file(&root, "a\\b"), None);

        // 没有扁平 HTML 时回退到目录下的 index.html
        std::fs::remove_file(root.join("dashboard.html")).unwrap();
        assert_eq!(
            resolve_file(&root, "dashboard"),
            Some(root.join("dashboard").join("index.html"))
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
