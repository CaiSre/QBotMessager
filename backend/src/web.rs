//! 静态资源托管 + SPA 回退 + 安全响应头。
//!
//! 解析顺序：原路径 → `{path}.html` → `{path}/index.html` → 404。
//! 安全响应头由 Rust 中间件统一添加；HTML 响应还会按页面内联脚本的
//! SHA-256 生成 CSP，API 响应额外禁止缓存。

use std::collections::HashSet;
use std::future::{Future, Ready, ready};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use actix_files::NamedFile;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderName, HeaderValue,
};
use actix_web::{Error, HttpRequest, HttpResponse, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use regex::bytes::Regex;
use sha2::{Digest, Sha256};

use crate::state::AppState;

///
/// 名称必须全小写：`HeaderName::from_static` 只接受小写（HTTP 头名本身大小写不敏感，
/// HTTP/2 也要求小写）。
pub const SECURITY_HEADERS: [(&str, &str); 6] = [
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    ),
    (
        // 基线策略用于 API 与静态资源；HTML 响应会在 serve_static 中按页面
        // 内联脚本的实际内容追加 sha256 哈希，不使用 'unsafe-inline'。
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; \
         base-uri 'self'; form-action 'self'",
    ),
    (
        // 浏览器只在 HTTPS 响应上采纳该头；HTTP 部署不受影响。
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
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
        let no_store = req.path().starts_with("/api/");
        let future = self.service.call(req);
        Box::pin(async move {
            let mut response = future.await?;
            let headers = response.headers_mut();
            for (name, value) in SECURITY_HEADERS {
                // HTML 处理器已按页面计算含内联脚本哈希的 CSP，不要覆盖。
                if name == "content-security-policy"
                    && headers.contains_key(CONTENT_SECURITY_POLICY)
                {
                    continue;
                }
                headers.insert(
                    HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                );
            }
            if no_store {
                headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
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
    let html = is_html(&file_path);
    let prepared = web::block(move || {
        let csp = if html {
            let bytes = std::fs::read(&open_path)?;
            Some(content_security_policy(&inline_script_hashes(&bytes)))
        } else {
            None
        };
        let file = NamedFile::open(&open_path)?;
        Ok::<_, std::io::Error>((file, csp))
    })
    .await;
    let (file, csp) = match prepared {
        Ok(Ok(prepared)) => prepared,
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
    if let Some(csp) = csp
        && let Ok(value) = HeaderValue::from_str(&csp)
    {
        response
            .headers_mut()
            .insert(CONTENT_SECURITY_POLICY, value);
    }
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

/// 构造按页面内联脚本哈希收紧的 CSP。
fn content_security_policy(hashes: &[String]) -> String {
    let mut script_src = String::from("'self'");
    for hash in hashes {
        script_src.push_str(" 'sha256-");
        script_src.push_str(hash);
        script_src.push('\'');
    }
    format!(
        "default-src 'self'; script-src {script_src}; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; \
         base-uri 'self'; form-action 'self'"
    )
}

/// 提取 HTML 中每个非空内联脚本正文的 SHA-256（base64），按出现顺序去重。
///
/// CSP 的脚本哈希计算对象是 `<script>` 与 `</script>` 之间的原始字节；
/// 外链脚本正文为空，会被跳过，其来源仍由 `script-src 'self'` 约束。
fn inline_script_hashes(html: &[u8]) -> Vec<String> {
    static SCRIPT_RE: OnceLock<Regex> = OnceLock::new();
    let pattern = SCRIPT_RE.get_or_init(|| {
        Regex::new(r#"(?is)<script\b(?:"[^"]*"|'[^']*'|[^'">])*>(.*?)</script\s*>"#)
            .expect("内联脚本匹配正则必须合法")
    });

    let mut seen = HashSet::new();
    let mut hashes = Vec::new();
    for capture in pattern.captures_iter(html) {
        let Some(body) = capture.get(1) else {
            continue;
        };
        if body.as_bytes().is_empty() {
            continue;
        }
        let hash = STANDARD.encode(Sha256::digest(body.as_bytes()));
        if seen.insert(hash.clone()) {
            hashes.push(hash);
        }
    }
    hashes
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
    fn security_headers_block_scripts_and_upgrade_https() {
        let find = |name: &str| {
            SECURITY_HEADERS
                .iter()
                .find(|(header, _)| *header == name)
                .map(|(_, value)| *value)
                .unwrap_or_else(|| panic!("缺少安全头 {name}"))
        };
        let csp = find("content-security-policy");
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert_eq!(
            find("strict-transport-security"),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[test]
    fn html_csp_hashes_inline_scripts_and_skips_external() {
        let html = br#"<script>alert(1)</script>
            <script src="/app.js"></script>
            <SCRIPT type="module">console.log("x")</SCRIPT>"#;
        let hashes = inline_script_hashes(html);
        assert_eq!(
            hashes,
            vec![
                STANDARD.encode(Sha256::digest(b"alert(1)")),
                STANDARD.encode(Sha256::digest(br#"console.log("x")"#)),
            ]
        );
        let csp = content_security_policy(&hashes);
        let script_src = csp
            .split("script-src ")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .expect("CSP 必须包含 script-src");
        assert!(script_src.contains(&format!("'sha256-{}'", hashes[0])));
        assert!(!script_src.contains("unsafe-inline"));
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
    }

    #[test]
    fn csp_hash_deduplicates_repeated_scripts() {
        let html = br#"<script>same()</script><script>same()</script>"#;
        let hashes = inline_script_hashes(html);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], STANDARD.encode(Sha256::digest(b"same()")));
    }

    #[actix_web::test]
    async fn api_responses_are_not_cached() {
        use actix_web::{App, test};

        let app = test::init_service(
            App::new()
                .wrap(SecurityHeaders)
                .route("/api/auth/me", web::get().to(|| async { "ok" })),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/api/auth/me").to_request(),
        )
        .await;
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
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
