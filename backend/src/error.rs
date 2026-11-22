//! 统一错误类型：与 FastAPI 的 `{"detail": "中文信息"}` 响应体形状保持一致。
//!
//! 规格书第 5.1 节约定：所有错误都返回 `{"detail": "<中文信息>"}`，
//! 前端 `web/lib/api.ts` 的 `detailOf()` 只取字符串分支。

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;

/// 错误响应体。
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// 中文错误信息。
    pub detail: String,
}

/// 应用级错误。
///
/// 变体与 HTTP 状态码一一对应，便于在处理器里直接 `?` 传播。
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// 400：请求本身不合法。
    #[error("{0}")]
    BadRequest(String),
    /// 401：未登录或凭据无效。
    #[error("{0}")]
    Unauthorized(String),
    /// 403：已登录但权限不足。
    #[error("{0}")]
    Forbidden(String),
    /// 404：目标不存在。
    #[error("{0}")]
    NotFound(String),
    /// 409：与现有资源冲突（重复用户名、Passkey 已绑定等）。
    #[error("{0}")]
    Conflict(String),
    /// 422：字段校验失败。
    #[error("{0}")]
    Validation(String),
    /// 429：触发限速；`retry_after` 为建议的 Retry-After 秒数。
    #[error("{message}")]
    RateLimited {
        /// 中文错误信息。
        message: String,
        /// 建议客户端等待的秒数。
        retry_after: u64,
    },
    /// 503：数据库繁忙（连接池等待超时等）。
    #[error("{0}")]
    DatabaseBusy(String),
    /// 502：外部服务（QQ、OAuth、SMTP、GitHub）调用失败。
    #[error("{0}")]
    ExternalService(String),
    /// 500：内部错误。
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    /// 400 请求不合法。
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    /// 401 未登录。
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized(message.into())
    }

    /// 403 无权限。
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    /// 404 未找到。
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    /// 409 冲突。
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    /// 422 校验失败。
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    /// 429 限速，带 Retry-After 秒数。
    pub fn rate_limited(message: impl Into<String>, retry_after: u64) -> Self {
        Self::RateLimited {
            message: message.into(),
            retry_after,
        }
    }

    /// 503 数据库繁忙。
    pub fn database_busy(message: impl Into<String>) -> Self {
        Self::DatabaseBusy(message.into())
    }

    /// 502 外部服务失败。
    pub fn external_service(message: impl Into<String>) -> Self {
        Self::ExternalService(message.into())
    }

    /// 500 内部错误。
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// 响应体中的中文信息。
    pub fn detail(&self) -> &str {
        match self {
            Self::BadRequest(m)
            | Self::Unauthorized(m)
            | Self::Forbidden(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::Validation(m)
            | Self::DatabaseBusy(m)
            | Self::ExternalService(m)
            | Self::Internal(m) => m,
            Self::RateLimited { message, .. } => message,
        }
    }

    /// 429 时携带的 Retry-After 秒数。
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after, .. } => Some(*retry_after),
            _ => None,
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::DatabaseBusy(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::ExternalService(_) => StatusCode::BAD_GATEWAY,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut builder = HttpResponse::build(self.status_code());
        if let Some(retry_after) = self.retry_after() {
            builder.insert_header(("Retry-After", retry_after.to_string()));
        }
        builder.json(ErrorBody {
            detail: self.detail().to_string(),
        })
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            // 连接池等待超时：交给调用方重试，而不是暴露成 500。
            sqlx::Error::PoolTimedOut => Self::database_busy("数据库繁忙，请稍后重试"),
            // MySQL 1205（锁等待超时）/ 1213（死锁）同样按繁忙处理。
            sqlx::Error::Database(db_err) => {
                let code = db_err.code().unwrap_or_default().to_string();
                if code == "1205" || code == "1213" {
                    Self::database_busy("数据库繁忙，请稍后重试")
                } else {
                    tracing::error!(error = %db_err, "数据库操作失败");
                    Self::internal("数据库操作失败")
                }
            }
            other => {
                tracing::error!(error = %other, "数据库操作失败");
                Self::internal("数据库操作失败")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_match_contract() {
        assert_eq!(
            AppError::unauthorized("未登录").status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::forbidden("无权限").status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AppError::not_found("不存在").status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::conflict("已存在").status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::validation("字段非法").status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            AppError::rate_limited("太频繁", 30).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            AppError::database_busy("忙").status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AppError::external_service("失败").status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            AppError::internal("炸了").status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn detail_is_chinese_message() {
        assert_eq!(AppError::not_found("通道不存在").detail(), "通道不存在");
        assert_eq!(AppError::rate_limited("慢一点", 5).retry_after(), Some(5));
        assert_eq!(AppError::not_found("x").retry_after(), None);
    }
}
