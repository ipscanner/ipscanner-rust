use std::fmt;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use serde_json::Value;

/// Errors returned by the client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The API answered with an error status not covered by a more specific variant.
    #[error("{0}")]
    Api(ApiError),
    /// 401 or 403: the key is missing, invalid, or the account is suspended.
    #[error("{0}")]
    Authentication(ApiError),
    /// 404: the resource does not exist.
    #[error("{0}")]
    NotFound(ApiError),
    /// 429: a quota or rate limit was hit.
    #[error("{0}")]
    RateLimit(Box<RateLimitError>),
    /// The request could not be sent or the response could not be read.
    #[error("http error: {0}")]
    Http(#[source] reqwest::Error),
    /// The request timed out.
    #[error("request timed out")]
    Timeout,
    /// The response body was not the expected JSON.
    #[error("decode error: {0}")]
    Decode(#[from] serde_json::Error),
}

impl Error {
    /// The API error details, if the server answered with an error status.
    pub fn api_error(&self) -> Option<&ApiError> {
        match self {
            Error::Api(e) | Error::Authentication(e) | Error::NotFound(e) => Some(e),
            Error::RateLimit(e) => Some(&e.api),
            _ => None,
        }
    }

    /// The HTTP status code, if the server answered with an error status.
    pub fn status(&self) -> Option<u16> {
        self.api_error().map(|e| e.status)
    }

    /// The API error code, such as `invalid_ip`.
    pub fn code(&self) -> Option<&str> {
        self.api_error().map(|e| e.code.as_str())
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            Error::Timeout
        } else {
            Error::Http(e)
        }
    }
}

/// An error response from the API.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
    pub body: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.code, self.status, self.message)
    }
}

impl std::error::Error for ApiError {}

/// A 429 response, with the quota fields from the body and the rate-limit headers.
#[derive(Debug, Clone)]
pub struct RateLimitError {
    pub api: ApiError,
    pub reason: Option<String>,
    pub retry_after: Option<Duration>,
    pub reset_at: Option<String>,
    pub reset_date: Option<String>,
    pub limit: Option<i64>,
    pub usage: Option<i64>,
    pub remaining: Option<i64>,
    pub needed: Option<i64>,
    pub plan: Option<String>,
    pub upgrade_url: Option<String>,
    pub rate_limit: RateLimitHeaders,
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.api.fmt(f)
    }
}

impl std::error::Error for RateLimitError {}

/// The `X-RateLimit-*`, `X-Quota-*` and `Retry-After` response headers.
#[derive(Debug, Clone, Default)]
pub struct RateLimitHeaders {
    pub meter: Option<String>,
    pub limit: Option<i64>,
    pub remaining: Option<i64>,
    pub reset: Option<i64>,
    pub daily_limit: Option<i64>,
    pub daily_remaining: Option<i64>,
    pub daily_reset: Option<i64>,
    pub hourly_limit: Option<i64>,
    pub hourly_remaining: Option<i64>,
    pub hourly_reset: Option<i64>,
    pub usage_percent: Option<f64>,
    pub upgrade_hint: Option<String>,
    pub upgrade_url: Option<String>,
    pub upgrade_plan: Option<String>,
    pub retry_after: Option<u64>,
}

impl RateLimitHeaders {
    pub(crate) fn from_headers(h: &HeaderMap) -> Self {
        let s = |name: &str| {
            h.get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let n = |name: &str| s(name).and_then(|v| v.parse().ok());
        RateLimitHeaders {
            meter: s("x-ratelimit-meter"),
            limit: n("x-ratelimit-limit"),
            remaining: n("x-ratelimit-remaining"),
            reset: n("x-ratelimit-reset"),
            daily_limit: n("x-ratelimit-daily-limit"),
            daily_remaining: n("x-ratelimit-daily-remaining"),
            daily_reset: n("x-ratelimit-daily-reset"),
            hourly_limit: n("x-ratelimit-hourly-limit"),
            hourly_remaining: n("x-ratelimit-hourly-remaining"),
            hourly_reset: n("x-ratelimit-hourly-reset"),
            usage_percent: s("x-ratelimit-usage-percent").and_then(|v| v.parse().ok()),
            upgrade_hint: s("x-quota-upgrade-hint"),
            upgrade_url: s("x-quota-upgrade-url"),
            upgrade_plan: s("x-quota-upgrade-plan"),
            retry_after: s("retry-after").and_then(|v| v.parse().ok()),
        }
    }
}

pub(crate) fn from_response(status: StatusCode, headers: &HeaderMap, body: String) -> Error {
    let parsed: Option<serde_json::Map<String, Value>> = serde_json::from_str(&body).ok();
    let with_code = parsed
        .as_ref()
        .and_then(|m| m.get("error").and_then(Value::as_str).map(|c| (m, c)));

    let api = match with_code {
        Some((m, code)) => ApiError {
            status: status.as_u16(),
            code: code.to_string(),
            message: m
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            details: m.get("details").filter(|v| !v.is_null()).cloned(),
            body: body.clone(),
        },
        None => ApiError {
            status: status.as_u16(),
            code: format!("http_{}", status.as_u16()),
            message: status.canonical_reason().unwrap_or_default().to_string(),
            details: None,
            body: body.clone(),
        },
    };

    match status.as_u16() {
        401 | 403 => Error::Authentication(api),
        404 => Error::NotFound(api),
        429 => {
            let get = |k: &str| parsed.as_ref().and_then(|m| m.get(k));
            let str_field = |k: &str| get(k).and_then(Value::as_str).map(str::to_string);
            let int_field = |k: &str| get(k).and_then(Value::as_i64);
            let rate_limit = RateLimitHeaders::from_headers(headers);
            let retry_after = get("retryAfter")
                .and_then(Value::as_u64)
                .or(rate_limit.retry_after)
                .map(Duration::from_secs);
            let upgrade_url = get("upgrade")
                .and_then(|u| u.get("url"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| rate_limit.upgrade_url.clone());
            Error::RateLimit(Box::new(RateLimitError {
                reason: str_field("reason"),
                retry_after,
                reset_at: str_field("resetAt"),
                reset_date: str_field("resetDate"),
                limit: int_field("limit"),
                usage: int_field("usage"),
                remaining: int_field("remaining"),
                needed: int_field("needed"),
                plan: str_field("plan"),
                upgrade_url,
                rate_limit,
                api,
            }))
        }
        _ => Error::Api(api),
    }
}
