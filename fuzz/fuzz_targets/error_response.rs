#![no_main]

use ipscanner::fuzzing::error_from_response;
use ipscanner::Error;
use ipscanner_io_fuzz::Body;
use libfuzzer_sys::fuzz_target;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::StatusCode;
use serde_json::Value;

const HEADERS: &[&str] = &[
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-meter",
    "x-ratelimit-usage-percent",
    "x-quota-upgrade-url",
];

fuzz_target!(|input: (u16, Vec<(u8, Vec<u8>)>, Body)| {
    let (status, headers, body) = input;
    let status = StatusCode::from_u16(400 + status % 200).unwrap();
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_static(HEADERS[usize::from(name) % HEADERS.len()]);
        if let Ok(value) = HeaderValue::from_bytes(&value) {
            map.append(name, value);
        }
    }
    let text = body.text();
    let err = error_from_response(status, &map, text.clone());
    let _ = err.to_string();

    let code = status.as_u16();
    assert_eq!(err.status(), Some(code));
    match (&err, code) {
        (Error::Authentication(_), 401 | 403)
        | (Error::NotFound(_), 404)
        | (Error::RateLimit(_), 429)
        | (Error::Api(_), _) => {}
        _ => panic!("{code} mapped to {err:?}"),
    }
    assert!(!matches!(err, Error::Api(_)) || !matches!(code, 401 | 403 | 404 | 429));

    let parsed: Option<serde_json::Map<String, Value>> = serde_json::from_str(&text).ok();
    let api = err.api_error().unwrap();
    assert_eq!(api.body, text);
    match parsed
        .as_ref()
        .and_then(|m| m.get("error"))
        .and_then(Value::as_str)
    {
        Some(c) => assert_eq!(api.code, c),
        None => assert_eq!(api.code, format!("http_{code}")),
    }

    if let Error::RateLimit(rl) = &err {
        let body_retry = parsed
            .as_ref()
            .and_then(|m| m.get("retryAfter"))
            .and_then(Value::as_u64);
        let want = body_retry.or(rl.rate_limit.retry_after);
        assert_eq!(rl.retry_after.map(|d| d.as_secs()), want);
    }
});
