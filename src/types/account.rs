use serde::{Deserialize, Serialize};

/// Response of `GET /v1/user/limits`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Limits {
    pub account_type: String,
    pub limit: i64,
    pub usage: i64,
    pub remaining: i64,
    pub reset_date: String,
    pub daily: Option<Window>,
    pub hourly: Option<Window>,
}

/// A daily or hourly allowance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Window {
    pub limit: i64,
    pub used: i64,
    pub remaining: i64,
    pub reset_at: String,
}

/// Response of `GET /v1/usage/summary`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct UsageSummary {
    pub plan: String,
    pub used: i64,
    pub limit: i64,
    pub unlimited: bool,
    pub remaining: i64,
    pub percent: f64,
    pub soft_blocked: bool,
    /// Empty, `monthly`, `daily` or `hourly`.
    pub blocked_by: String,
    pub upgrade_hint: bool,
    pub bulk_cap: i64,
    pub daily: Option<Window>,
    pub hourly: Option<Window>,
    pub period_start: String,
    pub reset_date: String,
    pub as_of: String,
}
