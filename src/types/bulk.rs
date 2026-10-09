use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{null_default, Deduction};

/// Input for the bulk endpoints: a list of IPs, or a pasted blob the server splits.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct BulkRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
}

impl BulkRequest {
    /// A request from a list of IPs.
    pub fn ips<I, S>(ips: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        BulkRequest {
            ips: Some(ips.into_iter().map(Into::into).collect()),
            input: None,
        }
    }

    /// A request from free text, one or more IPs per line.
    pub fn input(input: impl Into<String>) -> Self {
        BulkRequest {
            ips: None,
            input: Some(input.into()),
        }
    }
}

/// Response of `POST /v1/bulk/check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BulkCheck {
    pub submitted: i64,
    pub unique: i64,
    pub duplicates: i64,
    #[serde(deserialize_with = "null_default")]
    pub invalid: Vec<String>,
    /// Empty on the Free plan.
    #[serde(deserialize_with = "null_default")]
    pub summary: HashMap<String, i64>,
    #[serde(deserialize_with = "null_default")]
    pub results: Vec<BulkResult>,
    pub plan_required: Option<String>,
}

/// One row of a bulk check. Score, grade, verdict, deductions and VPN brand are null on the Free plan.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BulkResult {
    pub input: String,
    pub ip: String,
    pub port: Option<u16>,
    pub score: Option<i64>,
    pub grade: Option<String>,
    pub verdict: Option<String>,
    pub classification: String,
    pub confidence: f64,
    pub anonymized: bool,
    pub vpn_provider: Option<String>,
    pub is_tor_exit: bool,
    pub in_vpn_range: bool,
    pub in_datacenter_range: bool,
    pub asn: Option<String>,
    pub asn_name: Option<String>,
    pub asn_type: Option<String>,
    pub country: Option<String>,
    #[serde(deserialize_with = "null_default")]
    pub deductions: Vec<Deduction>,
    pub locked: Vec<String>,
}

/// One line of the `POST /v1/ip/bulk` NDJSON stream. Missing and null fields are zero values.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BulkEvent {
    /// `meta`, `result`, `error` or `done`.
    #[serde(rename = "type")]
    pub kind: String,
    pub index: i64,
    pub total: i64,
    pub input: String,
    pub reason: String,
    pub message: String,
    pub error: String,
    pub ip: String,
    #[serde(deserialize_with = "null_default")]
    pub verdict: String,
    pub classification: String,
    pub confidence: f64,
    pub anonymized: bool,
    #[serde(deserialize_with = "null_default")]
    pub vpn_provider: String,
    #[serde(deserialize_with = "null_default")]
    pub score: i64,
    #[serde(deserialize_with = "null_default")]
    pub grade: String,
    pub is_tor_exit: bool,
    pub asn: String,
    pub asn_name: String,
    pub asn_type: String,
    pub country: String,
    pub processed: i64,
    pub failed: i64,
    pub metered: i64,
    /// Set on the `meta` line when result lines are locked.
    pub plan_required: String,
    /// Fields of a `result` line nulled because of the plan.
    pub locked: Vec<String>,
}

impl BulkEvent {
    /// True for a `done` event with reason `complete` where `processed + failed >= total`.
    pub fn complete(&self) -> bool {
        self.kind == "done"
            && self.reason == "complete"
            && self.processed + self.failed >= self.total
    }
}
