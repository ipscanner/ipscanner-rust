use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::Deduction;

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
    pub invalid: Vec<String>,
    pub summary: HashMap<String, i64>,
    pub results: Vec<BulkResult>,
}

/// One row of a bulk check.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BulkResult {
    pub input: String,
    pub ip: String,
    pub port: Option<u16>,
    pub score: i64,
    pub grade: String,
    pub verdict: String,
    pub classification: String,
    pub confidence: f64,
    pub anonymized: bool,
    pub is_tor_exit: bool,
    pub in_vpn_range: bool,
    pub in_datacenter_range: bool,
    pub asn: Option<String>,
    pub asn_name: Option<String>,
    pub asn_type: Option<String>,
    pub country: Option<String>,
    pub deductions: Vec<Deduction>,
}

/// One line of the `POST /v1/ip/bulk` NDJSON stream. Missing fields are zero values.
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
    pub verdict: String,
    pub classification: String,
    pub confidence: f64,
    pub anonymized: bool,
    pub score: i64,
    pub grade: String,
    pub is_tor_exit: bool,
    pub asn: String,
    pub asn_name: String,
    pub asn_type: String,
    pub country: String,
    pub processed: i64,
    pub failed: i64,
    pub metered: i64,
}

impl BulkEvent {
    /// True for a `done` event with reason `complete` where `processed + failed >= total`.
    pub fn complete(&self) -> bool {
        self.kind == "done"
            && self.reason == "complete"
            && self.processed + self.failed >= self.total
    }
}
