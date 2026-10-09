use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::AgentCheck;

/// Body of `POST /v1/edge/check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct EdgeCheckRequest {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headless_flags: Option<HashMap<String, bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl EdgeCheckRequest {
    pub fn new(ip: impl Into<String>) -> Self {
        EdgeCheckRequest {
            ip: ip.into(),
            ..Default::default()
        }
    }
}

/// Response of `POST /v1/edge/check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EdgeCheck {
    /// Traffic class, such as `human`, `verified_bot`, `ai_agent`, `vpn` or `relay`.
    pub class: String,
    /// Null when the Agentscan half did not answer.
    pub agent: Option<AgentCheck>,
    /// Null when the network half did not answer.
    pub network: Option<EdgeNetwork>,
    /// Null when no site was given, or it is unknown or another account's.
    pub site: Option<EdgeSite>,
    /// `agent` and/or `network` when that half is missing.
    pub degraded: Vec<String>,
    pub locked: Vec<String>,
    pub plan_required: Option<String>,
}

/// The network half of an edge check.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EdgeNetwork {
    pub network_class: String,
    pub anonymized: bool,
    pub risk_score: i64,
    /// The network owner. Null on the Free plan.
    pub provider: Option<String>,
    /// The VPN brand when known. Null on the Free plan.
    pub vpn_provider: Option<String>,
    pub evidence: Vec<String>,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_name: Option<String>,
}

/// The site an edge check was attributed to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EdgeSite {
    pub id: String,
    /// `monitor` or `enforce`.
    pub mode: String,
    pub policy_version: i64,
}
