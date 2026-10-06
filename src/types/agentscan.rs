use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{AsnResponse, GeolocationResponse};

/// Body of `POST /v1/agentscan/check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AgentCheckRequest {
    pub ip: String,
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

impl AgentCheckRequest {
    pub fn new(ip: impl Into<String>) -> Self {
        AgentCheckRequest {
            ip: ip.into(),
            ..Default::default()
        }
    }
}

/// Response of `POST /v1/agentscan/check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentCheck {
    /// `human`, `known_bot`, `ai_agent` or `malicious_automation`.
    pub class: String,
    pub confidence: f64,
    /// `allow`, `flag` or `block`.
    pub action: String,
    pub signals: Map<String, Value>,
}

/// One log line for `POST /v1/agentscan/batch`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AgentBatchLine {
    pub line: i64,
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

impl AgentBatchLine {
    pub fn new(line: i64, ip: impl Into<String>) -> Self {
        AgentBatchLine {
            line,
            ip: ip.into(),
            ..Default::default()
        }
    }
}

/// Response of `POST /v1/agentscan/batch`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentBatch {
    pub submitted: i64,
    pub processed: i64,
    pub failed: i64,
    pub truncated: bool,
    /// Empty, or `quota_exceeded` when the batch was cut short.
    pub reason: String,
    pub by_class: HashMap<String, i64>,
    pub results: Vec<AgentBatchResult>,
    pub as_of: String,
}

/// One classified line of a batch.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentBatchResult {
    pub line: i64,
    pub ip: String,
    pub user_agent: Option<String>,
    pub class: Option<String>,
    pub confidence: Option<f64>,
    pub action: Option<String>,
    pub signals: Option<Map<String, Value>>,
    pub error: Option<String>,
}

/// Body of `POST /v1/agentscan/verify`. Set `bot` or `user_agent`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CrawlerVerifyRequest {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl CrawlerVerifyRequest {
    /// Verify `ip` against a crawler slug such as `googlebot`.
    pub fn bot(ip: impl Into<String>, bot: impl Into<String>) -> Self {
        CrawlerVerifyRequest {
            ip: ip.into(),
            bot: Some(bot.into()),
            user_agent: None,
        }
    }

    /// Verify `ip` against the crawler named in a User-Agent string.
    pub fn user_agent(ip: impl Into<String>, user_agent: impl Into<String>) -> Self {
        CrawlerVerifyRequest {
            ip: ip.into(),
            bot: None,
            user_agent: Some(user_agent.into()),
        }
    }
}

/// Response of `POST /v1/agentscan/verify`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CrawlerVerification {
    pub ip: String,
    pub slug: String,
    pub crawler: String,
    pub user_agent: Option<String>,
    /// `verified`, `spoofed` or `unverifiable`.
    pub outcome: String,
    pub method: String,
    pub summary: String,
    pub checks: Vec<VerifyCheck>,
    pub network_origin: String,
    pub anonymized: bool,
    pub asn: Option<String>,
    pub asn_name: Option<String>,
    pub country: Option<String>,
    pub hostname: Option<String>,
    pub docs: Option<String>,
    pub checked_at: String,
}

/// One check behind a crawler verification.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct VerifyCheck {
    pub name: String,
    pub status: String,
    pub detail: String,
}

/// One entry of `GET /v1/agentscan/allowlist`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AllowlistAgent {
    pub id: i64,
    pub ident: String,
    /// `search`, `ai_crawler` or `partner`.
    #[serde(rename = "type")]
    pub kind: String,
    pub verification_method: String,
    pub customer_id: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Allowlist {
    pub agents: Vec<AllowlistAgent>,
}

/// Body of `POST /v1/agentscan/self`. Every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AgentSelfRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
}

/// Response of `POST /v1/agentscan/self`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AgentSelfCheck {
    pub ip: String,
    pub user_agent: String,
    pub ja4: String,
    /// `edge`, `client` or `unavailable`.
    pub ja4_source: String,
    pub class: String,
    pub confidence: f64,
    pub action: String,
    pub signals: Map<String, Value>,
    pub metered: bool,
    pub as_of: String,
    pub asn: Option<AsnResponse>,
    pub geo: Option<GeolocationResponse>,
}
