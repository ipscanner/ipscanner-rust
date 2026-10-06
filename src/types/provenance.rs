use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Body of `POST /v1/provenance/check`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ProvenanceCheckRequest {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_jurisdiction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_context: Option<Map<String, Value>>,
}

impl ProvenanceCheckRequest {
    pub fn new(ip: impl Into<String>) -> Self {
        ProvenanceCheckRequest {
            ip: ip.into(),
            ..Default::default()
        }
    }
}

/// Response of `POST /v1/provenance/check`. The API sends this one in snake_case.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProvenanceCheck {
    pub network_origin: String,
    pub anonymized: bool,
    pub method: String,
    pub confidence: f64,
    /// `allow`, `step_up` or `block`.
    pub policy_action: String,
    pub attestation_id: i64,
}

/// Response of `GET /v1/provenance/verify`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ChainVerification {
    pub ok: bool,
    pub count: i64,
    pub broken_at: i64,
}

/// Response of `POST /v1/provenance/verify`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnchoredVerification {
    pub ok: bool,
    pub count: i64,
    pub broken_at: i64,
    pub yours: i64,
    pub anchor: Option<Anchor>,
    pub at: String,
}

/// A daily root hash anchoring the chain.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Anchor {
    pub day: String,
    pub root_hash: String,
    pub last_id: i64,
}

/// Query parameters for `GET /v1/provenance/chain`.
#[derive(Debug, Clone, Default)]
pub struct ChainParams {
    /// Page size. The server defaults to 50 and caps at 200.
    pub limit: Option<u32>,
    pub before: Option<i64>,
}

/// Response of `GET /v1/provenance/chain`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Chain {
    pub links: Vec<ChainLink>,
    pub next_before: i64,
    pub total: i64,
    pub summary: ChainSummary,
    pub anchor: Option<Anchor>,
    pub jurisdictions: Vec<Jurisdiction>,
    pub as_of: String,
}

/// One attestation in the chain, with its verification state.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ChainLink {
    pub id: i64,
    pub ts: String,
    pub ip: String,
    pub claimed_jurisdiction: String,
    pub network_origin: String,
    pub anonymized: bool,
    pub method: String,
    pub confidence: f64,
    pub policy_action: String,
    pub entry_hash: String,
    pub prev_hash: String,
    pub prev_id: i64,
    pub entry_ok: bool,
    pub link_ok: bool,
}

/// Attestation counts by policy action.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChainSummary {
    pub allow: i64,
    pub step_up: i64,
    pub block: i64,
}

/// A jurisdiction the policy engine knows.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Jurisdiction {
    pub code: String,
    pub label: String,
    pub law: Option<String>,
    pub strict: bool,
    pub clean_action: String,
    pub masked_action: String,
    pub rule: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Jurisdictions {
    pub jurisdictions: Vec<Jurisdiction>,
}

/// Query parameters for `GET /v1/provenance/export`. Dates are RFC3339 or `YYYY-MM-DD`.
#[derive(Debug, Clone, Default)]
pub struct ExportParams {
    pub from: Option<String>,
    pub to: Option<String>,
}
