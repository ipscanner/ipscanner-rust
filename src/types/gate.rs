use serde::{Deserialize, Serialize};

/// Body of `POST /v1/gate/verify`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct GateVerifyRequest {
    /// The site secret (`gs_...`).
    pub secret: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// The address the form submitted. Adds an email check (one request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl GateVerifyRequest {
    pub fn new(secret: impl Into<String>, token: impl Into<String>) -> Self {
        GateVerifyRequest {
            secret: secret.into(),
            token: token.into(),
            remote_ip: None,
            email: None,
        }
    }
}

/// Response of `POST /v1/gate/verify`. Wire names are snake_case.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateVerification {
    pub success: bool,
    /// Traffic class, as on an edge check.
    pub class: String,
    /// `allow`, `flag` or `block`.
    pub action: String,
    /// `monitor` or `enforce`.
    pub mode: String,
    pub confidence: f64,
    pub network: GateNetwork,
    pub signals: Vec<String>,
    pub hostname: String,
    pub issued_at: String,
    pub ip_match: bool,
    /// Present when `email` was sent. `action` is then the stricter of the network and email actions.
    pub email: Option<GateEmail>,
    pub locked: Vec<String>,
    #[serde(rename = "planRequired")]
    pub plan_required: Option<String>,
}

/// The email check of a gate verification.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateEmail {
    pub status: String,
    pub reason: Option<String>,
    pub suggestion: Option<String>,
    pub domain: String,
    /// The site's email policy for this outcome.
    pub action: String,
}

/// The network part of a gate verification.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateNetwork {
    pub classification: String,
    pub anonymized: bool,
    /// The network owner. Null when unknown or on the site owner's Free plan.
    pub provider: Option<String>,
    /// The VPN brand. Null when unknown or on the site owner's Free plan.
    pub vpn_provider: Option<String>,
}
