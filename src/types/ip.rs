use serde::{Deserialize, Serialize};

use super::null_default;

/// Response of `GET /v1/vpn/{ip}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct VpnResponse {
    pub ip: String,
    pub is_vpn: bool,
    pub is_tor: bool,
    pub network_class: String,
    pub anonymized: bool,
    /// The network owner. Null on the Free plan.
    pub provider: Option<String>,
    /// The VPN brand when known. Null on the Free plan.
    pub vpn_provider: Option<String>,
    pub risk_score: i64,
    pub evidence: Vec<String>,
    /// Fields nulled because of the plan.
    pub locked: Vec<String>,
    /// The plan that unlocks `locked`.
    pub plan_required: Option<String>,
}

/// Response of `GET /v1/proxy/{ip}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ProxyResponse {
    pub ip: String,
    pub is_proxy: bool,
    pub is_tor: bool,
    pub network_class: String,
    pub anonymized: bool,
    /// The network owner. Null on the Free plan.
    pub provider: Option<String>,
    /// The VPN brand when known. Null on the Free plan.
    pub vpn_provider: Option<String>,
    pub risk_score: i64,
    pub evidence: Vec<String>,
    /// Fields nulled because of the plan.
    pub locked: Vec<String>,
    /// The plan that unlocks `locked`.
    pub plan_required: Option<String>,
}

/// Response of `GET /v1/geo/{ip}`. Precise-location fields are null on the Free plan.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct GeolocationResponse {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub region: String,
    pub postal_code: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: String,
    pub accuracy_radius: Option<i64>,
    pub locked: Vec<String>,
    pub plan_required: Option<String>,
}

/// Response of `GET /v1/asn/{ip}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AsnResponse {
    pub ip: String,
    pub asn: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub country: String,
}

/// Response of `GET /v1/whois/{domain}`. Dates are the registry's raw strings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WhoisResponse {
    pub domain: String,
    pub registrar: String,
    pub registered_on: String,
    pub expires_on: String,
    pub last_updated: String,
    #[serde(deserialize_with = "null_default")]
    pub nameservers: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub status: Vec<String>,
    pub privacy_protection: bool,
    /// `ok`, `not_found`, `timeout`, `unavailable` or `unparsed`; set on `GET /v1/whois/{domain}`.
    pub whois_status: Option<String>,
}

/// A full lookup, from `POST /v1/ip/lookup` or `GET /v1/demo/{ip}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LookupResult {
    pub target: Target,
    pub reserved: ReservedRange,
    pub verdict: Verdict,
    /// Null on the Free plan.
    pub purity: Option<Purity>,
    pub network_class: String,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_tor: bool,
    pub provider: Option<String>,
    pub vpn_provider: Option<String>,
    pub risk_score: i64,
    pub network_type: Option<String>,
    pub geo: Option<GeolocationResponse>,
    pub asn: Option<AsnResponse>,
    /// Present only when `whois_status` is `ok`.
    pub whois: Option<WhoisResponse>,
    /// Set for hostname targets.
    pub whois_status: Option<String>,
    pub degraded: Vec<String>,
    pub at: String,
    pub locked: Vec<String>,
    pub plan_required: Option<String>,
}

/// What a lookup target resolved to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Target {
    pub raw: String,
    pub kind: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub network: Option<String>,
    pub addresses: Option<i64>,
}

/// Whether the address is in a reserved range.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReservedRange {
    pub reserved: bool,
    pub label: Option<String>,
    pub detail: Option<String>,
}

/// The network classification.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Verdict {
    pub classification: String,
    pub anonymized: bool,
    pub confidence: f64,
    pub method: String,
    pub evidence: Vec<String>,
}

/// The purity score and the deductions behind it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Purity {
    pub score: i64,
    pub grade: String,
    pub verdict: String,
    #[serde(deserialize_with = "null_default")]
    pub deductions: Vec<Deduction>,
}

/// One factor that lowered a purity score.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Deduction {
    pub factor: String,
    pub points: i64,
    pub detail: String,
}

/// Query parameters for `GET /v1/ip/history`.
#[derive(Debug, Clone, Default)]
pub struct HistoryParams {
    pub limit: Option<u32>,
    pub before: Option<i64>,
    pub verdict: Option<String>,
}

/// Response of `GET /v1/ip/history`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct History {
    pub events: Vec<HistoryEvent>,
    /// Cursor for the next page; 0 means there are no more.
    pub next_before: i64,
    pub as_of: String,
}

/// One past lookup.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HistoryEvent {
    pub id: i64,
    pub at: String,
    pub target: String,
    pub ip: String,
    pub verdict: String,
    pub confidence: f64,
    pub asn: String,
    pub asn_name: String,
    pub country: String,
    pub anonymized: bool,
    pub source: String,
}

/// Response of `GET /v1/myip`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MyIp {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub region: String,
    pub postal_code: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub accuracy_radius: i64,
    pub asn: String,
    pub asn_name: String,
    pub asn_type: String,
    pub asn_country: String,
}
