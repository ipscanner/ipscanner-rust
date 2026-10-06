use serde::{Deserialize, Serialize};

/// Query parameters for the ASN directory top list.
#[derive(Debug, Clone, Default)]
pub struct AsnTopParams {
    /// How many to return, 1 to 1000. The server defaults to 100.
    pub top: Option<u32>,
    /// `addresses` (default) or `prefixes`.
    pub by: Option<String>,
}

/// Response of `GET /v1/asn/directory?top=`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AsnTop {
    pub total: i64,
    pub by: String,
    pub count: i64,
    pub results: Vec<AsnSummary>,
}

/// Response of `GET /v1/asn/directory?q=`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AsnSearch {
    pub total: i64,
    pub query: String,
    pub count: i64,
    pub results: Vec<AsnSummary>,
}

/// An autonomous system in the directory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AsnSummary {
    pub asn: u32,
    pub label: String,
    pub org: String,
    pub network_type: String,
    pub ipv4_prefixes: i64,
    pub ipv6_prefixes: i64,
    pub prefixes: i64,
    pub addresses: u64,
}

/// Response of `GET /v1/asn/directory/{asn}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AsnDetail {
    pub asn: u32,
    pub label: String,
    pub org: String,
    pub network_type: String,
    pub ipv4_prefixes: i64,
    pub ipv6_prefixes: i64,
    pub prefixes: i64,
    pub addresses: u64,
    pub sample_prefixes: Vec<AsnPrefix>,
    pub vpn_range_prefixes: i64,
    pub datacenter_range_prefixes: i64,
    /// Whether the two range counts are meaningful yet.
    pub ranges_loaded: bool,
}

/// A sample prefix announced by an autonomous system.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AsnPrefix {
    pub prefix: String,
    pub version: i64,
    pub addresses: Option<u64>,
}

/// Response of `GET /v1/crawlers`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CrawlerList {
    pub crawlers: Vec<Crawler>,
    pub count: i64,
    pub note: String,
}

/// A crawler this service can verify.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Crawler {
    pub slug: String,
    pub name: String,
    pub tokens: Vec<String>,
    pub method: String,
    pub verifiable: bool,
    pub reverse_dns: Vec<String>,
    pub prefix_files: Vec<String>,
    pub asns: Vec<i64>,
    pub docs: Option<String>,
    pub note: Option<String>,
}
