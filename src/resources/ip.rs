use serde_json::json;

use crate::client::segment;
use crate::types::{
    AsnResponse, GeolocationResponse, History, HistoryParams, LookupResult, MyIp, ProxyResponse,
    VpnResponse, WhoisResponse,
};
use crate::{Client, Error};

/// IP lookups. Get one with [`Client::ip`].
#[derive(Debug, Clone, Copy)]
pub struct Ip<'a> {
    client: &'a Client,
}

impl<'a> Ip<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Ip { client }
    }

    /// Full lookup of an IPv4 or IPv6 address, CIDR block or hostname.
    pub async fn lookup(&self, target: &str) -> Result<LookupResult, Error> {
        self.client
            .post("/ip/lookup", &json!({ "target": target }))
            .await
    }

    /// VPN and Tor check.
    pub async fn vpn(&self, ip: &str) -> Result<VpnResponse, Error> {
        self.client.get(&format!("/vpn/{}", segment(ip)), &[]).await
    }

    /// Proxy and Tor check.
    pub async fn proxy(&self, ip: &str) -> Result<ProxyResponse, Error> {
        self.client
            .get(&format!("/proxy/{}", segment(ip)), &[])
            .await
    }

    /// Geolocation.
    pub async fn geo(&self, ip: &str) -> Result<GeolocationResponse, Error> {
        self.client.get(&format!("/geo/{}", segment(ip)), &[]).await
    }

    /// Autonomous system of an address.
    pub async fn asn(&self, ip: &str) -> Result<AsnResponse, Error> {
        self.client.get(&format!("/asn/{}", segment(ip)), &[]).await
    }

    /// WHOIS record of a domain.
    pub async fn whois(&self, domain: &str) -> Result<WhoisResponse, Error> {
        self.client
            .get(&format!("/whois/{}", segment(domain)), &[])
            .await
    }

    /// Your recent lookups, newest first.
    pub async fn history(&self, params: &HistoryParams) -> Result<History, Error> {
        let mut q = Vec::new();
        if let Some(v) = params.limit {
            q.push(("limit", v.to_string()));
        }
        if let Some(v) = params.before {
            q.push(("before", v.to_string()));
        }
        if let Some(v) = &params.verdict {
            q.push(("verdict", v.clone()));
        }
        self.client.get("/ip/history", &q).await
    }

    /// Keyless demo lookup.
    pub async fn demo(&self, ip: &str) -> Result<LookupResult, Error> {
        self.client
            .get(&format!("/demo/{}", segment(ip)), &[])
            .await
    }

    /// The caller's own address. Keyless.
    pub async fn myip(&self) -> Result<MyIp, Error> {
        self.client.get("/myip", &[]).await
    }
}
