use crate::client::segment;
use crate::types::{AsnDetail, AsnSearch, AsnTop, AsnTopParams};
use crate::{Client, Error};

/// The public ASN directory. Keyless. Get one with [`Client::asn_directory`].
#[derive(Debug, Clone, Copy)]
pub struct AsnDirectory<'a> {
    client: &'a Client,
}

impl<'a> AsnDirectory<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        AsnDirectory { client }
    }

    /// The largest autonomous systems by address count or prefix count.
    pub async fn top(&self, params: &AsnTopParams) -> Result<AsnTop, Error> {
        let mut q = Vec::new();
        if let Some(v) = params.top {
            q.push(("top", v.to_string()));
        }
        if let Some(v) = &params.by {
            q.push(("by", v.clone()));
        }
        self.client.get("/asn/directory", &q).await
    }

    /// Searches by name or number.
    pub async fn search(&self, query: &str, limit: Option<u32>) -> Result<AsnSearch, Error> {
        let mut q = vec![("q", query.to_string())];
        if let Some(v) = limit {
            q.push(("limit", v.to_string()));
        }
        self.client.get("/asn/directory", &q).await
    }

    /// One autonomous system. Accepts `15169` or `"AS15169"`.
    pub async fn get(&self, asn: impl ToString) -> Result<AsnDetail, Error> {
        let raw = asn.to_string();
        let raw = raw.trim();
        let number = raw
            .strip_prefix("AS")
            .or_else(|| raw.strip_prefix("as"))
            .unwrap_or(raw);
        self.client
            .get(&format!("/asn/directory/{}", segment(number)), &[])
            .await
    }
}
