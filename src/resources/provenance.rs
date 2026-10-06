use serde_json::json;

use crate::types::{
    AnchoredVerification, Chain, ChainParams, ChainVerification, ExportParams, Jurisdiction,
    Jurisdictions, ProvenanceCheck, ProvenanceCheckRequest,
};
use crate::{Client, Error};

/// Provenance attestations. Get one with [`Client::provenance`].
#[derive(Debug, Clone, Copy)]
pub struct Provenance<'a> {
    client: &'a Client,
}

impl<'a> Provenance<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Provenance { client }
    }

    /// Checks an IP against a claimed jurisdiction and writes an attestation.
    pub async fn check(&self, req: &ProvenanceCheckRequest) -> Result<ProvenanceCheck, Error> {
        self.client.post("/provenance/check", req).await
    }

    /// Recomputes your attestation chain.
    pub async fn verify(&self) -> Result<ChainVerification, Error> {
        self.client.get("/provenance/verify", &[]).await
    }

    /// Recomputes your chain and returns the latest daily anchor.
    pub async fn verify_anchored(&self) -> Result<AnchoredVerification, Error> {
        self.client.post("/provenance/verify", &json!({})).await
    }

    /// A page of your attestation chain, newest first.
    pub async fn chain(&self, params: &ChainParams) -> Result<Chain, Error> {
        let mut q = Vec::new();
        if let Some(v) = params.limit {
            q.push(("limit", v.to_string()));
        }
        if let Some(v) = params.before {
            q.push(("before", v.to_string()));
        }
        self.client.get("/provenance/chain", &q).await
    }

    /// The jurisdictions the policy engine knows.
    pub async fn jurisdictions(&self) -> Result<Vec<Jurisdiction>, Error> {
        let res: Jurisdictions = self.client.get("/provenance/jurisdictions", &[]).await?;
        Ok(res.jurisdictions)
    }

    /// Evidence export for a date range, as raw CSV.
    pub async fn export(&self, params: &ExportParams) -> Result<String, Error> {
        let mut q = Vec::new();
        if let Some(v) = &params.from {
            q.push(("from", v.clone()));
        }
        if let Some(v) = &params.to {
            q.push(("to", v.clone()));
        }
        self.client
            .get_text("/provenance/export", &q, "text/csv, application/json")
            .await
    }
}
