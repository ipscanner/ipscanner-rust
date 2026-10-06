use serde_json::json;

use crate::types::{
    AgentBatch, AgentBatchLine, AgentCheck, AgentCheckRequest, AgentSelfCheck, AgentSelfRequest,
    Allowlist, AllowlistAgent, CrawlerVerification, CrawlerVerifyRequest,
};
use crate::{Client, Error};

/// Agentscan. Get one with [`Client::agentscan`].
#[derive(Debug, Clone, Copy)]
pub struct Agentscan<'a> {
    client: &'a Client,
}

impl<'a> Agentscan<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Agentscan { client }
    }

    /// Classifies one request.
    pub async fn check(&self, req: &AgentCheckRequest) -> Result<AgentCheck, Error> {
        self.client.post("/agentscan/check", req).await
    }

    /// Classifies up to 25,000 log lines.
    pub async fn batch(&self, lines: &[AgentBatchLine]) -> Result<AgentBatch, Error> {
        self.client
            .post("/agentscan/batch", &json!({ "lines": lines }))
            .await
    }

    /// Checks whether an IP really belongs to the crawler it claims to be.
    pub async fn verify(&self, req: &CrawlerVerifyRequest) -> Result<CrawlerVerification, Error> {
        self.client.post("/agentscan/verify", req).await
    }

    /// The known agents on your allowlist.
    pub async fn allowlist(&self) -> Result<Vec<AllowlistAgent>, Error> {
        let res: Allowlist = self.client.get("/agentscan/allowlist", &[]).await?;
        Ok(res.agents)
    }

    /// Classifies the calling connection. Not metered.
    pub async fn self_check(&self, req: &AgentSelfRequest) -> Result<AgentSelfCheck, Error> {
        self.client.post("/agentscan/self", req).await
    }
}
