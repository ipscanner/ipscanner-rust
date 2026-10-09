use crate::types::{EdgeCheck, EdgeCheckRequest};
use crate::{Client, Error};

/// Edge checks for a Worker in front of a site. Get one with [`Client::edge`].
#[derive(Debug, Clone, Copy)]
pub struct Edge<'a> {
    client: &'a Client,
}

impl<'a> Edge<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Edge { client }
    }

    /// Agentscan verdict and network check for one visitor in one call. Metered 2 units.
    pub async fn check(&self, req: &EdgeCheckRequest) -> Result<EdgeCheck, Error> {
        self.client.post("/edge/check", req).await
    }
}
