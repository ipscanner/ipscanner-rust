use crate::types::{GateVerification, GateVerifyRequest};
use crate::{Client, Error};

/// The form gate, server side. Get one with [`Client::gate`].
#[derive(Debug, Clone, Copy)]
pub struct Gate<'a> {
    client: &'a Client,
}

impl<'a> Gate<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Gate { client }
    }

    /// Redeems a gate token with the site secret. Sent without the API key and never retried.
    pub async fn verify(&self, req: &GateVerifyRequest) -> Result<GateVerification, Error> {
        self.client.post_keyless("/gate/verify", req).await
    }
}
