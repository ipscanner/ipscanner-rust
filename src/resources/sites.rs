use crate::client::segment;
use crate::types::SitePolicy;
use crate::{Client, Error};

/// Site policies. Get one with [`Client::sites`].
#[derive(Debug, Clone, Copy)]
pub struct Sites<'a> {
    client: &'a Client,
}

impl<'a> Sites<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Sites { client }
    }

    /// The policy a site's Worker enforces. Not metered.
    pub async fn policy(&self, id: &str) -> Result<SitePolicy, Error> {
        self.client
            .get(&format!("/sites/{}/policy", segment(id)), &[])
            .await
    }
}
