//! Request and response types.

mod account;
mod agentscan;
mod bulk;
mod directory;
mod edge;
mod gate;
mod ip;
mod provenance;
mod sites;

pub use account::*;
pub use agentscan::*;
pub use bulk::*;
pub use directory::*;
pub use edge::*;
pub use gate::*;
pub use ip::*;
pub use provenance::*;
pub use sites::*;

use serde::{Deserialize, Deserializer};

/// Decodes JSON null as the type's default value.
pub(crate) fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
