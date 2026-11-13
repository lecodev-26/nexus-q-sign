//! Backend boundary for NEXUS-Q Sign.
//! This scaffold deliberately performs no cryptographic signing or verification.
pub mod domain;
pub mod error;
pub mod provider;
pub mod service;
pub use domain::*;
pub use error::*;
pub use provider::*;
pub use service::*;
