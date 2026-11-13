use std::path::PathBuf;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentToSign { pub source: PathBuf, pub sidecar_destination: PathBuf }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRef { pub id: String, pub display_name: String }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureArtifact { pub sidecar_path: PathBuf, pub format_version: u16, pub algorithm: String, pub key_id: String }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRequest { pub document: PathBuf, pub sidecar: PathBuf }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus { Valid, Invalid, UnsupportedFormat }
