use crate::{domain::*, error::SignError};
/// Implement only through the approved Core/Vault document-key custody API.
/// Implementations must never expose private-key bytes to the UI layer.
pub trait DocumentSigningProvider: Send + Sync {
    fn sign_document(&self, identity: &IdentityRef, document: &DocumentToSign) -> Result<SignatureArtifact, SignError>;
    fn verify_document(&self, request: &VerificationRequest) -> Result<VerificationStatus, SignError>;
}
/// Default provider while the Core/Vault API is pending. It fails closed.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableProvider;
impl DocumentSigningProvider for UnavailableProvider {
    fn sign_document(&self, _identity: &IdentityRef, _document: &DocumentToSign) -> Result<SignatureArtifact, SignError> {
        Err(SignError::ProviderUnavailable)
    }
    fn verify_document(&self, _request: &VerificationRequest) -> Result<VerificationStatus, SignError> {
        Err(SignError::ProviderUnavailable)
    }
}
