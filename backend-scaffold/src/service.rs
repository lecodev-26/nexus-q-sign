use crate::{domain::*, error::SignError, provider::{DocumentSigningProvider, UnavailableProvider}};
pub struct SigningService<P: DocumentSigningProvider = UnavailableProvider> { provider: P }
impl Default for SigningService<UnavailableProvider> {
    fn default() -> Self { Self { provider: UnavailableProvider } }
}
impl<P: DocumentSigningProvider> SigningService<P> {
    pub fn new(provider: P) -> Self { Self { provider } }
    pub fn sign(&self, identity: &IdentityRef, document: &DocumentToSign) -> Result<SignatureArtifact, SignError> {
        if identity.id.trim().is_empty() { return Err(SignError::InvalidInput("identificador de identidad vacío")); }
        if document.source.as_os_str().is_empty() || document.sidecar_destination.as_os_str().is_empty() {
            return Err(SignError::InvalidInput("ruta de documento o sidecar vacía"));
        }
        if document.source == document.sidecar_destination {
            return Err(SignError::InvalidInput("el sidecar no puede sobrescribir el original"));
        }
        self.provider.sign_document(identity, document)
    }
    pub fn verify(&self, request: &VerificationRequest) -> Result<VerificationStatus, SignError> {
        if request.document.as_os_str().is_empty() || request.sidecar.as_os_str().is_empty() {
            return Err(SignError::InvalidInput("ruta de documento o firma vacía"));
        }
        self.provider.verify_document(request)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    #[test]
    fn default_service_fails_closed_for_signing() {
        let service = SigningService::default();
        let identity = IdentityRef { id: "identity-1".into(), display_name: "Test".into() };
        let request = DocumentToSign { source: PathBuf::from("document.pdf"), sidecar_destination: PathBuf::from("document.pdf.nqsig") };
        assert_eq!(service.sign(&identity, &request), Err(SignError::ProviderUnavailable));
    }
    #[test]
    fn default_service_fails_closed_for_verification() {
        let service = SigningService::default();
        let request = VerificationRequest { document: PathBuf::from("document.pdf"), sidecar: PathBuf::from("document.pdf.nqsig") };
        assert_eq!(service.verify(&request), Err(SignError::ProviderUnavailable));
    }
    #[test]
    fn rejects_sidecar_overwriting_original() {
        let service = SigningService::default();
        let identity = IdentityRef { id: "identity-1".into(), display_name: "Test".into() };
        let request = DocumentToSign { source: PathBuf::from("document.pdf"), sidecar_destination: PathBuf::from("document.pdf") };
        assert_eq!(service.sign(&identity, &request), Err(SignError::InvalidInput("el sidecar no puede sobrescribir el original")));
    }
    #[test]
    fn rejects_empty_identity() {
        let service = SigningService::default();
        let identity = IdentityRef { id: " ".into(), display_name: "Test".into() };
        let request = DocumentToSign { source: PathBuf::from("document.pdf"), sidecar_destination: PathBuf::from("document.pdf.nqsig") };
        assert_eq!(service.sign(&identity, &request), Err(SignError::InvalidInput("identificador de identidad vacío")));
    }
}
