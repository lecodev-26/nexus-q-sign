use std::fmt;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    ProviderUnavailable, InvalidInput(&'static str), IdentityUnavailable, IdentityLocked,
    UnsupportedFormat, Io, Internal,
}
impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderUnavailable => write!(f, "El proveedor seguro de firma aún no está conectado"),
            Self::InvalidInput(message) => write!(f, "Entrada no válida: {message}"),
            Self::IdentityUnavailable => write!(f, "La identidad seleccionada no está disponible"),
            Self::IdentityLocked => write!(f, "La identidad está bloqueada"),
            Self::UnsupportedFormat => write!(f, "El formato de firma no es compatible"),
            Self::Io => write!(f, "No se pudo completar la operación de archivo"),
            Self::Internal => write!(f, "Se produjo un error interno"),
        }
    }
}
impl std::error::Error for SignError {}
