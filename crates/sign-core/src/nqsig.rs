//! Strict NQSIG v1 detached-signature framing and deterministic-CBOR codec.
//! This module parses untrusted sidecars but performs no document I/O or cryptography.

use thiserror::Error;

pub const NQSIG_MAGIC: &[u8; 8] = b"NQSIG\r\n\x1a";
pub const NQSIG_VERSION: u16 = 1;
pub const NQSIG_HEADER_LEN: usize = 14;
pub const NQSIG_MAX_FILE_LEN: usize = 65_536;
pub const NQSIG_PUBLIC_KEY_LEN: usize = 1_952;
pub const NQSIG_SIGNATURE_LEN: usize = 3_309;
pub const NQSIG_DIGEST_LEN: usize = 32;
pub const NQSIG_ID_LEN: usize = 16;
pub const NQSIG_ML_DSA_65: u64 = 1;
pub const NQSIG_SHA_256: u64 = 1;
pub const NQSIG_MANIFEST_VERSION: u64 = 1;
pub const NQSIG_DOMAIN: &[u8] = b"NEXUS-Q-SIGN-DOCUMENT\0V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NqsigManifest {
    pub signature_algorithm: u64,
    pub digest_algorithm: u64,
    pub document_digest: [u8; NQSIG_DIGEST_LEN],
    pub identity_id: [u8; NQSIG_ID_LEN],
    pub key_id: [u8; NQSIG_ID_LEN],
    pub created_at: u64,
}

impl NqsigManifest {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        push_map(&mut out, 7);
        push_uint(&mut out, 1);
        push_uint(&mut out, NQSIG_MANIFEST_VERSION);
        push_uint(&mut out, 2);
        push_uint(&mut out, self.signature_algorithm);
        push_uint(&mut out, 3);
        push_uint(&mut out, self.digest_algorithm);
        push_uint(&mut out, 4);
        push_bytes(&mut out, &self.document_digest);
        push_uint(&mut out, 5);
        push_bytes(&mut out, &self.identity_id);
        push_uint(&mut out, 6);
        push_bytes(&mut out, &self.key_id);
        push_uint(&mut out, 7);
        push_uint(&mut out, self.created_at);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, NqsigError> {
        let mut r = CborReader::new(bytes);
        r.expect_map(7)?;
        r.expect_key(1)?;
        if r.read_uint()? != NQSIG_MANIFEST_VERSION {
            return Err(NqsigError::UnsupportedVersion);
        }
        r.expect_key(2)?;
        let signature_algorithm = r.read_uint()?;
        if signature_algorithm != NQSIG_ML_DSA_65 {
            return Err(NqsigError::UnsupportedAlgorithm);
        }
        r.expect_key(3)?;
        let digest_algorithm = r.read_uint()?;
        if digest_algorithm != NQSIG_SHA_256 {
            return Err(NqsigError::UnsupportedAlgorithm);
        }
        r.expect_key(4)?;
        let document_digest = r.read_fixed_bytes()?;
        r.expect_key(5)?;
        let identity_id = r.read_fixed_bytes()?;
        r.expect_key(6)?;
        let key_id = r.read_fixed_bytes()?;
        r.expect_key(7)?;
        let created_at = r.read_uint()?;
        r.finish()?;
        Ok(Self {
            signature_algorithm,
            digest_algorithm,
            document_digest,
            identity_id,
            key_id,
            created_at,
        })
    }

    /// Exact bytes authenticated by ML-DSA-65 pure mode.
    pub fn signing_message(&self) -> Result<Vec<u8>, NqsigError> {
        if self.signature_algorithm != NQSIG_ML_DSA_65 || self.digest_algorithm != NQSIG_SHA_256 {
            return Err(NqsigError::UnsupportedAlgorithm);
        }
        let manifest = self.encode();
        let mut message = Vec::with_capacity(NQSIG_DOMAIN.len() + manifest.len());
        message.extend_from_slice(NQSIG_DOMAIN);
        message.extend_from_slice(&manifest);
        Ok(message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NqsigEnvelope {
    pub manifest: NqsigManifest,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NqsigError {
    #[error("NQSIG sidecar exceeds the maximum size")]
    TooLarge,
    #[error("invalid NQSIG magic")]
    InvalidMagic,
    #[error("unsupported NQSIG version")]
    UnsupportedVersion,
    #[error("unsupported NQSIG algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid NQSIG payload length")]
    InvalidPayloadLength,
    #[error("malformed or non-canonical NQSIG CBOR")]
    MalformedCbor,
    #[error("invalid NQSIG field length")]
    InvalidFieldLength,
}

impl NqsigEnvelope {
    /// Encode a complete v1 sidecar with deterministic CBOR and exact framing.
    pub fn encode(&self) -> Result<Vec<u8>, NqsigError> {
        if self.public_key.len() != NQSIG_PUBLIC_KEY_LEN
            || self.signature.len() != NQSIG_SIGNATURE_LEN
        {
            return Err(NqsigError::InvalidFieldLength);
        }
        if self.manifest.signature_algorithm != NQSIG_ML_DSA_65
            || self.manifest.digest_algorithm != NQSIG_SHA_256
        {
            return Err(NqsigError::UnsupportedAlgorithm);
        }

        let manifest = self.manifest.encode();
        let mut payload =
            Vec::with_capacity(manifest.len() + self.public_key.len() + self.signature.len() + 16);
        push_map(&mut payload, 3);
        push_uint(&mut payload, 1);
        push_bytes(&mut payload, &manifest);
        push_uint(&mut payload, 2);
        push_bytes(&mut payload, &self.public_key);
        push_uint(&mut payload, 3);
        push_bytes(&mut payload, &self.signature);

        let total_len = NQSIG_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(NqsigError::TooLarge)?;
        if total_len > NQSIG_MAX_FILE_LEN || payload.len() > u32::MAX as usize {
            return Err(NqsigError::TooLarge);
        }
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(NQSIG_MAGIC);
        out.extend_from_slice(&NQSIG_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Strictly decode a sidecar. All framing and CBOR fields are bounded and exact.
    pub fn decode(bytes: &[u8]) -> Result<Self, NqsigError> {
        if bytes.len() > NQSIG_MAX_FILE_LEN {
            return Err(NqsigError::TooLarge);
        }
        if bytes.len() < NQSIG_HEADER_LEN {
            return Err(NqsigError::InvalidPayloadLength);
        }
        if &bytes[..8] != NQSIG_MAGIC {
            return Err(NqsigError::InvalidMagic);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != NQSIG_VERSION {
            return Err(NqsigError::UnsupportedVersion);
        }
        let payload_len = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
        if payload_len == 0 || payload_len != bytes.len() - NQSIG_HEADER_LEN {
            return Err(NqsigError::InvalidPayloadLength);
        }

        let mut r = CborReader::new(&bytes[NQSIG_HEADER_LEN..]);
        r.expect_map(3)?;
        r.expect_key(1)?;
        let manifest_bytes = r.read_bytes()?;
        let manifest = NqsigManifest::decode(manifest_bytes)?;
        r.expect_key(2)?;
        let public_key = r.read_bytes()?.to_vec();
        if public_key.len() != NQSIG_PUBLIC_KEY_LEN {
            return Err(NqsigError::InvalidFieldLength);
        }
        r.expect_key(3)?;
        let signature = r.read_bytes()?.to_vec();
        if signature.len() != NQSIG_SIGNATURE_LEN {
            return Err(NqsigError::InvalidFieldLength);
        }
        r.finish()?;
        Ok(Self {
            manifest,
            public_key,
            signature,
        })
    }
}

fn push_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => out.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn push_uint(out: &mut Vec<u8>, value: u64) {
    push_head(out, 0, value);
}

fn push_map(out: &mut Vec<u8>, len: u64) {
    push_head(out, 5, len);
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct CborReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], NqsigError> {
        let end = self.pos.checked_add(len).ok_or(NqsigError::MalformedCbor)?;
        if end > self.bytes.len() {
            return Err(NqsigError::MalformedCbor);
        }
        let value = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(value)
    }

    fn read_head(&mut self) -> Result<(u8, u64), NqsigError> {
        let first = *self.take(1)?.first().ok_or(NqsigError::MalformedCbor)?;
        let major = first >> 5;
        let additional = first & 0x1f;
        let value = match additional {
            0..=23 => additional as u64,
            24 => {
                let n = self.take(1)?[0] as u64;
                if n < 24 {
                    return Err(NqsigError::MalformedCbor);
                }
                n
            }
            25 => {
                let b = self.take(2)?;
                let n = u16::from_be_bytes([b[0], b[1]]) as u64;
                if n <= 0xff {
                    return Err(NqsigError::MalformedCbor);
                }
                n
            }
            26 => {
                let b = self.take(4)?;
                let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if n <= 0xffff {
                    return Err(NqsigError::MalformedCbor);
                }
                n
            }
            27 => {
                let b = self.take(8)?;
                let n = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if n <= 0xffff_ffff {
                    return Err(NqsigError::MalformedCbor);
                }
                n
            }
            _ => return Err(NqsigError::MalformedCbor),
        };
        Ok((major, value))
    }

    fn expect_map(&mut self, expected: u64) -> Result<(), NqsigError> {
        let (major, len) = self.read_head()?;
        if major != 5 || len != expected {
            return Err(NqsigError::MalformedCbor);
        }
        Ok(())
    }

    fn expect_key(&mut self, expected: u64) -> Result<(), NqsigError> {
        if self.read_uint()? != expected {
            return Err(NqsigError::MalformedCbor);
        }
        Ok(())
    }

    fn read_uint(&mut self) -> Result<u64, NqsigError> {
        let (major, value) = self.read_head()?;
        if major != 0 {
            return Err(NqsigError::MalformedCbor);
        }
        Ok(value)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], NqsigError> {
        let (major, len) = self.read_head()?;
        if major != 2 {
            return Err(NqsigError::MalformedCbor);
        }
        let len = usize::try_from(len).map_err(|_| NqsigError::MalformedCbor)?;
        self.take(len)
    }

    fn read_fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], NqsigError> {
        let bytes = self.read_bytes()?;
        if bytes.len() != N {
            return Err(NqsigError::InvalidFieldLength);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn finish(&self) -> Result<(), NqsigError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(NqsigError::MalformedCbor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> NqsigEnvelope {
        NqsigEnvelope {
            manifest: NqsigManifest {
                signature_algorithm: NQSIG_ML_DSA_65,
                digest_algorithm: NQSIG_SHA_256,
                document_digest: [0x11; NQSIG_DIGEST_LEN],
                identity_id: [0x22; NQSIG_ID_LEN],
                key_id: [0x33; NQSIG_ID_LEN],
                created_at: 1_800_000_000,
            },
            public_key: vec![0x44; NQSIG_PUBLIC_KEY_LEN],
            signature: vec![0x55; NQSIG_SIGNATURE_LEN],
        }
    }

    #[test]
    fn sidecar_roundtrips_byte_for_byte() {
        let original = fixture();
        let encoded = original.encode().unwrap();
        assert_eq!(&encoded[..8], NQSIG_MAGIC);
        assert_eq!(u16::from_be_bytes([encoded[8], encoded[9]]), 1);
        let decoded = NqsigEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn rejects_framing_mutations_and_trailing_bytes() {
        let encoded = fixture().encode().unwrap();
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            NqsigEnvelope::decode(&bad_magic),
            Err(NqsigError::InvalidMagic)
        );

        let mut bad_len = encoded.clone();
        bad_len[13] ^= 1;
        assert_eq!(
            NqsigEnvelope::decode(&bad_len),
            Err(NqsigError::InvalidPayloadLength)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            NqsigEnvelope::decode(&trailing),
            Err(NqsigError::InvalidPayloadLength)
        );
    }

    #[test]
    fn rejects_unsupported_version_empty_payload_and_oversized_sidecar() {
        let mut unsupported = fixture().encode().unwrap();
        unsupported[9] = 2;
        assert_eq!(
            NqsigEnvelope::decode(&unsupported),
            Err(NqsigError::UnsupportedVersion)
        );

        let mut empty_payload = NQSIG_MAGIC.to_vec();
        empty_payload.extend_from_slice(&NQSIG_VERSION.to_be_bytes());
        empty_payload.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            NqsigEnvelope::decode(&empty_payload),
            Err(NqsigError::InvalidPayloadLength)
        );

        let oversized = vec![0u8; NQSIG_MAX_FILE_LEN + 1];
        assert_eq!(NqsigEnvelope::decode(&oversized), Err(NqsigError::TooLarge));
    }

    #[test]
    fn rejects_non_minimal_cbor_integer() {
        // Top-level map length 3 must be encoded as 0xa3, not 0xb8 0x03.
        let mut encoded = fixture().encode().unwrap();
        encoded[NQSIG_HEADER_LEN] = 0xb8;
        encoded.insert(NQSIG_HEADER_LEN + 1, 0x03);
        let len = (encoded.len() - NQSIG_HEADER_LEN) as u32;
        encoded[10..14].copy_from_slice(&len.to_be_bytes());
        assert_eq!(
            NqsigEnvelope::decode(&encoded),
            Err(NqsigError::MalformedCbor)
        );
    }

    #[test]
    fn rejects_wrong_key_and_signature_lengths() {
        let mut bad_key = fixture();
        bad_key.public_key.pop();
        assert_eq!(bad_key.encode(), Err(NqsigError::InvalidFieldLength));
        let mut bad_sig = fixture();
        bad_sig.signature.pop();
        assert_eq!(bad_sig.encode(), Err(NqsigError::InvalidFieldLength));
    }

    #[test]
    fn signing_message_has_fixed_domain_and_manifest_bytes() {
        let manifest = fixture().manifest;
        let message = manifest.signing_message().unwrap();
        assert!(message.starts_with(NQSIG_DOMAIN));
        assert_eq!(message.len(), NQSIG_DOMAIN.len() + manifest.encode().len());
        assert_eq!(NQSIG_DOMAIN.len(), 25);
    }
}
