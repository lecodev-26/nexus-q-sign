#[cfg(test)]
mod tests {
    use nexusq_core::crypto::pq_sign::{
        MlDsa65KeyPair, MlDsa65VerifyingKey,
        ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN,
        ML_DSA_65_SIGNATURE_LEN,
    };

    #[test]
    fn mldsa65_document_manifest_sign_verify_and_tamper_rejection() {
        let manifest = b"NEXUS-Q-SIGN\0NQSIG\0v1\0sha256:demo-digest";
        let pair = MlDsa65KeyPair::try_generate().expect("key generation");
        let public_key = pair.public_key();
        let secret_seed = pair.secret_key();
        assert_eq!(public_key.len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(secret_seed.len(), ML_DSA_65_SECRET_KEY_LEN);

        let signature = pair.try_sign(manifest).expect("signing");
        assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_LEN);
        let verifier = MlDsa65VerifyingKey::from_public_key(&public_key).expect("public key");
        verifier.verify(manifest, &signature).expect("valid signature");

        let mut altered = manifest.to_vec();
        altered.push(b'!');
        assert!(verifier.verify(&altered, &signature).is_err());
        let mut altered_signature = signature.clone();
        altered_signature[0] ^= 1;
        assert!(verifier.verify(manifest, &altered_signature).is_err());

        let restored = MlDsa65KeyPair::from_secret_key(&secret_seed).expect("restore from seed");
        let restored_signature = restored.try_sign(manifest).expect("sign after restore");
        verifier.verify(manifest, &restored_signature).expect("restored key matches public key");
    }
}
