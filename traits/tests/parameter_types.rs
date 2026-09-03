//! The parameter types of a ciphersuite are code points; the built-in values
//! are constants.

use openmls_traits::types::{
    AeadType, Ciphersuite, CiphersuiteParams, HashType, HpkeAeadType, HpkeKdfType, HpkeKemType,
    SignatureScheme,
};

#[test]
fn builtin_code_points() {
    assert_eq!(HpkeKemType::DhKemP256.id(), 0x0010);
    assert_eq!(HpkeKemType::DhKemP384.id(), 0x0011);
    assert_eq!(HpkeKemType::DhKemP521.id(), 0x0012);
    assert_eq!(HpkeKemType::DhKem25519.id(), 0x0020);
    assert_eq!(HpkeKemType::DhKem448.id(), 0x0021);
    assert_eq!(HpkeKemType::new(0x0010), HpkeKemType::DhKemP256);
}

#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
#[test]
fn pq_code_points() {
    assert_eq!(HpkeKemType::MlKem768.id(), 0x0041);
    assert_eq!(HpkeKemType::MlKem1024.id(), 0x0042);
}

#[test]
fn a_kem_the_library_does_not_know() {
    // ML-KEM-768 with P-256 in draft-ietf-hpke-pq.
    let kem = HpkeKemType::new(0x0050);
    assert_eq!(kem.id(), 0x0050);
    assert_ne!(kem, HpkeKemType::DhKemP256);
    assert_eq!(format!("{kem:?}"), "HpkeKemType(0x0050)");
    assert_eq!(format!("{:?}", HpkeKemType::DhKemP256), "DhKemP256");
}

#[test]
fn serde_round_trip() {
    for kem in [HpkeKemType::DhKemP256, HpkeKemType::new(0x0050)] {
        let json = serde_json::to_string(&kem).unwrap();
        assert_eq!(serde_json::from_str::<HpkeKemType>(&json).unwrap(), kem);
        let bytes = postcard::to_allocvec(&kem).unwrap();
        assert_eq!(postcard::from_bytes::<HpkeKemType>(&bytes).unwrap(), kem);
    }
}

#[test]
fn kdf_and_aead_code_points() {
    assert_eq!(HpkeKdfType::HkdfSha256.id(), 0x0001);
    assert_eq!(HpkeKdfType::HkdfSha384.id(), 0x0002);
    assert_eq!(HpkeKdfType::HkdfSha512.id(), 0x0003);
    assert_eq!(HpkeAeadType::AesGcm128.id(), 0x0001);
    assert_eq!(HpkeAeadType::AesGcm256.id(), 0x0002);
    assert_eq!(HpkeAeadType::ChaCha20Poly1305.id(), 0x0003);
    assert_eq!(HpkeAeadType::Export.id(), 0xFFFF);
    assert_eq!(
        format!("{:?}", HpkeKdfType::new(0x0010)),
        "HpkeKdfType(0x0010)"
    );
    assert_eq!(format!("{:?}", HpkeAeadType::AesGcm128), "AesGcm128");
}

#[test]
fn hash_carries_its_size() {
    // The built-in values are the TLS HashAlgorithm identifiers.
    assert_eq!(HashType::Sha2_256.id(), 4);
    assert_eq!(HashType::Sha2_384.id(), 5);
    assert_eq!(HashType::Sha2_512.id(), 6);
    assert_eq!(HashType::Sha2_256.size(), 32);
    assert_eq!(HashType::Sha2_512.size(), 64);
    let blake3 = HashType::new(0x0100, 32);
    assert_eq!(blake3.size(), 32);
    assert_eq!(format!("{blake3:?}"), "HashType(0x0100)");
    let json = serde_json::to_string(&blake3).unwrap();
    assert_eq!(serde_json::from_str::<HashType>(&json).unwrap(), blake3);
}

#[test]
fn aead_carries_its_sizes() {
    // The built-in values are the HPKE AEAD identifiers.
    assert_eq!(AeadType::Aes128Gcm.id(), 0x0001);
    assert_eq!(AeadType::Aes256Gcm.id(), 0x0002);
    assert_eq!(AeadType::ChaCha20Poly1305.id(), 0x0003);
    assert_eq!(AeadType::Aes128Gcm.key_size(), 16);
    assert_eq!(AeadType::Aes256Gcm.key_size(), 32);
    assert_eq!(AeadType::ChaCha20Poly1305.nonce_size(), 12);
    assert_eq!(AeadType::ChaCha20Poly1305.tag_size(), 16);
    let custom = AeadType::new(0x0004, 32, 16);
    assert_eq!(
        (custom.key_size(), custom.nonce_size(), custom.tag_size()),
        (32, 12, 16)
    );
    assert_eq!(format!("{custom:?}"), "AeadType(0x0004)");
    // A built-in code point with other sizes is another value.
    assert_ne!(AeadType::new(0x0001, 32, 16), AeadType::Aes128Gcm);
}

#[test]
fn hpke_aead_is_the_same_code_point() {
    let suite = Ciphersuite::custom(
        0xF0F0,
        CiphersuiteParams {
            aead: AeadType::new(0x0004, 32, 16),
            ..Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.params()
        },
    );
    assert_eq!(suite.hpke_aead_algorithm(), HpkeAeadType::new(0x0004));
    assert_eq!(
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.hpke_aead_algorithm(),
        HpkeAeadType::AesGcm128
    );
}

#[test]
fn signature_scheme_code_points() {
    // The built-in values are the TLS SignatureScheme identifiers.
    assert_eq!(SignatureScheme::ECDSA_SECP256R1_SHA256.id(), 0x0403);
    assert_eq!(SignatureScheme::ECDSA_SECP384R1_SHA384.id(), 0x0503);
    assert_eq!(SignatureScheme::ECDSA_SECP521R1_SHA512.id(), 0x0603);
    assert_eq!(SignatureScheme::ED25519.id(), 0x0807);
    assert_eq!(SignatureScheme::ED448.id(), 0x0808);
    assert_eq!(
        SignatureScheme::try_from(0x0807),
        Ok(SignatureScheme::ED25519)
    );
    // ECDSA on brainpoolP256r1, RFC 8734.
    let brainpool = SignatureScheme::new(0x081A);
    assert_eq!(brainpool.id(), 0x081A);
    assert_eq!(format!("{brainpool:?}"), "SignatureScheme(0x081a)");
    assert!(SignatureScheme::try_from(0x081A).is_err());
}
