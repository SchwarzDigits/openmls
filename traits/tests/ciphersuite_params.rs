//! The parameters of each built-in ciphersuite, as the accessor tables had
//! them while `Ciphersuite` was an enum.

use openmls_traits::types::{
    AeadType, Ciphersuite, HashType, HpkeKdfType, HpkeKemType, SignatureScheme,
};

type Row = (
    Ciphersuite,
    HpkeKemType,
    HpkeKdfType,
    AeadType,
    HashType,
    SignatureScheme,
);

const EXPECTED: &[Row] = &[
    (
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        AeadType::Aes128Gcm,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    ),
    (
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        HpkeKemType::DhKemP256,
        HpkeKdfType::HkdfSha256,
        AeadType::Aes128Gcm,
        HashType::Sha2_256,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    ),
    (
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    ),
    (
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
        HpkeKemType::DhKem448,
        HpkeKdfType::HkdfSha512,
        AeadType::Aes256Gcm,
        HashType::Sha2_512,
        SignatureScheme::ED448,
    ),
    (
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        HpkeKemType::DhKemP521,
        HpkeKdfType::HkdfSha512,
        AeadType::Aes256Gcm,
        HashType::Sha2_512,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
    ),
    (
        Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
        HpkeKemType::DhKem448,
        HpkeKdfType::HkdfSha512,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_512,
        SignatureScheme::ED448,
    ),
    (
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        HpkeKemType::DhKemP384,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha256,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
        HpkeKemType::MlKem1024,
        HpkeKdfType::HkdfSha512,
        AeadType::Aes256Gcm,
        HashType::Sha2_512,
        SignatureScheme::MLDSA87,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha256,
        AeadType::Aes128Gcm,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ED25519,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
        HpkeKemType::MlKem768,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ED25519,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
        HpkeKemType::MlKem768,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        HpkeKemType::MlKem1024,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha384,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_384,
        SignatureScheme::MLDSA44,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        HpkeKemType::MlKem768,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::MLDSA65,
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        HpkeKemType::MlKem1024,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::MLDSA87,
    ),
];

#[test]
fn builtin_parameters() {
    let builtin = (0..=u16::MAX).filter(|v| Ciphersuite::try_from(*v).is_ok());
    assert_eq!(builtin.count(), EXPECTED.len());
    for (cs, kem, kdf, aead, hash, sig) in EXPECTED {
        assert_eq!(cs.hpke_kem_algorithm(), *kem, "{cs}");
        assert_eq!(cs.hpke_kdf_algorithm(), *kdf, "{cs}");
        assert_eq!(cs.aead_algorithm(), *aead, "{cs}");
        assert_eq!(cs.hash_algorithm(), *hash, "{cs}");
        assert_eq!(cs.signature_algorithm(), *sig, "{cs}");
    }
}
