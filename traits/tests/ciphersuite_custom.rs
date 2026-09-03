//! Custom ciphersuites: what `Ciphersuite::custom` accepts, and that a custom
//! ciphersuite survives the same three codecs as the built-in ones.

use openmls_traits::types::{
    AeadType, Ciphersuite, CiphersuiteParams, CustomCiphersuiteError, HashType, HpkeKdfType,
    HpkeKemType, SignatureScheme,
};

const PARAMS: CiphersuiteParams = CiphersuiteParams {
    kem: HpkeKemType::DhKemP256,
    kdf: HpkeKdfType::HkdfSha256,
    aead: AeadType::ChaCha20Poly1305,
    hash: HashType::Sha2_256,
    signature: SignatureScheme::ECDSA_SECP256R1_SHA256,
};

/// A custom ciphersuite can be a `const`.
const CUSTOM: Ciphersuite = Ciphersuite::custom(0xF0F0, PARAMS);

#[test]
fn custom_carries_its_parameters() {
    assert_eq!(CUSTOM.id(), 0xF0F0);
    assert!(!CUSTOM.is_builtin());
    assert_eq!(CUSTOM.params(), PARAMS);
    assert_eq!(CUSTOM.hpke_kem_algorithm(), HpkeKemType::DhKemP256);
    assert_eq!(CUSTOM.aead_algorithm(), AeadType::ChaCha20Poly1305);
    assert_eq!(
        CUSTOM.signature_algorithm(),
        SignatureScheme::ECDSA_SECP256R1_SHA256
    );
    assert_eq!(format!("{CUSTOM:?}"), "Ciphersuite(0xf0f0)");
    assert!(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.is_builtin());
}

#[test]
fn rejected_code_points() {
    let err = |id| Ciphersuite::try_custom(id, PARAMS).unwrap_err();
    assert_eq!(err(0x0002), CustomCiphersuiteError::OutsidePrivateUse);
    assert_eq!(err(0xEFFF), CustomCiphersuiteError::OutsidePrivateUse);
    // GREASE values all lie below the private use range; 0xFAFA is not one
    // of them (RFC 9420, Section 13.5) and is a valid private use code point.
    assert_eq!(err(0x0A0A), CustomCiphersuiteError::OutsidePrivateUse);
    assert!(Ciphersuite::try_custom(0xFAFA, PARAMS).is_ok());
    assert!(Ciphersuite::try_custom(0xF000, PARAMS).is_ok());
    assert!(Ciphersuite::try_custom(0xFFFF, PARAMS).is_ok());
}

#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
#[test]
fn builtin_code_point_in_private_range_is_rejected() {
    // MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519 sits at 0xF042.
    assert_eq!(
        Ciphersuite::try_custom(0xF042, PARAMS).unwrap_err(),
        CustomCiphersuiteError::BuiltIn
    );
}

#[test]
fn equality_is_on_the_code_point() {
    let other = Ciphersuite::try_custom(
        0xF0F0,
        CiphersuiteParams {
            hash: HashType::Sha2_512,
            ..PARAMS
        },
    )
    .unwrap();
    assert_eq!(CUSTOM, other);
    assert_ne!(CUSTOM, Ciphersuite::try_custom(0xF0F1, PARAMS).unwrap());
}

#[test]
fn custom_round_trips_through_serde() {
    let json = serde_json::to_string(&CUSTOM).unwrap();
    assert!(json.starts_with("{\"Custom\":"), "{json}");
    assert_eq!(serde_json::from_str::<Ciphersuite>(&json).unwrap(), CUSTOM);
    assert_eq!(
        serde_json::from_str::<Ciphersuite>(&json).unwrap().params(),
        PARAMS
    );

    let bytes = postcard::to_allocvec(&CUSTOM).unwrap();
    // The `Custom` variant has a fixed index, 0xFFFF, so that it does not
    // move when a feature adds built-in ciphersuites.
    assert_eq!(
        &bytes[..3],
        postcard::to_allocvec(&0xFFFFu32).unwrap().as_slice()
    );
    let back: Ciphersuite = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, CUSTOM);
    assert_eq!(back.params(), PARAMS);

    let mut cbor = Vec::new();
    ciborium::into_writer(&CUSTOM, &mut cbor).unwrap();
    let back: Ciphersuite = ciborium::from_reader(cbor.as_slice()).unwrap();
    assert_eq!(back, CUSTOM);
    assert_eq!(back.params(), PARAMS);
}

#[test]
fn stored_custom_with_a_builtin_code_point_is_rejected() {
    let json = serde_json::to_string(&CUSTOM)
        .unwrap()
        .replace("61680", "2");
    assert!(json.contains("\"id\":2"), "{json}");
    assert!(serde_json::from_str::<Ciphersuite>(&json).is_err());
}
