//! openmls stores `AeadType` and `SignatureScheme`, in AEAD keys and in
//! signature key pairs. Their serde encoding is the one
//! `#[derive(Serialize, Deserialize)]` produced while they were enums: the
//! variant name for self-describing formats, the declaration index for
//! compact ones. The TLS encoding of `SignatureScheme` is its code point.
//! These values are pinned here so that stored data keeps loading.

use openmls_traits::types::{AeadType, SignatureScheme};
use tls_codec::{Deserialize as _, Serialize as _};

/// Value, former declaration index, former variant name.
const AEADS: &[(AeadType, u32, &str)] = &[
    (AeadType::Aes128Gcm, 0, "Aes128Gcm"),
    (AeadType::Aes256Gcm, 1, "Aes256Gcm"),
    (AeadType::ChaCha20Poly1305, 2, "ChaCha20Poly1305"),
];

const SCHEMES: &[(SignatureScheme, u32, &str)] = &[
    (
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        0,
        "ECDSA_SECP256R1_SHA256",
    ),
    (
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        1,
        "ECDSA_SECP384R1_SHA384",
    ),
    (
        SignatureScheme::ECDSA_SECP521R1_SHA512,
        2,
        "ECDSA_SECP521R1_SHA512",
    ),
    (SignatureScheme::ED25519, 3, "ED25519"),
    (SignatureScheme::ED448, 4, "ED448"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (SignatureScheme::MLDSA44, 5, "MLDSA44"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (SignatureScheme::MLDSA65, 6, "MLDSA65"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (SignatureScheme::MLDSA87, 7, "MLDSA87"),
];

fn check<T>(value: T, index: u32, name: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let json = serde_json::to_string(&value).unwrap();
    assert_eq!(json, format!("\"{name}\""));
    assert_eq!(serde_json::from_str::<T>(&json).unwrap(), value);

    let bytes = postcard::to_allocvec(&value).unwrap();
    assert_eq!(bytes, postcard::to_allocvec(&index).unwrap(), "{name}");
    assert_eq!(postcard::from_bytes::<T>(&bytes).unwrap(), value);

    let mut cbor = Vec::new();
    ciborium::into_writer(&value, &mut cbor).unwrap();
    let mut expected = Vec::new();
    ciborium::into_writer(name, &mut expected).unwrap();
    assert_eq!(cbor, expected, "{name}");
    assert_eq!(
        ciborium::from_reader::<T, _>(cbor.as_slice()).unwrap(),
        value
    );

    assert_eq!(format!("{value:?}"), name);
}

#[test]
fn builtin_aeads_keep_their_encoding() {
    for (aead, index, name) in AEADS {
        check(*aead, *index, name);
    }
    assert!(serde_json::from_str::<AeadType>("\"Aes192Gcm\"").is_err());
    let out_of_range = postcard::to_allocvec(&(AEADS.len() as u32)).unwrap();
    assert!(postcard::from_bytes::<AeadType>(&out_of_range).is_err());
}

#[test]
fn builtin_schemes_keep_their_encoding() {
    for (scheme, index, name) in SCHEMES {
        check(*scheme, *index, name);
    }
    let out_of_range = postcard::to_allocvec(&(SCHEMES.len() as u32)).unwrap();
    assert!(postcard::from_bytes::<SignatureScheme>(&out_of_range).is_err());
}

#[test]
fn tls_encoding_of_a_scheme_is_the_code_point() {
    for (scheme, _, _) in SCHEMES {
        let bytes = scheme.tls_serialize_detached().unwrap();
        assert_eq!(bytes, scheme.id().to_be_bytes());
        assert_eq!(
            SignatureScheme::tls_deserialize_exact(&bytes).unwrap(),
            *scheme
        );
    }
    let bytes = SignatureScheme::new(0x081A)
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(bytes, [0x08, 0x1A]);
}

#[test]
fn custom_values_round_trip() {
    let aead = AeadType::new(0x0004, 32, 16);
    let scheme = SignatureScheme::new(0x081A);

    let json = serde_json::to_string(&aead).unwrap();
    assert_eq!(
        json,
        "{\"Custom\":{\"id\":4,\"key_size\":32,\"tag_size\":16}}"
    );
    assert_eq!(serde_json::from_str::<AeadType>(&json).unwrap(), aead);
    let json = serde_json::to_string(&scheme).unwrap();
    assert_eq!(json, "{\"Custom\":2074}");
    assert_eq!(
        serde_json::from_str::<SignatureScheme>(&json).unwrap(),
        scheme
    );

    // Custom has a fixed index, 0xFFFF, that no built-in table reaches.
    let custom_index = postcard::to_allocvec(&0xFFFFu32).unwrap();
    let bytes = postcard::to_allocvec(&aead).unwrap();
    assert!(bytes.starts_with(&custom_index));
    assert_eq!(postcard::from_bytes::<AeadType>(&bytes).unwrap(), aead);
    let bytes = postcard::to_allocvec(&scheme).unwrap();
    assert!(bytes.starts_with(&custom_index));
    assert_eq!(
        postcard::from_bytes::<SignatureScheme>(&bytes).unwrap(),
        scheme
    );
}
