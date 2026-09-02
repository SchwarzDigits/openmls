//! The serde encoding of `Ciphersuite` is part of the storage format. It is
//! the encoding `#[derive(Serialize, Deserialize)]` produced while
//! `Ciphersuite` was an enum: the variant name for self-describing formats,
//! the declaration index for compact ones. These values are pinned here so
//! that stored group state keeps loading.

use openmls_traits::types::Ciphersuite;

/// Code point, former declaration index, former variant name.
const EXPECTED: &[(u16, u32, &str)] = &[
    (0x0001, 0, "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"),
    (0x0002, 1, "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"),
    (
        0x0003,
        2,
        "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
    ),
    (0x0004, 3, "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448"),
    (0x0005, 4, "MLS_256_DHKEMP521_AES256GCM_SHA512_P521"),
    (0x0006, 5, "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448"),
    (0x0007, 6, "MLS_256_DHKEMP384_AES256GCM_SHA384_P384"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0x004D, 7, "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0x0906, 8, "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0x004F, 9, "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        0x004E,
        10,
        "MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519",
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0xF042, 11, "MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0x0050, 12, "MLS_128_MLKEM768_AES256GCM_SHA384_P256"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0x0042, 13, "MLS_192_MLKEM1024_AES256GCM_SHA384_P384"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (
        0x0052,
        14,
        "MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44",
    ),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0x0051, 15, "MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65"),
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    (0x0907, 16, "MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87"),
];

#[test]
fn every_builtin_is_listed() {
    let builtin: Vec<u16> = (0..=u16::MAX)
        .filter(|v| Ciphersuite::try_from(*v).is_ok())
        .collect();
    let mut listed: Vec<u16> = EXPECTED.iter().map(|(cp, _, _)| *cp).collect();
    listed.sort();
    assert_eq!(builtin, listed);
}

#[test]
fn serde_json_uses_the_name() {
    for (cp, _, name) in EXPECTED {
        let cs = Ciphersuite::try_from(*cp).unwrap();
        let json = serde_json::to_string(&cs).unwrap();
        assert_eq!(json, format!("\"{name}\""), "{cp:#06x}");
        assert_eq!(serde_json::from_str::<Ciphersuite>(&json).unwrap(), cs);
    }
    assert!(serde_json::from_str::<Ciphersuite>("\"MLS_000_NOPE\"").is_err());
}

#[test]
fn postcard_uses_the_declaration_index() {
    for (cp, index, _) in EXPECTED {
        let cs = Ciphersuite::try_from(*cp).unwrap();
        let bytes = postcard::to_allocvec(&cs).unwrap();
        assert_eq!(bytes, postcard::to_allocvec(index).unwrap(), "{cp:#06x}");
        assert_eq!(postcard::from_bytes::<Ciphersuite>(&bytes).unwrap(), cs);
    }
    let out_of_range = postcard::to_allocvec(&(EXPECTED.len() as u32)).unwrap();
    assert!(postcard::from_bytes::<Ciphersuite>(&out_of_range).is_err());
}

#[test]
fn ciborium_uses_the_name() {
    for (cp, _, name) in EXPECTED {
        let cs = Ciphersuite::try_from(*cp).unwrap();
        let mut bytes = Vec::new();
        ciborium::into_writer(&cs, &mut bytes).unwrap();
        let mut expected = Vec::new();
        ciborium::into_writer(name, &mut expected).unwrap();
        assert_eq!(bytes, expected, "{cp:#06x}");
        assert_eq!(
            ciborium::from_reader::<Ciphersuite, _>(bytes.as_slice()).unwrap(),
            cs
        );
    }
}

#[test]
fn debug_prints_the_name() {
    for (cp, _, name) in EXPECTED {
        assert_eq!(format!("{:?}", Ciphersuite::try_from(*cp).unwrap()), *name);
    }
}
