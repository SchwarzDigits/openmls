//! A ciphersuite that is not built in, defined by the crypto provider, on
//! every path a ciphersuite takes: key package, group creation, Welcome,
//! external commit, key schedule, storage. Each wire path is also tried with
//! a provider that does not know the ciphersuite.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    types::{
        AeadType, Ciphersuite, CiphersuiteParams, HashType, HpkeKdfType, HpkeKemType,
        SignatureScheme, VerifiableCiphersuite,
    },
    OpenMlsProvider,
};

use crate::{
    group::{
        errors::WelcomeError,
        tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
        ExternalCommitBuilderError, MlsGroup, MlsGroupJoinConfig, StagedWelcome,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::errors::KeyPackageVerifyError,
    prelude::{
        Capabilities, KeyPackage, KeyPackageBundle, KeyPackageIn, LeafNodeParameters,
        MlsMessageBodyIn, MlsMessageIn, ProtocolVersion,
    },
    test_utils::restricted_provider::RestrictedProvider,
};

/// P-256, HKDF-SHA256, ChaCha20-Poly1305, SHA-256, ECDSA P-256. RFC 9420 has
/// no such ciphersuite; RustCrypto has every primitive in it.
const CUSTOM: Ciphersuite = Ciphersuite::custom(
    0xF0F0,
    CiphersuiteParams {
        kem: HpkeKemType::DhKemP256,
        kdf: HpkeKdfType::HkdfSha256,
        aead: AeadType::ChaCha20Poly1305,
        hash: HashType::Sha2_256,
        signature: SignatureScheme::ECDSA_SECP256R1_SHA256,
    },
);

const WIRE: VerifiableCiphersuite = VerifiableCiphersuite::new(0xF0F0);

fn provider() -> RestrictedProvider {
    RestrictedProvider::new(vec![CUSTOM])
}

fn credential(name: &str, provider: &impl OpenMlsProvider) -> CredentialWithKeyAndSigner {
    generate_credential_with_key(name.into(), CUSTOM.signature_algorithm(), provider)
}

fn key_package_for(
    provider: &RestrictedProvider,
    credential: &CredentialWithKeyAndSigner,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .leaf_node_capabilities(Capabilities::for_provider(provider.crypto()))
        .build(
            CUSTOM,
            provider,
            &credential.signer,
            credential.credential_with_key.clone(),
        )
        .unwrap()
}

fn group_for(provider: &RestrictedProvider, credential: &CredentialWithKeyAndSigner) -> MlsGroup {
    MlsGroup::builder()
        .ciphersuite(CUSTOM)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .with_capabilities(Capabilities::for_provider(provider.crypto()))
        .build(
            provider,
            &credential.signer,
            credential.credential_with_key.clone(),
        )
        .unwrap()
}

#[test]
fn key_package() {
    let bob_provider = provider();
    let bob = credential("Bob", &bob_provider);
    let bundle = key_package_for(&bob_provider, &bob);
    assert_eq!(bundle.key_package().ciphersuite(), CUSTOM);

    let validated = KeyPackageIn::from(bundle.key_package().clone())
        .validate(bob_provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    assert_eq!(validated.ciphersuite(), CUSTOM);

    let err = KeyPackageIn::from(bundle.key_package().clone())
        .validate(
            OpenMlsRustCrypto::default().crypto(),
            ProtocolVersion::Mls10,
        )
        .unwrap_err();
    assert_eq!(err, KeyPackageVerifyError::UnknownCiphersuite(WIRE));
}

#[test]
fn welcome() {
    let alice_provider = provider();
    let alice = credential("Alice", &alice_provider);
    let mut alice_group = group_for(&alice_provider, &alice);
    assert_eq!(alice_group.ciphersuite(), CUSTOM);

    let bob_provider = provider();
    let bob = credential("Bob", &bob_provider);
    let bob_key_package = key_package_for(&bob_provider, &bob);

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();
    let welcome = welcome.into_welcome().unwrap();
    assert_eq!(welcome.ciphersuite(), WIRE);

    // A provider that does not know the ciphersuite stops before it touches
    // any key material.
    let err = StagedWelcome::new_from_welcome(
        &OpenMlsRustCrypto::default(),
        &MlsGroupJoinConfig::default(),
        welcome.clone(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap_err();
    assert!(matches!(err, WelcomeError::UnknownCiphersuite(cs) if cs == WIRE));

    let bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&bob_provider)
    .unwrap();

    assert_eq!(bob_group.ciphersuite(), CUSTOM);
    assert_eq!(bob_group.epoch(), alice_group.epoch());
    assert_eq!(
        alice_group
            .export_secret(alice_provider.crypto(), "test", b"", 32)
            .unwrap(),
        bob_group
            .export_secret(bob_provider.crypto(), "test", b"", 32)
            .unwrap()
    );
}

#[test]
fn external_commit() {
    let alice_provider = provider();
    let alice = credential("Alice", &alice_provider);
    let alice_group = group_for(&alice_provider, &alice);

    let group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let ratchet_tree = alice_group.export_ratchet_tree();

    let stranger = OpenMlsRustCrypto::default();
    let charlie = credential("Charlie", &stranger);
    let err = MlsGroup::external_commit_builder()
        .with_ratchet_tree(ratchet_tree.clone().into())
        .build_group(&stranger, group_info.clone(), charlie.credential_with_key)
        .unwrap_err();
    assert!(matches!(err, ExternalCommitBuilderError::UnknownCiphersuite(cs) if cs == WIRE));

    let charlie_provider = provider();
    let charlie = credential("Charlie", &charlie_provider);
    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_capabilities(Capabilities::for_provider(charlie_provider.crypto()))
        .build();
    let (charlie_group, _commit) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(ratchet_tree.into())
        .build_group(&charlie_provider, group_info, charlie.credential_with_key)
        .unwrap()
        .leaf_node_parameters(leaf_node_parameters)
        .load_psks(charlie_provider.storage())
        .unwrap()
        .build(
            charlie_provider.rand(),
            charlie_provider.crypto(),
            &charlie.signer,
            |_| true,
        )
        .unwrap()
        .finalize(&charlie_provider)
        .unwrap();
    assert_eq!(charlie_group.ciphersuite(), CUSTOM);

    // The same from the wire form of the GroupInfo, as it arrives in an
    // `MlsMessageIn`.
    let group_info_in = || {
        let message: MlsMessageIn = alice_group
            .export_group_info(alice_provider.crypto(), &alice.signer, false)
            .unwrap()
            .into();
        match message.extract() {
            MlsMessageBodyIn::GroupInfo(group_info) => group_info,
            other => panic!("expected a GroupInfo, got {other:?}"),
        }
    };
    let ratchet_tree = alice_group.export_ratchet_tree();

    let dave = credential("Dave", &stranger);
    let err = MlsGroup::external_commit_builder()
        .with_ratchet_tree(ratchet_tree.clone().into())
        .build_group(&stranger, group_info_in(), dave.credential_with_key)
        .unwrap_err();
    assert!(matches!(err, ExternalCommitBuilderError::UnknownCiphersuite(cs) if cs == WIRE));

    let dave_provider = provider();
    let dave = credential("Dave", &dave_provider);
    let (dave_group, _commit) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(ratchet_tree.into())
        .build_group(&dave_provider, group_info_in(), dave.credential_with_key)
        .unwrap()
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(Capabilities::for_provider(dave_provider.crypto()))
                .build(),
        )
        .load_psks(dave_provider.storage())
        .unwrap()
        .build(
            dave_provider.rand(),
            dave_provider.crypto(),
            &dave.signer,
            |_| true,
        )
        .unwrap()
        .finalize(&dave_provider)
        .unwrap();
    assert_eq!(dave_group.ciphersuite(), CUSTOM);
}

#[test]
fn storage() {
    let alice_provider = provider();
    let alice = credential("Alice", &alice_provider);
    let alice_group = group_for(&alice_provider, &alice);

    let loaded = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
        .unwrap()
        .unwrap();
    assert_eq!(loaded.ciphersuite(), CUSTOM);
    assert_eq!(loaded.ciphersuite().params(), CUSTOM.params());
}

/// A ciphersuite on a KEM the provider does not implement is not a panic
/// anywhere, but an error from the first HPKE operation.
#[test]
fn unknown_kem() {
    use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};

    // ML-KEM-768 with P-256, draft-ietf-hpke-pq.
    let params = CiphersuiteParams {
        kem: HpkeKemType::new(0x0050),
        ..CUSTOM.params()
    };
    let suite = Ciphersuite::custom(0xF0F1, params);
    let provider = RestrictedProvider::new(vec![suite]);

    let err = provider
        .crypto()
        .derive_hpke_keypair(suite.hpke_config(), &[0u8; 32])
        .unwrap_err();
    assert_eq!(err, CryptoError::UnsupportedKem);

    let alice = credential("Alice", &provider);
    assert!(MlsGroup::builder()
        .ciphersuite(suite)
        .with_capabilities(Capabilities::for_provider(provider.crypto()))
        .build(&provider, &alice.signer, alice.credential_with_key)
        .is_err());
}

/// A ciphersuite on a hash the provider does not implement, the example that
/// opened openmls#1915, is rejected by the provider's hash call, and group
/// creation fails with that instead of panicking.
#[test]
fn unknown_hash() {
    use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};

    let params = CiphersuiteParams {
        hash: HashType::new(0x0100, 32),
        ..CUSTOM.params()
    };
    let suite = Ciphersuite::custom(0xF0F2, params);
    let provider = RestrictedProvider::new(vec![suite]);
    assert_eq!(suite.hash_length(), 32);
    assert_eq!(
        provider
            .crypto()
            .hash(suite.hash_algorithm(), b"")
            .unwrap_err(),
        CryptoError::UnsupportedHashAlgorithm
    );

    let alice = credential("Alice", &provider);
    assert!(MlsGroup::builder()
        .ciphersuite(suite)
        .with_capabilities(Capabilities::for_provider(provider.crypto()))
        .build(&provider, &alice.signer, alice.credential_with_key)
        .is_err());
}

/// A ciphersuite on an AEAD the provider does not implement is rejected by
/// the provider's encryption call rather than panicking.
#[test]
fn unknown_aead() {
    use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};

    let params = CiphersuiteParams {
        aead: AeadType::new(0x0004, 32, 16),
        ..CUSTOM.params()
    };
    let suite = Ciphersuite::custom(0xF0F3, params);
    let provider = RestrictedProvider::new(vec![suite]);
    assert_eq!(suite.aead_key_length(), 32);
    assert_eq!(
        provider
            .crypto()
            .aead_encrypt(suite.aead_algorithm(), &[0u8; 32], b"", &[0u8; 12], b"")
            .unwrap_err(),
        CryptoError::UnsupportedAeadAlgorithm
    );
}

/// A ciphersuite on a signature scheme the provider does not implement, ECDSA
/// on brainpoolP256r1 from RFC 8734, is rejected at key generation.
#[test]
fn unknown_signature_scheme() {
    use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};

    let params = CiphersuiteParams {
        signature: SignatureScheme::new(0x081A),
        ..CUSTOM.params()
    };
    let suite = Ciphersuite::custom(0xF0F4, params);
    let provider = RestrictedProvider::new(vec![suite]);
    assert_eq!(
        provider
            .crypto()
            .signature_key_gen(suite.signature_algorithm())
            .unwrap_err(),
        CryptoError::UnsupportedSignatureScheme
    );
}
