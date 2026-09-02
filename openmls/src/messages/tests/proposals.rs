use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    group::{
        errors::ValidationError,
        tests_and_kats::utils::{generate_credential_with_key, generate_key_package},
    },
    messages::{
        proposals::{AddProposal, Proposal, ProposalOrRef, RemoveProposal},
        proposals_in::{AddProposalIn, ProposalOrRefIn},
    },
    prelude::{Extensions, KeyPackage, KeyPackageIn, ProtocolVersion},
};

/// This test encodes and decodes the `ProposalOrRef` struct and makes sure the
/// decoded values are the same as the original
#[openmls_test::openmls_test]
fn proposals_codec() {
    let provider = &Provider::default();
    // Proposal

    let remove_proposal = RemoveProposal {
        removed: LeafNodeIndex::new(72549),
    };
    let proposal = Proposal::remove(remove_proposal);
    let proposal_or_ref = ProposalOrRef::proposal(proposal.clone());
    let encoded = proposal_or_ref
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = ProposalOrRefIn::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(proposal_or_ref, decoded.into());

    // Reference

    let reference = ProposalRef::from_raw_proposal(ciphersuite, provider.crypto(), &proposal)
        .expect("An unexpected error occurred.");
    let proposal_or_ref = ProposalOrRef::reference(reference);
    let encoded = proposal_or_ref
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = ProposalOrRefIn::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(proposal_or_ref, decoded.into());
}

#[test]
fn add_proposal_checks_ciphersuite_before_signature() {
    let provider = &OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

    let credential =
        generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), provider);
    let key_package = generate_key_package(ciphersuite, Extensions::empty(), provider, credential);

    // Corrupt the signature, the last field on the wire.
    let mut bytes = key_package.key_package().tls_serialize_detached().unwrap();
    *bytes.last_mut().unwrap() ^= 0x01;
    let key_package: KeyPackage = KeyPackageIn::tls_deserialize_exact(bytes.as_slice())
        .unwrap()
        .into();
    let add: Box<AddProposalIn> = AddProposal::from(key_package).into();

    let err = add
        .validate(provider.crypto(), ProtocolVersion::Mls10, group_ciphersuite)
        .unwrap_err();
    assert_eq!(err, ValidationError::InvalidAddProposalCiphersuite);
}

/// A ReInit proposal is resolved with the crypto provider when it is
/// validated: a GREASE value, an unknown code point and a built-in
/// ciphersuite the provider does not support are all rejected.
#[test]
fn reinit_proposal_resolves_its_ciphersuite() {
    use openmls_traits::{types::VerifiableCiphersuite, OpenMlsProvider};

    use crate::{
        group::{errors::ValidationError, GroupId},
        messages::proposals_in::ReInitProposalIn,
        test_utils::restricted_provider::RestrictedProvider,
    };

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let reinit = |wire: VerifiableCiphersuite| ReInitProposalIn {
        group_id: GroupId::from_slice(b"reinit"),
        version: ProtocolVersion::default(),
        ciphersuite: wire,
        extensions: Extensions::empty(),
    };

    let provider = RestrictedProvider::new(vec![ciphersuite]);
    assert_eq!(
        reinit(ciphersuite.into())
            .validate(provider.crypto())
            .unwrap()
            .ciphersuite,
        ciphersuite
    );
    for wire in [
        VerifiableCiphersuite::new(0x0A0A),
        VerifiableCiphersuite::new(0xF0F0),
        VerifiableCiphersuite::new(u16::from(
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        )),
    ] {
        assert!(matches!(
            reinit(wire).validate(provider.crypto()),
            Err(ValidationError::InvalidReInitCiphersuite)
        ));
    }
}
