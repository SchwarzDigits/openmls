# SchwarzDigits fork: openmls_basic_credential on the p256 0.14 line

This branch (`schwarzdigits/openmls-0.9`) carries the SchwarzDigits changes
on the openmls 0.9 release line; the fork's `main` tracks upstream and the
other branches are upstream pull requests in flight. For this crate the
branch is the 0.6.0 release plus upstream's crypto-crate migration
(openmls/openmls#2249, commit 055a2b4b0: `p256` / `p384` 0.14,
`ed25519-dalek` 3, `rand_core` 0.10), which leaves `crypto-bigint` 0.5
(RUSTSEC-2026-0387) ahead of an openmls release, and `openmls_traits` from
crates.io instead of the workspace path, so a consumer on the crates.io
openmls 0.9 line holds the trait crate once. The code is upstream's. The
branch is consumed as a git dependency by its tag.

---

# Signature Keys for the Basic Credential

The basic credential in the MLS spec is only defined by its identity.
In practice the basic credential needs a key pair for signatures to be functional.
This crate implements a simple signature key pair for basic credential and
implements the `Signer` trait required by the OpenMLS APIs.
