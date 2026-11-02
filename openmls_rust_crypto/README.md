# SchwarzDigits fork: openmls_rust_crypto on the p256 0.14 line

This branch (`schwarzdigits/openmls-0.9`) carries the SchwarzDigits changes
on the openmls 0.9 release line; the fork's `main` tracks upstream and the
other branches are upstream pull requests in flight. For this crate the
branch is the 0.6.0 release plus upstream's crypto-crate migration
(openmls/openmls#2249, commit 055a2b4b0: `p256` / `p384` 0.14,
`ed25519-dalek` 3, `rand_core` 0.10, the RustCrypto 0.11 line) and the
`hpke-rs` 0.7 → 0.8 lines of upstream commit e0b21a70a, which together
leave `crypto-bigint` 0.5 (RUSTSEC-2026-0387) ahead of an openmls release;
`openmls_traits` and `openmls_memory_storage` come from crates.io instead
of the workspace path, so a consumer on the crates.io openmls 0.9 line
holds the trait crate once. The code is upstream's. The branch is consumed
as a git dependency by its tag.

---

# Rust Crypto Backend

This crate implements the [OpenMLS traits](../traits/README.md) using the following rust crates: [hkdf], [hpke-rs], [sha2], [p256], [p384], [x25519-dalek], [ed25519-dalek] [chacha20poly1305], [aes-gcm].

[hkdf]: https://docs.rs/hkdf
[hpke-rs]: https://docs.rs/hpke-rs
[sha2]: https://docs.rs/sha2
[p256]: https://docs.rs/p256
[p384]: https://docs.rs/p384
[x25519-dalek]: https://docs.rs/x25519-dalek
[ed25519-dalek]: https://docs.rs/ed25519-dalek
[chacha20poly1305]: https://docs.rs/chacha20poly1305
[aes-gcm]: https://docs.rs/aes-gcm
