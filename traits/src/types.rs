//! # OpenMLS Types
//!
//! This module holds a number of types that are needed by the traits.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tls_codec::{
    SecretVLBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSerializeBytes, TlsSize,
    VLBytes,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,
}

impl AeadType {
    /// Get the tag size of the [`AeadType`] in bytes.
    pub const fn tag_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
        }
    }

    /// Get the key size of the [`AeadType`] in bytes.
    pub const fn key_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size of the [`AeadType`] in bytes.
    pub const fn nonce_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm | AeadType::Aes256Gcm | AeadType::ChaCha20Poly1305 => 12,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[allow(non_camel_case_types)]
/// Hash types
pub enum HashType {
    Sha2_256 = 0x04,
    Sha2_384 = 0x05,
    Sha2_512 = 0x06,
}

impl HashType {
    /// Returns the output size of a hash by [`HashType`].
    #[inline]
    pub const fn size(&self) -> usize {
        match self {
            HashType::Sha2_256 => 32,
            HashType::Sha2_384 => 48,
            HashType::Sha2_512 => 64,
        }
    }
}

/// SignatureScheme according to IANA TLS parameters
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Copy,
    Hash,
    Eq,
    PartialEq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsSerializeBytes,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[repr(u16)]
pub enum SignatureScheme {
    /// ECDSA_SECP256R1_SHA256
    ECDSA_SECP256R1_SHA256 = 0x0403,
    /// ECDSA_SECP384R1_SHA384
    ECDSA_SECP384R1_SHA384 = 0x0503,
    /// ECDSA_SECP521R1_SHA512
    ECDSA_SECP521R1_SHA512 = 0x0603,
    /// ED25519
    ED25519 = 0x0807,
    /// ED448
    ED448 = 0x0808,
    /// ML-DSA44
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLDSA44 = 0x0904,
    /// ML-DSA65
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLDSA65 = 0x0905,
    /// ML-DSA87
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MLDSA87 = 0x0906,
}

impl TryFrom<u16> for SignatureScheme {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0403 => Ok(SignatureScheme::ECDSA_SECP256R1_SHA256),
            0x0503 => Ok(SignatureScheme::ECDSA_SECP384R1_SHA384),
            0x0603 => Ok(SignatureScheme::ECDSA_SECP521R1_SHA512),
            0x0807 => Ok(SignatureScheme::ED25519),
            0x0808 => Ok(SignatureScheme::ED448),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            0x0904 => Ok(SignatureScheme::MLDSA44),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            0x0905 => Ok(SignatureScheme::MLDSA65),
            #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
            0x0906 => Ok(SignatureScheme::MLDSA87),
            _ => Err(format!("Unsupported SignatureScheme: {value}")),
        }
    }
}

/// Crypto errors.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CryptoError {
    CryptoLibraryError,
    AeadDecryptionError,
    HpkeDecryptionError,
    HpkeEncryptionError,
    UnsupportedSignatureScheme,
    KdfLabelTooLarge,
    KdfSerializationError,
    HkdfOutputLengthInvalid,
    InsufficientRandomness,
    InvalidSignature,
    UnsupportedAeadAlgorithm,
    UnsupportedKdf,
    InvalidLength,
    UnsupportedHashAlgorithm,
    SignatureEncodingError,
    SignatureDecodingError,
    SenderSetupError,
    ReceiverSetupError,
    ExporterError,
    UnsupportedCiphersuite,
    TlsSerializationError,
    TooMuchData,
    SigningError,
    InvalidPublicKey,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CryptoError {}

// === HPKE === //

/// Convenience tuple struct for an HPKE configuration.
#[derive(Debug)]
pub struct HpkeConfig(pub HpkeKemType, pub HpkeKdfType, pub HpkeAeadType);

/// KEM Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKemType {
    /// DH KEM on P256
    DhKemP256 = 0x0010,

    /// DH KEM on P384
    DhKemP384 = 0x0011,

    /// DH KEM on P521
    DhKemP521 = 0x0012,

    /// DH KEM on x25519
    DhKem25519 = 0x0020,

    /// DH KEM on x448
    DhKem448 = 0x0021,

    /// ML-KEM-768
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MlKem768 = 0x0041,

    /// ML-KEM-1024
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    MlKem1024 = 0x0042,

    /// XWing combiner for ML-KEM and X25519
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    XWingKemDraft6 = 0x004D,
}

/// KDF Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKdfType {
    /// HKDF SHA 256
    HkdfSha256 = 0x0001,

    /// HKDF SHA 384
    HkdfSha384 = 0x0002,

    /// HKDF SHA 512
    HkdfSha512 = 0x0003,
}

/// AEAD Types for HPKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeAeadType {
    /// AES GCM 128
    AesGcm128 = 0x0001,

    /// AES GCM 256
    AesGcm256 = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// Export-only
    Export = 0xFFFF,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<V>;
///     opaque ciphertext<V>;
/// } HPKECiphertext;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct HpkeCiphertext {
    pub kem_output: VLBytes,
    pub ciphertext: VLBytes,
}

/// A simple type for HPKE private keys.
#[derive(
    Clone,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[cfg_attr(feature = "test-utils", derive(PartialEq, Eq))]
#[serde(transparent)]
pub struct HpkePrivateKey(SecretVLBytes);

impl std::fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dt = f.debug_tuple("HpkePrivateKey");

        #[cfg(feature = "crypto-debug")]
        dt.field(&self.0);
        #[cfg(not(feature = "crypto-debug"))]
        dt.field(&"***");

        dt.finish()
    }
}

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }
}

impl From<&[u8]> for HpkePrivateKey {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl std::ops::Deref for HpkePrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

/// Helper holding a (private, public) key pair as byte vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeKeyPair {
    pub private: HpkePrivateKey,
    pub public: Vec<u8>,
}

pub type KemOutput = Vec<u8>;
#[derive(Clone)]
pub struct ExporterSecret(SecretVLBytes);

impl std::fmt::Debug for ExporterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dt = f.debug_tuple("ExporterSecret");

        #[cfg(feature = "crypto-debug")]
        dt.field(&self.0);
        #[cfg(not(feature = "crypto-debug"))]
        dt.field(&"***");

        dt.finish()
    }
}

impl Deref for ExporterSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for ExporterSecret {
    fn from(secret: Vec<u8>) -> Self {
        Self(secret.into())
    }
}

/// A currently unknown ciphersuite.
///
/// Used to accept unknown values, e.g., in `Capabilities`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct VerifiableCiphersuite(u16);

impl VerifiableCiphersuite {
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw u16 value of this ciphersuite.
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Returns true if this is a GREASE ciphersuite value.
    ///
    /// GREASE values are used to ensure implementations properly handle unknown
    /// ciphersuites. See [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
    ///
    /// GREASE ciphersuites cannot be used for actual cryptographic operations.
    pub fn is_grease(&self) -> bool {
        crate::grease::is_grease_value(self.0)
    }
}

impl From<Ciphersuite> for VerifiableCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value.id())
    }
}

impl TryFrom<VerifiableCiphersuite> for Ciphersuite {
    type Error = tls_codec::Error;

    fn try_from(value: VerifiableCiphersuite) -> Result<Self, Self::Error> {
        Ciphersuite::try_from(value.0)
    }
}

/// MLS ciphersuites.
///
/// The identity of a ciphersuite is its code point; the parameters are kept
/// alongside so the accessors stay infallible and `const`.
#[derive(Clone, Copy)]
pub struct Ciphersuite {
    id: u16,
    kem: HpkeKemType,
    kdf: HpkeKdfType,
    aead: AeadType,
    hash: HashType,
    signature: SignatureScheme,
}

#[allow(non_upper_case_globals)]
impl Ciphersuite {
    const fn builtin(
        id: u16,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        hash: HashType,
        signature: SignatureScheme,
    ) -> Self {
        Self {
            id,
            kem,
            kdf,
            aead,
            hash,
            signature,
        }
    }
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    pub const MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519: Self = Self::builtin(
        0x0001,
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        AeadType::Aes128Gcm,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    );
    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    pub const MLS_128_DHKEMP256_AES128GCM_SHA256_P256: Self = Self::builtin(
        0x0002,
        HpkeKemType::DhKemP256,
        HpkeKdfType::HkdfSha256,
        AeadType::Aes128Gcm,
        HashType::Sha2_256,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    );
    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    pub const MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519: Self = Self::builtin(
        0x0003,
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    );
    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    pub const MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448: Self = Self::builtin(
        0x0004,
        HpkeKemType::DhKem448,
        HpkeKdfType::HkdfSha512,
        AeadType::Aes256Gcm,
        HashType::Sha2_512,
        SignatureScheme::ED448,
    );
    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    pub const MLS_256_DHKEMP521_AES256GCM_SHA512_P521: Self = Self::builtin(
        0x0005,
        HpkeKemType::DhKemP521,
        HpkeKdfType::HkdfSha512,
        AeadType::Aes256Gcm,
        HashType::Sha2_512,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
    );
    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    pub const MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448: Self = Self::builtin(
        0x0006,
        HpkeKemType::DhKem448,
        HpkeKdfType::HkdfSha512,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_512,
        SignatureScheme::ED448,
    );
    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    pub const MLS_256_DHKEMP384_AES256GCM_SHA384_P384: Self = Self::builtin(
        0x0007,
        HpkeKemType::DhKemP384,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
    );
    /// X-WING KEM draft-01 | Chacha20Poly1305 | SHA2-256 | Ed25519
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519: Self = Self::builtin(
        0x004D,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha256,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    );
    /// ML-KEM1024 | AES-GCM256 | SHA2-512 | ML-DSA87
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87: Self = Self::builtin(
        0x0906,
        HpkeKemType::MlKem1024,
        HpkeKdfType::HkdfSha512,
        AeadType::Aes256Gcm,
        HashType::Sha2_512,
        SignatureScheme::MLDSA87,
    );
    /// ML-KEM768 + X25519 (XWing) | AES-GCM128 | SHA2-256 | Ed25519
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD1 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519: Self = Self::builtin(
        0x004F,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha256,
        AeadType::Aes128Gcm,
        HashType::Sha2_256,
        SignatureScheme::ED25519,
    );
    /// ML-KEM768 + X25519 (XWing) | AES-GCM256 | SHA2-384 | Ed25519
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD2 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519: Self = Self::builtin(
        0x004E,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ED25519,
    );
    /// ML-KEM768 | AES-GCM256 | SHA2-384 | Ed25519
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD6 (custom provisional code point, kept from the
    /// former AIR_128_MLKEM768_AES256GCM_SHA384_Ed25519 ciphersuite for backwards compatibility)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519: Self = Self::builtin(
        0xF042,
        HpkeKemType::MlKem768,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ED25519,
    );
    /// ML-KEM768 | AES-GCM256 | SHA2-384 | EcDSA P256
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD7 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_128_MLKEM768_AES256GCM_SHA384_P256: Self = Self::builtin(
        0x0050,
        HpkeKemType::MlKem768,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    );
    /// ML-KEM1024 | AES-GCM256 | SHA2-384 | EcDSA P384
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD8 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_192_MLKEM1024_AES256GCM_SHA384_P384: Self = Self::builtin(
        0x0042,
        HpkeKemType::MlKem1024,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
    );
    /// ML-KEM768 + X25519 (XWing) | Chacha20Poly1305 | SHA2-384 | ML-DSA44
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD9 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44: Self = Self::builtin(
        0x0052,
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha384,
        AeadType::ChaCha20Poly1305,
        HashType::Sha2_384,
        SignatureScheme::MLDSA44,
    );
    /// ML-KEM768 | AES-GCM256 | SHA2-384 | ML-DSA65
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD10 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65: Self = Self::builtin(
        0x0051,
        HpkeKemType::MlKem768,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::MLDSA65,
    );
    /// ML-KEM1024 | AES-GCM256 | SHA2-384 | ML-DSA87
    ///
    /// [draft-ietf-mls-pq-ciphersuites] TBD11 (provisional code point)
    ///
    /// [draft-ietf-mls-pq-ciphersuites]: https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites
    #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
    pub const MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87: Self = Self::builtin(
        0x0907,
        HpkeKemType::MlKem1024,
        HpkeKdfType::HkdfSha384,
        AeadType::Aes256Gcm,
        HashType::Sha2_384,
        SignatureScheme::MLDSA87,
    );

    /// The built-in ciphersuites. The order is the former enum's declaration
    /// order and is part of the serde encoding; `traits/tests/ciphersuite_codec.rs`
    /// pins it.
    const BUILTIN: &'static [Self] = &[
        Self::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Self::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        Self::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        Self::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
        Self::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        Self::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
        Self::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        Self::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
    ];

    /// Names of the built-in ciphersuites, in the same order as `BUILTIN`.
    const NAMES: &'static [&'static str] = &[
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
        "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
        "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
        "MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
        "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
        "MLS_256_DHKEMP384_AES256GCM_SHA384_P384",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_128_MLKEM768_AES256GCM_SHA384_P256",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_192_MLKEM1024_AES256GCM_SHA384_P384",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65",
        #[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]
        "MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87",
    ];

    /// The code point of this ciphersuite.
    #[inline]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Position in `BUILTIN`. The fields are private and only the constants
    /// construct a value, so every value is in the table.
    fn index(&self) -> usize {
        Self::BUILTIN
            .iter()
            .position(|c| c.id == self.id)
            .expect("every Ciphersuite is built in")
    }

    fn name(&self) -> &'static str {
        Self::NAMES[self.index()]
    }

    /// Get the [`HashType`] for this [`Ciphersuite`]
    #[inline]
    pub const fn hash_algorithm(&self) -> HashType {
        self.hash
    }

    /// Get the [`SignatureScheme`] for this [`Ciphersuite`].
    #[inline]
    pub const fn signature_algorithm(&self) -> SignatureScheme {
        self.signature
    }

    /// Get the [`AeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn aead_algorithm(&self) -> AeadType {
        self.aead
    }

    /// Get the [`HpkeKdfType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kdf_algorithm(&self) -> HpkeKdfType {
        self.kdf
    }

    /// Get the [`HpkeKemType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kem_algorithm(&self) -> HpkeKemType {
        self.kem
    }

    /// Get the [`HpkeAeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_aead_algorithm(&self) -> HpkeAeadType {
        match self.aead {
            AeadType::Aes128Gcm => HpkeAeadType::AesGcm128,
            AeadType::Aes256Gcm => HpkeAeadType::AesGcm256,
            AeadType::ChaCha20Poly1305 => HpkeAeadType::ChaCha20Poly1305,
        }
    }

    /// Get the [`HpkeConfig`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_config(&self) -> HpkeConfig {
        HpkeConfig(
            self.hpke_kem_algorithm(),
            self.hpke_kdf_algorithm(),
            self.hpke_aead_algorithm(),
        )
    }

    /// Get the length of the used hash algorithm.
    #[inline]
    pub const fn hash_length(&self) -> usize {
        self.hash_algorithm().size()
    }

    /// Get the length of the AEAD tag.
    #[inline]
    pub const fn mac_length(&self) -> usize {
        self.aead_algorithm().tag_size()
    }

    /// Returns the key size of the used AEAD.
    #[inline]
    pub const fn aead_key_length(&self) -> usize {
        self.aead_algorithm().key_size()
    }

    /// Returns the length of the nonce of the AEAD.
    #[inline]
    pub const fn aead_nonce_length(&self) -> usize {
        self.aead_algorithm().nonce_size()
    }
}

const _: () = assert!(Ciphersuite::BUILTIN.len() == Ciphersuite::NAMES.len());

impl PartialEq for Ciphersuite {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Ciphersuite {}

impl core::hash::Hash for Ciphersuite {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl PartialOrd for Ciphersuite {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ciphersuite {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl core::fmt::Debug for Ciphersuite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl core::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: Ciphersuite) -> u16 {
        s.id
    }
}

impl From<&Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: &Ciphersuite) -> u16 {
        s.id
    }
}

impl TryFrom<u16> for Ciphersuite {
    type Error = tls_codec::Error;

    #[inline(always)]
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match Self::BUILTIN.iter().find(|c| c.id == v) {
            Some(c) => Ok(*c),
            None => Err(Self::Error::DecodingError(format!(
                "{v} is not a valid ciphersuite value"
            ))),
        }
    }
}

// serde mirrors what the derive produced for the former enum: a unit variant
// with the declaration index and the name. serde_json and ciborium store the
// name, postcard stores the index, and stored data keeps deserializing.

impl Serialize for Ciphersuite {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let i = self.index();
        serializer.serialize_unit_variant("Ciphersuite", i as u32, Self::NAMES[i])
    }
}

impl<'de> Deserialize<'de> for Ciphersuite {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Index(usize);

        struct IndexVisitor;
        impl serde::de::Visitor<'_> for IndexVisitor {
            type Value = Index;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a ciphersuite name or index")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Index, E> {
                usize::try_from(v)
                    .ok()
                    .filter(|i| *i < Ciphersuite::NAMES.len())
                    .map(Index)
                    .ok_or_else(|| E::invalid_value(serde::de::Unexpected::Unsigned(v), &self))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Index, E> {
                Ciphersuite::NAMES
                    .iter()
                    .position(|n| *n == v)
                    .map(Index)
                    .ok_or_else(|| E::unknown_variant(v, Ciphersuite::NAMES))
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Index, E> {
                match core::str::from_utf8(v) {
                    Ok(s) => self.visit_str(s),
                    Err(_) => Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self)),
                }
            }
        }

        impl<'de> Deserialize<'de> for Index {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Index, D::Error> {
                d.deserialize_identifier(IndexVisitor)
            }
        }

        struct CiphersuiteVisitor;
        impl<'de> serde::de::Visitor<'de> for CiphersuiteVisitor {
            type Value = Ciphersuite;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("enum Ciphersuite")
            }
            fn visit_enum<A: serde::de::EnumAccess<'de>>(
                self,
                data: A,
            ) -> Result<Ciphersuite, A::Error> {
                use serde::de::VariantAccess;
                let (Index(i), variant) = data.variant::<Index>()?;
                variant.unit_variant()?;
                Ok(Ciphersuite::BUILTIN[i])
            }
        }

        deserializer.deserialize_enum("Ciphersuite", Self::NAMES, CiphersuiteVisitor)
    }
}

impl tls_codec::Size for Ciphersuite {
    fn tls_serialized_len(&self) -> usize {
        self.id.tls_serialized_len()
    }
}

impl tls_codec::Serialize for Ciphersuite {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.id.tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for Ciphersuite {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Self::try_from(u16::tls_deserialize(bytes)?)
    }
}

impl tls_codec::DeserializeBytes for Ciphersuite {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (v, rest) = u16::tls_deserialize_bytes(bytes)?;
        Ok((Self::try_from(v)?, rest))
    }
}

impl From<Ciphersuite> for SignatureScheme {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.signature_algorithm()
    }
}

impl From<Ciphersuite> for AeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKemType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kem_algorithm()
    }
}

impl From<Ciphersuite> for HpkeAeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKdfType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kdf_algorithm()
    }
}

impl From<Ciphersuite> for HashType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hash_algorithm()
    }
}
