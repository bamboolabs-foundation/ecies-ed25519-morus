//! Experimental [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) on [Twisted Edwards Curve25519](https://en.wikipedia.org/wiki/Curve25519) and [MORUS-1280-128](https://competitions.cr.yp.to/round3/morusv2.pdf)
//!
//! ## Notes
//!
//! - [Flexible Symmetric Cryptography - Impractical plaintext recovery attack](https://eprint.iacr.org/2018/464.pdf).
//! - This work misuses the `sign & verify` keypair in the `ed25519` scheme for accomplishing `ECIES`. We call this, a perversion because we should only use the `ephemeral ones` (except for the recipient).
//! - No security audits, and perhaps will not happen.
//!
//! ## Features
//!
//! - `no-std` environment (for example: [wasm](https://en.wikipedia.org/wiki/WebAssembly)):
//!
//! ```bash
//! cargo add ecies-ed25519-morus --no-default-features --features="pure"
//! ```
//!
//! - `std` environment (default):
//!
//! ```bash
//! cargo add ecies-ed25519-morus
//! ```
//!
//! - `std` and `aarch64` environment (for example: [Apple Silicon](https://en.wikipedia.org/wiki/Apple_silicon))
//!
//! ```bash
//! cargo add ecies-ed25519-morus --features="aarch64-optimizations"
//! ```
//!
//! ## Example
//!
//! ```rust
//! use rand_core::RngCore;
//! use ecies_ed25519_morus::{encrypt_into, decrypt_into};
//!
//! const BUFFER_SIZE: usize = 512 * 1024; // avoid higher than this to prevent stackoverflow
//! let mut rng = rand_core::OsRng::default();
//! let sender_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
//! let receiver_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
//! let sender_public = sender_keypair.verifying_key();
//! let receiver_public = receiver_keypair.verifying_key();
//! let mut random_message = [0u8; BUFFER_SIZE];
//! let mut decrypted_message = [0u8; BUFFER_SIZE];
//! let mut ciphertext = [0u8; BUFFER_SIZE];
//! rng.fill_bytes(&mut random_message);
//!
//! let decrypt_materials = encrypt_into(
//!     &mut rng,
//!     &sender_keypair,
//!     &receiver_public,
//!     &[],
//!     &random_message[..],
//!     &mut ciphertext[..],
//! )
//! .unwrap();
//! decrypt_into(
//!     &decrypt_materials,
//!     &receiver_keypair,
//!     &sender_public,
//!     &[],
//!     &ciphertext[..],
//!     &mut decrypted_message[..],
//! )
//! .unwrap();
//!
//! assert_eq!(random_message, decrypted_message);
//! assert_ne!(sender_public, receiver_public);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]

pub mod errors;
pub mod morus;

pub(crate) mod helper;

pub type DecryptTag = morus::Tag;
pub type Nonce = morus::Nonce;

pub const KDF_CONTEXT: &str = "ecies-ed25519-morus/kdf";

#[doc(inline)]
pub use ed25519_dalek::{SecretKey, SigningKey, VerifyingKey};
pub use errors::Error;

/// A struct containing `nonce` and `tag` for decryption purpose, a result of [encrypt_into]
#[derive(Clone, Copy, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DecryptionMaterials {
    pub nonce: Nonce,
    pub tag: DecryptTag,
}

/// Encrypt function
///
/// ## Warning
///
/// Subsequent call will yield different [DecryptionMaterials], hence will produce different `ciphertext`
///
/// ## Returns
///
/// - Success : [DecryptionMaterials], only valid for decrypting `ciphertext` of this function.
/// - Errors  :
///   * [Error::BufferSizeMismatch], happens when `message` and `ciphertext` buffer slice has different length.
///   * [Error::RandomNumbersGenerationError], happens when [rng](rand_core::RngCore) can't produce numbers
///   * [Error::EdwardsPointDecompressionFailure], happens when invalid [sender_keypair](SigningKey) or [receiver_public_key](VerifyingKey)
///
pub fn encrypt_into<RNG: rand_core::CryptoRng + rand_core::RngCore>(
    rng: &mut RNG,
    sender_keypair: &SigningKey,
    receiver_public_key: &VerifyingKey,
    associated_data: &[u8],
    message: &[u8],
    ciphertext: &mut [u8],
) -> Result<DecryptionMaterials, Error> {
    let cipher_key = CipherKey::sender_generate(sender_keypair, receiver_public_key)?;

    helper::morus_encrypt(rng, &cipher_key, associated_data, message, ciphertext)
}

/// Decrypt function
///
/// ## Returns
///
/// - Success : [Ok(())]
/// - Errors  :
///   * [Error::BufferSizeMismatch], happens when `ciphertext` and `decrypted_message` buffer slice has different length.
///   * [Error::InvalidTag], happens when invalid [DecryptionMaterials] supplied
///   * [Error::EdwardsPointDecompressionFailure], happens when invalid [receiver_keypair](SigningKey) or [sender_public_key](VerifyingKey)
///
pub fn decrypt_into(
    decryption_materials: &DecryptionMaterials,
    receiver_keypair: &SigningKey,
    sender_public_key: &VerifyingKey,
    associated_data: &[u8],
    ciphertext: &[u8],
    decrypted_message: &mut [u8],
) -> Result<(), Error> {
    let cipher_key = CipherKey::receiver_generate(receiver_keypair, sender_public_key)?;

    helper::morus_decrypt(
        decryption_materials,
        &cipher_key,
        associated_data,
        ciphertext,
        decrypted_message,
    )
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct CipherKey {
    pub(crate) inner: morus::Key,
}

impl CipherKey {
    fn sender_generate(
        sender_keypair: &SigningKey,
        receiver_public_key: &VerifyingKey,
    ) -> Result<Self, Error> {
        let shared_secret = Self::generate_shared_secret(sender_keypair, receiver_public_key)?;
        let mut master_key = [0u8; 64];
        master_key[..32].copy_from_slice(&sender_keypair.verifying_key().as_bytes()[..]);
        master_key[32..].copy_from_slice(&shared_secret[..]);
        let inner = helper::derive_key(&master_key);

        Ok(Self { inner })
    }

    fn receiver_generate(
        receiver_keypair: &SigningKey,
        sender_public_key: &VerifyingKey,
    ) -> Result<Self, Error> {
        let shared_secret = Self::generate_shared_secret(receiver_keypair, sender_public_key)?;
        let mut master_key = [0u8; 64];
        master_key[..32].copy_from_slice(&sender_public_key.as_bytes()[..]);
        master_key[32..].copy_from_slice(&shared_secret[..]);
        let inner = helper::derive_key(&master_key);

        Ok(Self { inner })
    }

    fn generate_shared_secret(
        keypair_alice: &SigningKey,
        public_bob: &VerifyingKey,
    ) -> Result<[u8; 32], Error> {
        let pk_compressed = curve25519_dalek::edwards::CompressedEdwardsY(public_bob.to_bytes());
        let pk_point = pk_compressed
            .decompress()
            .ok_or(Error::EdwardsPointDecompressionFailure)?;
        let sk_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(
            curve25519_dalek::scalar::clamp_integer(keypair_alice.to_scalar_bytes()),
        );
        let shared_point = pk_point * sk_scalar;
        let shared_point_compressed = shared_point.compress();

        Ok(shared_point_compressed.to_bytes())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use rand_core::RngCore;

    const REPETITION: usize = 32;
    const BUFFER_SIZE: usize = 512 * 1024; // avoid higher than this to prevent stackoverflow

    #[test]
    fn test_encrypt_decrypt_always_successful() {
        for _ in 0..REPETITION {
            let mut rng = rand_core::OsRng::default();
            let sender_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
            let receiver_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
            let sender_public = sender_keypair.verifying_key();
            let receiver_public = receiver_keypair.verifying_key();
            let mut random_message = [0u8; BUFFER_SIZE];
            let mut decrypted_message = [0u8; BUFFER_SIZE];
            let mut ciphertext = [0u8; BUFFER_SIZE];
            rng.fill_bytes(&mut random_message);

            let decrypt_materials = encrypt_into(
                &mut rng,
                &sender_keypair,
                &receiver_public,
                &[],
                &random_message[..],
                &mut ciphertext[..],
            )
            .unwrap();
            decrypt_into(
                &decrypt_materials,
                &receiver_keypair,
                &sender_public,
                &[],
                &ciphertext[..],
                &mut decrypted_message[..],
            )
            .unwrap();

            assert_eq!(random_message, decrypted_message);
            assert_ne!(sender_public, receiver_public);
        }
    }

    #[test]
    fn test_idempotent_keys_yield_different() {
        for _ in 0..REPETITION {
            let mut rng = rand_core::OsRng::default();
            let sender_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
            let receiver_keypair = ed25519_dalek::SigningKey::generate(&mut rng);
            let receiver_public = receiver_keypair.verifying_key();
            let mut random_message = [0u8; BUFFER_SIZE];
            let mut ciphertext_0 = [0u8; BUFFER_SIZE];
            let mut ciphertext_1 = [0u8; BUFFER_SIZE];
            rng.fill_bytes(&mut random_message);

            let _ = encrypt_into(
                &mut rng,
                &sender_keypair,
                &receiver_public,
                &[],
                &random_message[..],
                &mut ciphertext_0[..],
            )
            .unwrap();
            let _ = encrypt_into(
                &mut rng,
                &sender_keypair,
                &receiver_public,
                &[],
                &random_message[..],
                &mut ciphertext_1[..],
            )
            .unwrap();

            assert_ne!(ciphertext_0, ciphertext_1);
        }
    }
}
