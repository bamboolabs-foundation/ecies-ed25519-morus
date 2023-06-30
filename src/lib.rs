#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]

pub mod errors;
pub mod morus;

pub(crate) mod helper;

pub type DecryptTag = morus::Tag;
pub type Nonce = morus::Nonce;

pub const KDF_CONTEXT: &str = "ecies-ed25519-morus/kdf";

pub use ed25519_dalek::{SecretKey, SigningKey, VerifyingKey};
pub use errors::Error;

#[derive(Clone, Copy, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DecryptionMaterials {
    pub nonce: Nonce,
    pub tag: DecryptTag,
}

pub fn encrypt_into<RNG: rand_core::CryptoRng + rand_core::RngCore>(
    sender_key: &SigningKey,
    receiver_key: &VerifyingKey,
    rng: &mut RNG,
    message: &[u8],
    ciphertext: &mut [u8],
) -> Result<DecryptionMaterials, Error> {
    let cipher_key = CipherKey::sender_generate(sender_key, receiver_key)?;

    helper::morus_encrypt(&cipher_key, message, rng, ciphertext)
}

pub fn decrypt_into(
    receiver_key: &SigningKey,
    sender_key: &VerifyingKey,
    decryption_materials: &DecryptionMaterials,
    ciphertext: &[u8],
    message: &mut [u8],
) -> Result<(), Error> {
    let cipher_key = CipherKey::receiver_generate(receiver_key, sender_key)?;

    helper::morus_decrypt(&cipher_key, ciphertext, decryption_materials, message)
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct CipherKey {
    pub(crate) inner: morus::Key,
}

impl CipherKey {
    fn sender_generate(
        sender_key: &SigningKey,
        receiver_key: &VerifyingKey,
    ) -> Result<Self, Error> {
        let shared_secret = Self::generate_shared_secret(sender_key, receiver_key)?;
        let mut master_key = [0u8; 64];
        master_key[..32].copy_from_slice(&sender_key.verifying_key().as_bytes()[..]);
        master_key[32..].copy_from_slice(&shared_secret[..]);
        let inner = helper::derive_key(&master_key);

        Ok(Self { inner })
    }

    fn receiver_generate(
        receiver_key: &SigningKey,
        sender_key: &VerifyingKey,
    ) -> Result<Self, Error> {
        let shared_secret = Self::generate_shared_secret(receiver_key, sender_key)?;
        let mut master_key = [0u8; 64];
        master_key[..32].copy_from_slice(&sender_key.as_bytes()[..]);
        master_key[32..].copy_from_slice(&shared_secret[..]);
        let inner = helper::derive_key(&master_key);

        Ok(Self { inner })
    }

    fn generate_shared_secret(
        secret_key: &SigningKey,
        public_key: &VerifyingKey,
    ) -> Result<[u8; 32], Error> {
        let pk_compressed = curve25519_dalek::edwards::CompressedEdwardsY(public_key.to_bytes());
        let pk_point = pk_compressed
            .decompress()
            .ok_or(Error::EdwardsPointDecompressionFailure)?;
        let sk_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(
            curve25519_dalek::scalar::clamp_integer(secret_key.to_scalar_bytes()),
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

    const REPETITION: usize = 128;
    const BUFFER_SIZE: usize = 512 * 1024; // avoid higher than this to avoid stackoverflow

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
                &sender_keypair,
                &receiver_public,
                &mut rng,
                &random_message[..],
                &mut ciphertext[..],
            )
            .unwrap();
            decrypt_into(
                &receiver_keypair,
                &sender_public,
                &decrypt_materials,
                &ciphertext[..],
                &mut decrypted_message[..],
            )
            .unwrap();

            assert_eq!(random_message, decrypted_message);
            assert_ne!(sender_public, receiver_public);
        }
    }
}
