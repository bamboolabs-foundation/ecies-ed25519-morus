pub(crate) fn derive_key(master_key: &[u8]) -> crate::morus::Key {
    let mut result = [0; 16];
    let full_derive_bytes = blake3::derive_key(crate::KDF_CONTEXT, master_key);
    result.copy_from_slice(&full_derive_bytes[..16]);

    result
}

pub(crate) fn morus_encrypt<RNG: rand_core::CryptoRng + rand_core::RngCore>(
    rng: &mut RNG,
    key: &crate::CipherKey,
    associated_data: &[u8],
    message: &[u8],
    ciphertext: &mut [u8],
) -> Result<crate::DecryptionMaterials, crate::Error> {
    if message.len() != ciphertext.len() {
        return Err(crate::Error::BufferSizeMismatch);
    }

    ciphertext.copy_from_slice(message);
    let mut nonce = [0u8; 16];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| crate::Error::RandomNumbersGenerationError)?;
    let tag =
        crate::morus::Morus::new(&nonce, &key.inner).encrypt_in_place(ciphertext, associated_data);

    Ok(crate::DecryptionMaterials { nonce, tag })
}

pub(crate) fn morus_decrypt(
    decryption_materials: &crate::DecryptionMaterials,
    key: &crate::CipherKey,
    associated_data: &[u8],
    cipertext: &[u8],
    message: &mut [u8],
) -> Result<(), crate::Error> {
    if cipertext.len() != message.len() {
        return Err(crate::Error::BufferSizeMismatch);
    }

    message.copy_from_slice(cipertext);
    crate::morus::Morus::new(&decryption_materials.nonce, &key.inner).decrypt_in_place(
        message,
        &decryption_materials.tag,
        associated_data,
    )?;

    Ok(())
}
