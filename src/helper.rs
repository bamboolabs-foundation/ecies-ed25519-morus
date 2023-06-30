pub(crate) fn derive_key(master_key: &[u8]) -> crate::morus::Key {
    let mut result = [0; 16];
    let full_derive_bytes = blake3::derive_key(crate::KDF_CONTEXT, master_key);
    result.copy_from_slice(&full_derive_bytes[..16]);

    result
}

pub(crate) fn morus_encrypt<RNG: rand_core::CryptoRng + rand_core::RngCore>(
    key: &crate::CipherKey,
    message: &[u8],
    rng: &mut RNG,
    ciphertext: &mut [u8],
) -> Result<crate::DecryptionMaterials, crate::Error> {
    if message.len() != ciphertext.len() {
        return Err(crate::Error::BufferSizeMismatch);
    }

    ciphertext.copy_from_slice(message);
    let mut nonce = [0u8; 16];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| crate::Error::RandomNumbersGenerationError)?;
    let tag = crate::morus::Morus::new(&nonce, &key.inner).encrypt_in_place(ciphertext, &[]);

    Ok(crate::DecryptionMaterials { nonce, tag })
}

pub(crate) fn morus_decrypt(
    key: &crate::CipherKey,
    cipertext: &[u8],
    decryption_materials: &crate::DecryptionMaterials,
    output: &mut [u8],
) -> Result<(), crate::Error> {
    if cipertext.len() != output.len() {
        return Err(crate::Error::BufferSizeMismatch);
    }

    output.copy_from_slice(cipertext);
    crate::morus::Morus::new(&decryption_materials.nonce, &key.inner).decrypt_in_place(
        output,
        &decryption_materials.tag,
        &[],
    )?;

    Ok(())
}
