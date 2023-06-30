use thiserror_no_std::Error as ThisError;

#[derive(Debug, Clone, Copy, ThisError)]
pub enum Error {
    #[error("Invalid tag supplied during decryption")]
    InvalidTag,
    #[error("Cannot generate random numbers")]
    RandomNumbersGenerationError,
    #[error("Input & output buffer size mismatch during decryptions/encryptions")]
    BufferSizeMismatch,
    #[error("EdwardsPoint decompression failure, maybe bad public key")]
    EdwardsPointDecompressionFailure,
}
