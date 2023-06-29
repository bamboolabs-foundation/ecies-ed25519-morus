use thiserror_no_std::Error as ThisError;

#[derive(Debug, Clone, Copy, ThisError)]
pub enum Error {
    #[error("Invalid tag supplied during decryption")]
    InvalidTag,
}
