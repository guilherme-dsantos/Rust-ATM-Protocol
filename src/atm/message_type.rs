use core::fmt;
use serde::{Deserialize, Serialize};
use std::vec::Vec;
#[derive(Serialize, Deserialize)]
pub(crate) enum MessageType {
    RegistrationRequest {
        ciphertext: Vec<u8>,
        hmac: Vec<u8>,
        nonce: String,
    },
    RegistrationResponse {
        success: String,
        hash: String,
        account_id: String,
        hmac: String,
        nonce: String,
    },
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageType::RegistrationRequest {
                ciphertext,
                hmac,
                nonce,
            } => {
                write!(
                    f,
                    "RegistrationRequest: ciphertext={:?}, hmac={:?}, nonce={}",
                    ciphertext, hmac, nonce
                )
            }
            MessageType::RegistrationResponse {
                success,
                hash,
                account_id,
                hmac,
                nonce,
            } => {
                write!(
                    f,
                    "RegistrationResponse: success={}, hash={}, account_id={}, hmac={}, nonce={}",
                    success, hash, account_id, hmac, nonce
                )
            } // Add other variants as needed
        }
    }
}
