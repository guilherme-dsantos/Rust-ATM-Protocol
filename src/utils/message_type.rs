use core::fmt;
use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Serialize, Deserialize)]
pub enum MessageRequest {
    RegistrationRequest {
        nonce: String,
        ciphertext: Vec<u8>,
        atm_public_key: Vec<u8>,
        hmac: Vec<u8>,
    },
    DepositRequest {
        id: String,
        nonce: String,
        ciphertext: Vec<u8>,
        hmac: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
pub enum MessageResponse {
    RegistrationResponse {
        success: bool,
        ciphertext: Vec<u8>,
        hmac: Vec<u8>,
    },
    DepositResponse {
        ciphertext: Vec<u8>,
        hmac: Vec<u8>,
    },
}

impl fmt::Display for MessageRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageRequest::RegistrationRequest {
                ciphertext,
                atm_public_key,
                hmac,
                nonce,
            } => {
                write!(
                    f,
                    "RegistrationRequest: ciphertext={:?}, atm_public_key={:?}, hmac={:?}, nonce={}",
                    ciphertext, atm_public_key, hmac, nonce
                )
            }
            MessageRequest::DepositRequest {
                id: _,
                nonce: _,
                ciphertext: _,
                hmac: _,
            } => todo!(),
        }
    }
}

impl fmt::Display for MessageResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageResponse::RegistrationResponse {
                success,
                ciphertext,
                hmac,
            } => {
                write!(
                    f,
                    "RegistrationResponse: success={}, ciphertext={:?}, hmac={:?}",
                    success, ciphertext, hmac
                )
            }
            MessageResponse::DepositResponse {
                ciphertext: _,
                hmac: _,
            } => todo!(),
        }
    }
}
