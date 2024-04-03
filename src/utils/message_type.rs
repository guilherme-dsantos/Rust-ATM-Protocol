use core::fmt;
use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageRequest {
    RegistrationRequest {
        msg_nonce: String,
        msg_ciphertext: Vec<u8>,
        msg_atm_public_key: Vec<u8>,
        msg_hmac: Vec<u8>,
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
        msg_success: bool,
        msg_ciphertext: Vec<u8>,
        msg_hmac: Vec<u8>,
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
                msg_ciphertext,
                msg_atm_public_key,
                msg_hmac,
                msg_nonce,
            } => {
                write!(
                    f,
                    "RegistrationRequest: ciphertext={:?}, atm_public_key={:?}, hmac={:?}, nonce={}",
                    msg_ciphertext, msg_atm_public_key, msg_hmac, msg_nonce
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
                msg_success,
                msg_ciphertext,
                msg_hmac,
            } => {
                write!(
                    f,
                    "RegistrationResponse: success={}, ciphertext={:?}, hmac={:?}",
                    msg_success, msg_ciphertext, msg_hmac
                )
            }
            MessageResponse::DepositResponse {
                ciphertext: _,
                hmac: _,
            } => todo!(),
        }
    }
}
