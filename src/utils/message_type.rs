use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageRequest {
    RegistrationRequest {
        msg_nonce: Vec<u8>,
        msg_ciphertext: Vec<u8>,
        msg_hmac: [u8; 32],
    },
    DepositRequest {
        msg_id: String,
        msg_nonce: [u8; 12],
        msg_ciphertext: Vec<u8>,
    },
    WithdrawRequest {
        msg_id: String,
        msg_nonce: [u8; 12],
        msg_ciphertext: Vec<u8>,
    },
    GetBalanceRequest {
        msg_id: String,
        msg_nonce: [u8; 12],
        msg_ciphertext: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
pub enum MessageResponse {
    RegistrationResponse {
        msg_success: bool,
        msg_ciphertext: Vec<u8>,
        msg_nonce: [u8; 12],
    },
    DepositResponse {
        msg_success: bool,
        msg_nonce: [u8; 12],
        msg_ciphertext: Vec<u8>,
    },
    WithdrawResponse {
        msg_success: bool,
        msg_nonce: Vec<u8>,
        msg_ciphertext: Vec<u8>,
    },
    GetBalanceResponse {
        msg_success: bool,
        msg_nonce: Vec<u8>,
        msg_ciphertext: Vec<u8>,
    },
}
