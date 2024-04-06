use serde::{Deserialize, Serialize};

pub enum Operation {
    Balance(String),
    Deposit(String),
    Withdraw(String),
    Get,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountIdHashAmount {
    pub id: String,
    pub hash: [u8; 32],
    pub amount: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountDataIdDHHash {
    pub id: String,
    pub dh_uk: [u8; 32],
    pub hash: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountDHHash {
    pub dh_uk: [u8; 32],
    pub hash: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountIDHash {
    pub id: String,
    pub hash: Vec<u8>,
}
