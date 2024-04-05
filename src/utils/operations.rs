use serde::Deserialize;

pub enum Operation {
    Balance(String),
    Deposit(String),
    Withdraw(String),
    Get,
}

#[derive(Debug, Deserialize)]
pub struct AccountData {
    pub id: String,
    pub hash: [u8; 32],
    pub balance: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountData2 {
    pub id: String,
    pub dh_uk: Vec<u8>,
    pub hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct AccountData3 {
    pub dh_uk: Vec<u8>,
    pub hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct AccountData4 {
    pub id: String,
    pub hash: Vec<u8>,
    pub deposit: String,
}
#[derive(Debug, Deserialize)]
pub struct AccountData5 {
    pub id: String,
    pub hash: Vec<u8>,
    pub balance: String,
}
#[derive(Debug, Deserialize)]
pub struct AccountData6 {
    pub id: String,
    pub hash: Vec<u8>,
}
