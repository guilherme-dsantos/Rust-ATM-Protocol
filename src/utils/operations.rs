use serde::Deserialize;

pub enum Operation {
    Balance(String),
    Deposit(String),
    Withdraw(String),
    Get(String),
}

#[derive(Debug, Deserialize)]
pub struct AccountData {
    pub id: String,
    pub hash: Vec<u8>,
    pub balance: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountData2 {
    pub dh_uk: Vec<u8>,
    pub hash: Vec<u8>,
    pub deposit: String,
}
