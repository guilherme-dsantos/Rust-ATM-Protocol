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
