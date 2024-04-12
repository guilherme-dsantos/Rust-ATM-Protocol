extern crate utils;
use aes_gcm_siv::{
    aead::{self, Aead, KeyInit},
    Aes256GcmSiv,
    Nonce, // Or `Aes128GcmSiv`
};
use blake3::Hasher;
use cipher::generic_array::GenericArray;
use rand::RngCore;
use rsa::{
    pkcs1::EncodeRsaPublicKey, pkcs8::LineEnding, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::exit,
    sync::{Arc, Mutex},
    thread,
};
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

use utils::{
    bank_parser,
    message_type::{MessageRequest, MessageResponse},
    operations::{AccountDataIdDHHash, AccountIDHash, AccountIdHashAmount},
    validate_functions::{validate_file_name, validate_port},
};

use ctrlc::set_handler;
use std::process;

fn encrypt_message(key: &[u8], data_to_encrypt: &str, nonce: &[u8]) -> Vec<u8> {
    // Use the key for AES256-GCM-SIV
    let aes_gcm_key = GenericArray::from_slice(key);
    let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
    let aes_gcm_nonce = Nonce::from_slice(nonce); // 96-bits; unique per message

    aes_gcm_cipher
        .encrypt(
            aes_gcm_nonce,
            aead::Payload {
                msg: data_to_encrypt.as_bytes(),
                aad: aes_gcm_nonce,
            },
        )
        .unwrap_or_else(|e| {
            eprintln!("Error encrypting with AES GCM {}", e);
            vec![]
        })
}

fn decrypt_message(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let aes_gcm_key = GenericArray::from_slice(key);
    let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
    let aes_gcm_nonce = Nonce::from_slice(nonce);
    aes_gcm_cipher
        .decrypt(
            aes_gcm_nonce,
            aead::Payload {
                msg: ciphertext,
                aad: aes_gcm_nonce,
            },
        )
        .unwrap_or_else(|e| {
            eprintln!("Error decrypting {}", e);
            vec![]
        })
}

fn serialize_and_write<T: serde::Serialize>(stream: &mut TcpStream, message: &T) {
    let serialized_message = serde_json::to_string(message).unwrap_or_else(|e| {
        eprintln!("Error serializing message {}", e);
        String::new()
    });

    let serialized_with_newline = format!("{}\n", serialized_message);
    stream
        .write_all(serialized_with_newline.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("Error sending message {}", e);
        });
}

fn handle_client(
    mut stream: TcpStream,
    _addr: SocketAddr,
    bank_private_key: Arc<RsaPrivateKey>,
    users_table: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    balance_table: Arc<Mutex<HashMap<String, u64>>>,
    nonces: Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let mut buffer = Vec::new();
    let mut reader = BufReader::new(&stream);

    //let _ = reader.read_until(b'\n', &mut buffer).unwrap();

    match reader.read_until(b'\n', &mut buffer) {
        Ok(_) => {
            match serde_json::from_slice::<MessageRequest>(&buffer) {
                //Receive first registry message
                Ok(message) => match message {
                    MessageRequest::RegistrationRequest {
                        msg_ciphertext,
                        msg_hmac,
                        msg_nonce,
                    } => {
                        //Check for Repeated Nonces for Replay Attacks
                        let mut locked_nonces = nonces.lock().unwrap();
                        if locked_nonces.contains(&msg_nonce.to_vec()) {
                            println!("protocol_error");
                            return;
                        } else {
                            locked_nonces.push(msg_nonce.to_vec());
                        }

                        //Decrypt received data
                        let decrypted_data = bank_private_key
                            .decrypt(Pkcs1v15Encrypt, msg_ciphertext.as_slice())
                            .expect("Error decrypting message");

                        //Deserialize decrypted data
                        let account_data: AccountIdHashAmount =
                            serde_json::from_slice(&decrypted_data).unwrap();
                        let account_id: String = account_data.id;
                        let hashed_password = account_data.hash;
                        let balance = account_data.amount;
                        let balanceu64: u64 = balance.parse().unwrap_or_else(|e| {
                            eprintln!("Error parsing string to iu64 {}", e);
                            1
                        });

                        buffer.clear();

                        //Recreate HMAC
                        let mut new_hmac = Hasher::new_keyed(&hashed_password);
                        new_hmac.update(msg_ciphertext.as_slice());
                        new_hmac.update(&msg_nonce);
                        let hmac_bytes = new_hmac.finalize().as_bytes().to_owned();

                        //Check if HMACs are the same
                        if msg_hmac != hmac_bytes {
                            eprintln!("Integrity attack detected!");
                            return;
                        }

                        let serialized_data = serde_json::json!({
                            "id": account_id,
                            "hash": hashed_password,
                            "amount" : balance.replace('.', ""),
                        });

                        let data_to_be_encrypted = serde_json::to_string(&serialized_data)
                            .expect("Failed to serialize data to JSON");

                        // Generate a 12-byte nonce
                        let mut response_nonce = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut response_nonce);

                        let ciphertext = encrypt_message(
                            &hashed_password,
                            &data_to_be_encrypted,
                            &response_nonce,
                        );

                        //Check if account is already registred, register account if not in the users_table
                        let mut successful_user_regist = true;
                        let mut locked_users_table = users_table.lock().unwrap();
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            locked_users_table.entry(account_id.clone())
                        {
                            e.insert(hashed_password);
                        } else {
                            successful_user_regist = false;
                        }

                        //Insert account id and balance in the balance_table
                        let mut successful_balance_regist = true;
                        let mut locked_balance_table = balance_table.lock().unwrap();
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            locked_balance_table.entry(account_id.clone())
                        {
                            e.insert(balanceu64);
                        } else {
                            successful_balance_regist = false;
                        }

                        //Rollback
                        if successful_user_regist && !successful_balance_regist {
                            locked_users_table.remove_entry(&account_id);
                        } else if !successful_user_regist && successful_balance_regist {
                            locked_balance_table.remove_entry(&account_id);
                        } else if !successful_balance_regist || !successful_user_regist {
                            //eprintln!("protocol_error");
                            let registration_response = MessageResponse::RegistrationResponse {
                                msg_success: false,
                                msg_ciphertext: ciphertext,
                                msg_nonce: response_nonce,
                            };
                            serialize_and_write(&mut stream, &registration_response);
                            return;
                        }

                        //Create Ok Registration Response to the ATM
                        let ok_registration_response = MessageResponse::RegistrationResponse {
                            msg_success: true,
                            msg_ciphertext: ciphertext,
                            msg_nonce: response_nonce,
                        };

                        serialize_and_write(&mut stream, &ok_registration_response);

                        //let amount = format!("{}.{}", balanceint / 100, balanceint % 100);
                        let amount = format!("{:.2}", balanceu64 as f64 / 100.0);

                        let json_result = json!({
                            "account": account_id,
                            "initial_balance": amount,
                        });

                        println!("{}", json_result);
                    }
                    //Receive first deposit message
                    MessageRequest::DepositRequest {
                        msg_id,
                        msg_nonce,
                        msg_ciphertext,
                    } => {
                        //Check for Repeated Nonces for Replay Attacks
                        let mut locked_nonces = nonces.lock().unwrap();
                        if locked_nonces.contains(&msg_nonce.to_vec()) {
                            println!("protocol_error");
                            return;
                        } else {
                            locked_nonces.push(msg_nonce.to_vec());
                        }
                        //Generate ATM DH Public Key
                        let csprng = rand::thread_rng();
                        let bank_secret = EphemeralSecret::random_from_rng(csprng);
                        let bank_public = PublicKey::from(&bank_secret);

                        //Get user's password
                        let locked_user_table = users_table.lock().unwrap();

                        let mut locked_balance_table = balance_table.lock().unwrap();

                        let hashed_password_from_table =
                            locked_user_table.get(&msg_id).unwrap().to_owned();

                        if !locked_user_table.contains_key(&msg_id) {
                            eprintln!("Received invalid message from ATM, maybe MITM...");
                            return;
                        }

                        let plaintext = decrypt_message(
                            &hashed_password_from_table,
                            &msg_nonce,
                            &msg_ciphertext,
                        );

                        buffer.clear();

                        if plaintext.is_empty() {
                            let deposit_response = MessageResponse::DepositResponse {
                                msg_ciphertext,
                                msg_nonce,
                                msg_success: false,
                            };
    
                            //Send second deposit message
                            serialize_and_write(&mut stream, &deposit_response);
                            return;
                        }

                        //Deserialize decrypted data
                        let account_data: AccountDataIdDHHash =
                            serde_json::from_slice(&plaintext).unwrap();
                        let id = account_data.id;
                        let dh_uk = account_data.dh_uk;
                        let hashed_password = account_data.hash;

                        if msg_id != id {
                            eprintln!("Received invalid message from ATM, maybe MITM...");
                            return;
                        }

                        if hashed_password != hashed_password_from_table {
                            eprintln!("Something wrong");
                            return;
                        }

                        let public_key = PublicKey::from(dh_uk);
                        let dh_shared_secret = bank_secret.diffie_hellman(&public_key);

                        // Generate a 12-byte nonce
                        let mut response_nonce = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut response_nonce);

                        //Serialized data to encrypt later
                        let serialized_data = serde_json::json!({
                            "id": "Bank",
                            "dh_uk" : bank_public.to_bytes(),
                            "hash": hashed_password,
                        });
                        let serialized_data_to_encrypt = serde_json::to_string(&serialized_data)
                            .expect("Failed to serialize data to JSON");

                        let ciphertext = encrypt_message(
                            &hashed_password,
                            &serialized_data_to_encrypt,
                            &response_nonce,
                        );

                        let deposit_response = MessageResponse::DepositResponse {
                            msg_ciphertext: ciphertext,
                            msg_nonce: response_nonce,
                            msg_success: true,
                        };

                        //Send second deposit message
                        serialize_and_write(&mut stream, &deposit_response);

                        //Receive third message
                        let mut reader = BufReader::new(&stream);
                        let _ = reader.read_until(b'\n', &mut buffer).unwrap();
                        let message = serde_json::from_slice::<MessageRequest>(&buffer).unwrap();

                        if let MessageRequest::DepositRequest {
                            msg_id,
                            msg_nonce,
                            msg_ciphertext,
                        } = message
                        {
                            if locked_nonces.contains(&msg_nonce.to_vec()) {
                                println!("protocol_error");
                                return;
                            } else {
                                locked_nonces.push(msg_nonce.to_vec());
                            }
                            let plaintext = decrypt_message(
                                dh_shared_secret.as_bytes(),
                                &msg_nonce,
                                &msg_ciphertext,
                            );

                            buffer.clear();

                            if plaintext.is_empty() {
                                let deposit_response = MessageResponse::DepositResponse {
                                    msg_ciphertext,
                                    msg_nonce,
                                    msg_success: false,
                                };
        
                                //Send second deposit message
                                serialize_and_write(&mut stream, &deposit_response);
                                return;
                            }

                            //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                            let account_data: AccountIdHashAmount =
                                serde_json::from_slice(&plaintext).unwrap();

                            if account_data.hash != hashed_password {
                                eprintln!("Something is wron the hashes aren't identical");
                                return;
                            }

                            let _ = locked_user_table.get(&msg_id).unwrap().to_owned();

                            let user_balance =
                                locked_balance_table.get(&msg_id).unwrap().to_owned();

                            let old_balance = user_balance;
                            let calculate_balance: u64 = account_data.amount.parse().unwrap();
                            let new_balance = user_balance + calculate_balance;

                            let mut successful_newbalance = true;
                            match locked_balance_table.get_mut(&account_data.id) {
                                Some(value) => *value = new_balance,
                                None => {
                                    successful_newbalance = false;
                                }
                            }

                            buffer.clear();

                            //Serialized data to encrypt later
                            let serialized_data = serde_json::json!({
                                "id": "Bank",
                                "hash": hashed_password,
                                "amount" : account_data.amount,
                            });

                            let serialized_data_to_encrypt =
                                serde_json::to_string(&serialized_data)
                                    .expect("Failed to serialize data to JSON");

                            // Generate a 12-byte nonce
                            let mut nonce = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce);

                            // Now we use the DH secret as a key for AES256-GCM-SIV
                            let mut successful_decryption = true;
                            let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                            let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message

                            let aes_gcm_ciphertext = aes_gcm_cipher
                                .encrypt(
                                    aes_gcm_nonce,
                                    aead::Payload {
                                        msg: serialized_data_to_encrypt.as_bytes(),
                                        aad: aes_gcm_nonce,
                                    },
                                )
                                .unwrap_or_else(|_| {
                                    //Rollback
                                    if successful_newbalance {
                                        if let Some(value) =
                                            locked_balance_table.get_mut(&account_data.id)
                                        {
                                            *value = old_balance;
                                        }
                                    }
                                    successful_decryption = false;
                                    vec![]
                                });

                            if !successful_newbalance || !successful_decryption {
                                println!("protocol_error");
                                return;
                            }

                            let deposit_response = MessageResponse::DepositResponse {
                                msg_ciphertext: aes_gcm_ciphertext,
                                msg_nonce: nonce,
                                msg_success: true,
                            };

                            //Send fourth message
                            serialize_and_write(&mut stream, &deposit_response);
                            let amount = format!("{:.2}", calculate_balance as f64 / 100.0);

                            let json_result_final = json!({
                                "account": account_data.id,
                                "deposit": amount,
                            });

                            println!("{}", json_result_final);
                        }
                    }
                    MessageRequest::WithdrawRequest {
                        msg_id,
                        msg_nonce,
                        msg_ciphertext,
                    } => {
                        let mut locked_nonces = nonces.lock().unwrap();
                        if locked_nonces.contains(&msg_nonce.to_vec()) {
                            println!("protocol_error");
                            return;
                        } else {
                            locked_nonces.push(msg_nonce.to_vec());
                        }
                        //Generate ATM DH Public Key
                        let csprng = rand::thread_rng();
                        let bank_secret = EphemeralSecret::random_from_rng(csprng);
                        let bank_public = PublicKey::from(&bank_secret);

                        //Get user's password
                        let locked_user_table = users_table.lock().unwrap();

                        let mut locked_balance_table = balance_table.lock().unwrap();

                        let hashed_password_from_table =
                            locked_user_table.get(&msg_id).unwrap().to_owned();

                        if !locked_user_table.contains_key(&msg_id) {
                            eprintln!("Received invalid message from ATM, maybe MITM...");
                            return;
                        }

                        let plaintext = decrypt_message(
                            &hashed_password_from_table,
                            &msg_nonce,
                            &msg_ciphertext,
                        );

                        buffer.clear();

                        if plaintext.is_empty() {
                            let deposit_response = MessageResponse::DepositResponse {
                                msg_ciphertext,
                                msg_nonce,
                                msg_success: false,
                            };
    
                            //Send second deposit message
                            serialize_and_write(&mut stream, &deposit_response);
                            return;
                        }

                        //Deserialize decrypted data
                        let account_data: AccountDataIdDHHash =
                            serde_json::from_slice(&plaintext).unwrap();
                        let id = account_data.id;
                        let dh_uk = account_data.dh_uk;
                        let hashed_password = account_data.hash;

                        if msg_id != id {
                            eprintln!("Received invalid message from ATM, maybe MITM...");
                            return;
                        }

                        if hashed_password != hashed_password_from_table {
                            eprintln!("Something wrong");
                            return;
                        }

                        let public_key = PublicKey::from(dh_uk);
                        let dh_shared_secret = bank_secret.diffie_hellman(&public_key);

                        // Generate a 12-byte nonce
                        let mut response_nonce = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut response_nonce);

                        //Serialized data to encrypt later
                        let serialized_data = serde_json::json!({
                            "id": "Bank",
                            "dh_uk" : bank_public.to_bytes(),
                            "hash": hashed_password,
                        });
                        let serialized_data_to_encrypt = serde_json::to_string(&serialized_data)
                            .expect("Failed to serialize data to JSON");

                        let ciphertext = encrypt_message(
                            &hashed_password,
                            &serialized_data_to_encrypt,
                            &response_nonce,
                        );

                        let withdraw_response = MessageResponse::WithdrawResponse {
                            msg_ciphertext: ciphertext,
                            msg_nonce: response_nonce,
                            msg_success: true,
                        };

                        serialize_and_write(&mut stream, &withdraw_response);

                        let mut reader = BufReader::new(&stream);
                        let _ = reader.read_until(b'\n', &mut buffer).unwrap();

                        let message = serde_json::from_slice::<MessageRequest>(&buffer).unwrap();

                        if let MessageRequest::WithdrawRequest {
                            msg_id,
                            msg_nonce,
                            msg_ciphertext,
                        } = message
                        {
                            if locked_nonces.contains(&msg_nonce.to_vec()) {
                                println!("protocol_error");
                                return;
                            } else {
                                locked_nonces.push(msg_nonce.to_vec());
                            }
                            let plaintext = decrypt_message(
                                dh_shared_secret.as_bytes(),
                                &msg_nonce,
                                &msg_ciphertext,
                            );

                            buffer.clear();

                            if plaintext.is_empty() {
                                let deposit_response = MessageResponse::DepositResponse {
                                    msg_ciphertext,
                                    msg_nonce,
                                    msg_success: false,
                                };
        
                                //Send second deposit message
                                serialize_and_write(&mut stream, &deposit_response);
                                return;
                            }

                            //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                            let account_data: AccountIdHashAmount =
                                serde_json::from_slice(&plaintext).unwrap();

                            if account_data.hash != hashed_password {
                                eprintln!("Something is wron the hashes aren't identical");
                                return;
                            }

                            let _ = locked_user_table.get(&msg_id).unwrap().to_owned();

                            let user_balance =
                                locked_balance_table.get(&msg_id).unwrap().to_owned();

                            let old_balance = user_balance;
                            let calculate_balance: u64 = account_data.amount.parse().unwrap();

                            let mut successful_withdraw = true;
                            let mut positive_balance = true;
                            if calculate_balance > user_balance {
                                positive_balance = false;
                            } else {
                                let new_balance = user_balance - calculate_balance;
                                match locked_balance_table.get_mut(&account_data.id) {
                                    Some(value) => *value = new_balance,
                                    None => successful_withdraw = false,
                                }
                            }

                            buffer.clear();

                            //Serialized data to encrypt later
                            let serialized_data = serde_json::json!({
                                "id": "Bank",
                                "hash": hashed_password,
                                "amount" : account_data.amount,
                            });

                            let serialized_data_to_encrypt =
                                serde_json::to_string(&serialized_data)
                                    .expect("Failed to serialize data to JSON");

                            // Generate a 12-byte nonce
                            let mut nonce = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce);

                            // Now we use the DH secret as a key for AES256-GCM-SIV
                            let mut successful_decryption = true;
                            let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                            let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message

                            let aes_gcm_ciphertext = aes_gcm_cipher
                                .encrypt(
                                    aes_gcm_nonce,
                                    aead::Payload {
                                        msg: serialized_data_to_encrypt.as_bytes(),
                                        aad: aes_gcm_nonce,
                                    },
                                )
                                .unwrap_or_else(|_| {
                                    successful_decryption = false;
                                    if successful_withdraw {
                                        if let Some(value) =
                                            locked_balance_table.get_mut(&account_data.id)
                                        {
                                            *value = old_balance;
                                        }
                                    }
                                    vec![]
                                });

                            if !successful_withdraw || !successful_decryption {
                                println!("protocol_error");
                                return;
                            }
                            if !positive_balance {
                                let withdraw_response = MessageResponse::WithdrawResponse {
                                    msg_success: false,
                                    msg_nonce: nonce,
                                    msg_ciphertext: aes_gcm_ciphertext,
                                };
                                serialize_and_write(&mut stream, &withdraw_response);
                                return;
                            }

                            let withdraw_response = MessageResponse::WithdrawResponse {
                                msg_success: true,
                                msg_nonce: nonce,
                                msg_ciphertext: aes_gcm_ciphertext,
                            };
                            let amount = format!("{:.2}", calculate_balance as f64 / 100.0);

                            serialize_and_write(&mut stream, &withdraw_response);
                            let json_result_final = json!({
                                "account": account_data.id,
                                "withdraw": amount,
                            });

                            println!("{}", json_result_final);
                        }
                    }

                    MessageRequest::GetBalanceRequest {
                        msg_id,
                        msg_nonce,
                        msg_ciphertext,
                    } => {
                        let mut locked_nonces = nonces.lock().unwrap();
                        if locked_nonces.contains(&msg_nonce.to_vec()) {
                            println!("protocol_error");
                            return;
                        } else {
                            locked_nonces.push(msg_nonce.to_vec());
                        }
                        //Generate ATM DH Public Key
                        let csprng = rand::thread_rng();
                        let bank_secret = EphemeralSecret::random_from_rng(csprng);
                        let bank_public = PublicKey::from(&bank_secret);

                        //Get user's password
                        let locked_user_table = users_table.lock().unwrap();

                        let locked_balance_table = balance_table.lock().unwrap();

                        let hashed_password_from_table =
                            locked_user_table.get(&msg_id).unwrap().to_owned();

                        if !locked_user_table.contains_key(&msg_id) {
                            eprintln!("Received invalid message from ATM, maybe MITM...");
                            return;
                        }

                        let plaintext = decrypt_message(
                            &hashed_password_from_table,
                            &msg_nonce,
                            &msg_ciphertext,
                        );

                        buffer.clear();

                        if plaintext.is_empty() {
                            let deposit_response = MessageResponse::DepositResponse {
                                msg_ciphertext,
                                msg_nonce,
                                msg_success: false,
                            };
    
                            //Send second deposit message
                            serialize_and_write(&mut stream, &deposit_response);
                            return;
                        }

                        //Deserialize decrypted data
                        let account_data: AccountDataIdDHHash =
                            serde_json::from_slice(&plaintext).unwrap();
                        let id = account_data.id;
                        let dh_uk = account_data.dh_uk;
                        let hashed_password = account_data.hash;

                        if msg_id != id {
                            eprintln!("Received invalid message from ATM, maybe MITM...");
                            return;
                        }

                        if hashed_password != hashed_password_from_table {
                            eprintln!("Something wrong");
                            return;
                        }

                        let public_key = PublicKey::from(dh_uk);
                        let dh_shared_secret = bank_secret.diffie_hellman(&public_key);

                        // Generate a 12-byte nonce
                        let mut response_nonce = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut response_nonce);

                        //Serialized data to encrypt later
                        let serialized_data = serde_json::json!({
                            "id": "Bank",
                            "dh_uk" : bank_public.to_bytes(),
                            "hash": hashed_password,
                        });
                        let serialized_data_to_encrypt = serde_json::to_string(&serialized_data)
                            .expect("Failed to serialize data to JSON");

                        let ciphertext = encrypt_message(
                            &hashed_password,
                            &serialized_data_to_encrypt,
                            &response_nonce,
                        );

                        let getbalance_response = MessageResponse::GetBalanceResponse {
                            msg_ciphertext: ciphertext,
                            msg_nonce: response_nonce,
                            msg_success: true,
                        };

                        serialize_and_write(&mut stream, &getbalance_response);

                        let mut reader = BufReader::new(&stream);
                        let _ = reader.read_until(b'\n', &mut buffer).unwrap();
                        let message = serde_json::from_slice::<MessageRequest>(&buffer).unwrap();

                        if let MessageRequest::GetBalanceRequest {
                            msg_id,
                            msg_nonce,
                            msg_ciphertext,
                        } = message
                        {
                            if locked_nonces.contains(&msg_nonce.to_vec()) {
                                println!("protocol_error");
                                return;
                            } else {
                                locked_nonces.push(msg_nonce.to_vec());
                            }
                            let plaintext = decrypt_message(
                                dh_shared_secret.as_bytes(),
                                &msg_nonce,
                                &msg_ciphertext,
                            );

                            buffer.clear();

                            if plaintext.is_empty() {
                                let deposit_response = MessageResponse::DepositResponse {
                                    msg_ciphertext,
                                    msg_nonce,
                                    msg_success: false,
                                };
        
                                //Send second deposit message
                                serialize_and_write(&mut stream, &deposit_response);
                                return;
                            }

                            //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                            let account_data: AccountIDHash =
                                serde_json::from_slice(&plaintext).unwrap();

                            if account_data.hash != hashed_password {
                                eprintln!("Something is wron the hashes aren't identical");
                                return;
                            }

                            let _ = locked_user_table.get(&msg_id).unwrap().to_owned();

                            let user_balance =
                                locked_balance_table.get(&msg_id).unwrap().to_owned();

                            buffer.clear();

                            //let balance = format!("{:.2}", user_balance);
                            let balance = format!("{:.2}", user_balance as f64 / 100.0);
                            //Serialized data to encrypt later
                            let serialized_data = serde_json::json!({
                                "id": "Bank",
                                "hash": hashed_password,
                                "amount" : balance,
                            });

                            let serialized_data_to_encrypt =
                                serde_json::to_string(&serialized_data)
                                    .expect("Failed to serialize data to JSON");

                            // Generate a 12-byte nonce
                            let mut nonce = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce);

                            let ciphertext = encrypt_message(
                                dh_shared_secret.as_bytes(),
                                &serialized_data_to_encrypt,
                                &nonce,
                            );

                            let deposit_response = MessageResponse::GetBalanceResponse {
                                msg_success: true,
                                msg_nonce: nonce,
                                msg_ciphertext: ciphertext,
                            };

                            serialize_and_write(&mut stream, &deposit_response);

                            let json_result_final = json!({
                                "account": account_data.id,
                                "balance": balance,
                            });

                            println!("{}", json_result_final);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Error {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read from stream: {}", e);
        }
    }
}

fn main() -> std::io::Result<()> {
    let users_table: Arc<Mutex<HashMap<String, [u8; 32]>>> = Arc::new(Mutex::new(HashMap::new()));
    let balance_table: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let nonces = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

    let (port, auth_file): (String, String) = match bank_parser::cli() {
        Ok(matches) => {
            let port = matches.value_of("port").unwrap_or("3000").to_string();
            if !validate_port(&port) {
                exit(255);
            }

            let auth_file = matches
                .value_of("auth-file")
                .unwrap_or("bank.auth")
                .to_string();
            if !validate_file_name(&auth_file) {
                exit(255);
            }

            (port, auth_file)
        }
        Err(_) => {
            exit(255);
        }
    };

    // Generate RSA keypair
    let bits = 2048;
    let bank_private_key = RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap_or_else(|_| {
        eprintln!("Error generating RSA pair");
        exit(255);
    });

    let bank_public_key = RsaPublicKey::from(&bank_private_key);
    let arc_bank_private_key = Arc::new(bank_private_key);

    //Create bank.auth file, expects error if bank.auth exists
    let file_path = Path::new(&auth_file);
    if file_path.exists() {
        eprintln!("Error auth exists");
        exit(255);
    } else {
        match fs::write(file_path, "bank.auth\n") {
            Ok(_) => println!("Created"),
            Err(_) => {
                eprintln!("Error creating auth");
                exit(255);
            }
        }
    }

    //Write RSA Public Key to .auth file
    let public_key_pem = bank_public_key
        .to_pkcs1_pem(LineEnding::CRLF)
        .expect("Failed to covert public key to PEM");
    fs::write(file_path, public_key_pem).expect("Failed to write keys to file");

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap_or_else(|e| {
        eprintln!("Error host {}", e);
        exit(255);
    });

    set_handler(move || {
        //println!("Received SIGTERM, exiting...");
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                let clone_bank_private_key = Arc::clone(&arc_bank_private_key);
                let clone_users_table = Arc::clone(&users_table);
                let clone_balance_table = Arc::clone(&balance_table);
                let clone_nonces = Arc::clone(&nonces);
                let _ = thread::spawn(move || {
                    handle_client(
                        stream,
                        addr,
                        clone_bank_private_key,
                        clone_users_table,
                        clone_balance_table,
                        clone_nonces,
                    )
                });
            }
            Err(_) => {
                continue;
            }
        }
    }
}
