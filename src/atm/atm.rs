extern crate utils;

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv,
    Nonce, // Or `Aes128GcmSiv`
};

use blake3::Hasher;
use cipher::generic_array::GenericArray;
use pbkdf2::password_hash::{rand_core::OsRng, SaltString};
use rand::{Rng, RngCore};
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use serde_json::json;
use std::io::BufRead;
use std::process::exit;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::TcpStream,
    path::Path,
};
use std::{
    io::{self, BufReader},
    time::Duration,
};
use std::{rc::Rc, vec::Vec};
use textnonce::TextNonce;

use utils::{
    atm_parser,
    message_type::{MessageRequest, MessageResponse},
    operations::{AccountDHHash, AccountIdHashAmount, Operation},
    validate_functions::{
        validate_account, validate_file_name, validate_ip_address, validate_number, validate_port,
    },
};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn extract_public_key(file_path: &str) -> Result<RsaPublicKey, String> {
    match fs::read_to_string(file_path) {
        Ok(content) => {
            let public_key = RsaPublicKey::from_pkcs1_pem(&content)
                .map_err(|e| format!("Error parsing public key: {}", e))?;
            Ok(public_key)
        }
        Err(err) => Err(format!("Error reading public key from file: {}", err)),
    }
}

pub fn is_new_card(file_path: &str) -> bool{
    let path = Path::new(file_path);
    if path.exists() {
        return false;
    } 
    true
}

fn create_card_file(file_path: &str) {
    let path = Path::new(file_path);
    if path.exists() {
        eprintln!("File already exists.");
        exit(279);
    } else if fs::write(path, "").is_err() {
        eprintln!("Failed to write to file.");
        exit(278);
    }
}

fn serialize_and_send<T: serde::Serialize>(stream: &mut TcpStream, message: &T) {
    let serialized_message = serde_json::to_string(message).unwrap_or_else(|e| {
        eprint!("Error serializing message {}", e);
        exit(255);
    });

    let serialized_with_newline = format!("{}\n", serialized_message);
    stream
        .write_all(serialized_with_newline.as_bytes())
        .unwrap_or_else(|e| {
            eprint!("Error sending message {}", e);
            exit(255);
        });
}

fn generate_hash(pin_bytes: &[u8], salt: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pin_bytes);
    hasher.update(salt.as_bytes());
    let password_hash = hasher.finalize();
    *password_hash.as_bytes()
}

fn main() -> std::io::Result<()> {
    let (auth_file, ip_address, port, card_file, account, operation): (
        String,
        String,
        String,
        String,
        String,
        Operation,
    ) = match atm_parser::cli() {
        Ok(matches) => {
            let auth_file = matches
                .value_of("auth-file")
                .unwrap_or("bank.auth")
                .to_string(); //alterar para working directory
                              //validate_file_name(&auth_file);
            if !validate_file_name(&auth_file) {
                exit(255);
            }
            let ip_address = matches
                .value_of("ip-address")
                .unwrap_or("127.0.0.1")
                .to_string();
            if !validate_ip_address(&ip_address) {
                exit(255);
            }
            let port = matches.value_of("port").unwrap_or("3000").to_string();
            if !validate_port(&port) {
                exit(255);
            }
            let account = matches
                .value_of("account")
                .unwrap_or_else(|| {
                    exit(255);
                })
                .to_string();
            if !validate_account(&account) {
                exit(255);
            }

            let card_file = matches
                .value_of("card-file")
                .map(|s| s.to_string())
                .unwrap_or(format!("{}{}", account, ".card"));
            if !validate_file_name(&card_file){
                exit(255);
            }

            let operation = if matches.is_present("balance") {
                let value = matches.value_of("balance").unwrap().to_string();
                if !validate_number(&value, true) || !is_new_card(&card_file) {
                    exit(255);
                }
                Operation::Balance(value)
            } else if matches.is_present("deposit") {
                let value = matches.value_of("deposit").unwrap().to_string();
                if !validate_number(&value, false) {
                    exit(255);
                }
                Operation::Deposit(value)
            } else if matches.is_present("withdraw") {
                let value = matches.value_of("withdraw").unwrap().to_string();
                if !validate_number(&value, false) {
                    exit(255);
                }
                Operation::Withdraw(value)
            } else if matches.is_present("get") {
                Operation::Get
            } else {
                eprintln!("An operation must be specified.");
                exit(255);
            };
            (auth_file, ip_address, port, card_file, account, operation)
        }
        Err(e) => {
            eprint!("Erro {}", e);
            exit(253);
        }
    };

    //Connect to the bank
    let mut stream = TcpStream::connect(format!("{}:{}", ip_address, port)).unwrap_or_else(|_| {
        exit(254);
    });

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap_or_else(|_| {
            exit(63);
        });

    match operation {
        Operation::Balance(balance) => {

            /* This part of the code is to send a request to the bank to register the account */

            // Generate RSA keypair
            let bits = 2048;
            let atm_private_key =
                RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap_or_else(|_| {
                    eprintln!("Error generating RSA pair");
                    exit(255);
                });
            let atm_public_key = RsaPublicKey::from(&atm_private_key);
            let atm_public_key_bytes = atm_public_key
                .to_pkcs1_der()
                .expect("Failed to serialize RSA public key to DER")
                .into_vec();

            //Generate nonce to prevent replay attacks
            let nonce = TextNonce::new();

            //Generate salt to prevent rainbow-table attacks
            let salt = SaltString::generate(&mut OsRng);

            //Generate a strong random 16 digit pin
            let mut rng = rand::thread_rng();
            let pin: u64 = rng.gen_range(1_000_000_000_000_000..10_000_000_000_000_000);
            let pin_bytes = pin.to_be_bytes();

            let password_hash_slice = generate_hash(&pin_bytes, salt.as_ref());

            //Read Bank RSA Public Key From .auth file
            let file_path = Path::new(&auth_file);
            let string_path = file_path.to_str().unwrap_or_default();
            let bank_extracted_public_key = extract_public_key(string_path).unwrap_or_else(|e| {
                eprint!("Error reading bank key {}", e);
                exit(255);
            });

            //Serialize the data we need to encrypt
            let serialized_data = serde_json::json!({
                "id": account,
                "hash": password_hash_slice,
                "amount" : balance.replace('.', ""),
            });
            let data_to_be_encrypted =
                serde_json::to_string(&serialized_data).expect("Failed to serialize data to JSON");

            //Encrypt data with Bank RSA Public Key
            let mut rng = rand::thread_rng();
            let enc_data = bank_extracted_public_key
                .encrypt(
                    &mut rng,
                    Pkcs1v15Encrypt,
                    &data_to_be_encrypted.into_bytes(),
                )
                .expect("failed to encrypt");

            //Create HMAC to prevent integrity attacks
            let mut hmac = Hasher::new_keyed(&password_hash_slice);
            hmac.update(enc_data.as_slice());
            hmac.update(atm_public_key_bytes.as_slice());
            let hmac_bytes = hmac.finalize().as_bytes().to_owned();

            let rc_hmac = Rc::new(hmac_bytes);
            let rc_clone_hmac = Rc::clone(&rc_hmac);
            let rc_hmac_value = Rc::try_unwrap(rc_hmac).unwrap_or_else(|data| (*data));

            //Create request to the bank
            let registration_request = MessageRequest::RegistrationRequest {
                msg_nonce: nonce.as_bytes().to_vec(),
                msg_ciphertext: enc_data,
                msg_atm_public_key: atm_public_key_bytes,
                msg_hmac: rc_hmac_value.to_vec(),
            };

            //Senf first registration message
            serialize_and_send(&mut stream, &registration_request);

            /* This part of the code is to receive the response from the bank */

            let mut buffer = Vec::new();
            let mut reader = BufReader::new(&stream);

            let bytes_read = reader.read_until(b'\n', &mut buffer).unwrap();

            if bytes_read == 0 {
                exit(0);
            }

            let message = serde_json::from_slice::<MessageResponse>(&buffer).unwrap();

            if let MessageResponse::RegistrationResponse {
                msg_success,
                msg_ciphertext,
                msg_hmac,
            } = message
            {
                if msg_success {
                    //Decrypt the ciphertext with ATM private key
                    let decrypted_data = atm_private_key
                        .decrypt(Pkcs1v15Encrypt, msg_ciphertext.as_slice())
                        .expect("Error decrypting message");

                    //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                    let account_data: AccountIdHashAmount =
                        serde_json::from_slice(&decrypted_data).unwrap();

                    if account_data.hash != password_hash_slice {
                        eprintln!("Detected MITM attack");
                        exit(255);
                    }

                    //Clean buffer
                    buffer.clear();

                    //Check HMACs for Integrity
                    let rc_hmac_value =
                        Rc::try_unwrap(rc_clone_hmac).unwrap_or_else(|data| (*data));
                    if msg_hmac != rc_hmac_value {
                        eprintln!("Integrity attack detected");
                        exit(255);
                    }

                    create_card_file(&card_file);
                    let mut file = OpenOptions::new().append(true).open(card_file).unwrap();
                    let content = format!("{}\n{}", pin, salt.to_string().replace('"', ""));
                    if let Err(e) = writeln!(file, "{}", &content) {
                        eprintln!("Couldn't write to file: {}", e);
                    }
                }
            } else {
                println!("Received wrong message!");
            }

            let json_result = json!({
                "account": account,
                "initial_balance": balance,
            });

            println!("{}", json_result);
        }
        Operation::Deposit(deposit) => {
            //Generate ATM DH Public Key
            let csprng = rand::thread_rng();
            let atm_secret = EphemeralSecret::random_from_rng(csprng);
            let atm_public = PublicKey::from(&atm_secret);

            //Read PIN and Salt from card
            let path = Path::new(&card_file);
            let file = File::open(path)?;
            let reader = io::BufReader::new(file);
            let mut lines = reader.lines();
            let pin = lines.next().unwrap().unwrap();
            let salt = lines.next().unwrap().unwrap();
            let pin64: u64 = pin.parse().expect("Failed to parse string to u64");

            //Generate hashed password from PIN and Salt
            let pin_bytes = pin64.to_be_bytes();
            let password_hash_bytes = generate_hash(&pin_bytes, &salt);
            let client_dh_public_to_bytes = atm_public.as_bytes();

            //Serialized data to encrypt later
            let serialized_data = serde_json::json!({
                "id": account,
                "dh_uk" : client_dh_public_to_bytes,
                "hash": password_hash_bytes,
            });

            let serialized_data_to_encrypt =
                serde_json::to_string(&serialized_data).expect("Failed to serialize data to JSON");

            // Generate a 12-byte nonce
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);

            // Use the hash as a key for AES256-GCM-SIV
            let aes_gcm_key = GenericArray::from_slice(password_hash_bytes.as_slice());
            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
            let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message
            let aes_gcm_ciphertext = aes_gcm_cipher
                .encrypt(
                    aes_gcm_nonce,
                    serialized_data_to_encrypt.into_bytes().as_ref(),
                )
                .unwrap_or_else(|e| {
                    eprint!("Error encrypting with AES GCM {}", e);
                    exit(255);
                });

            let deposit_request = MessageRequest::DepositRequest {
                msg_id: account.clone(),
                msg_nonce: aes_gcm_nonce.to_vec(),
                msg_ciphertext: aes_gcm_ciphertext.to_vec(),
            };

            //Send first deposit message
            serialize_and_send(&mut stream, &deposit_request);

            /* This part of the code is to receive the response from the bank */

            let mut buffer = Vec::new();
            let mut reader = BufReader::new(&stream);

            //Receive second deposit message
            let _ = reader.read_until(b'\n', &mut buffer).unwrap();

            let message = serde_json::from_slice::<MessageResponse>(&buffer).unwrap();

            if let MessageResponse::DepositResponse {
                msg_success,
                msg_ciphertext,
                msg_nonce,
            } = message
            {
                if msg_success {
                    let response_aes_gcm_nonce = Nonce::from_slice(&msg_nonce); // 96-bits; unique per message
                                                                                //Decrypt the ciphertext with my hashed password
                    let plaintext = aes_gcm_cipher
                        .decrypt(response_aes_gcm_nonce, msg_ciphertext.as_ref())
                        .unwrap_or_else(|e| {
                            eprint!("Error decrypting {}", e);
                            exit(255);
                        });

                    //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                    let account_data: AccountDHHash = serde_json::from_slice(&plaintext).unwrap();

                    if account_data.hash != password_hash_bytes {
                        eprintln!("Something is wron the hashes aren't identical");
                        exit(255);
                    }

                    //Clean buffer
                    buffer.clear();

                    let public_key = PublicKey::from(account_data.dh_uk);
                    let dh_shared_secret = atm_secret.diffie_hellman(&public_key);

                    //Serialized data to encrypt later
                    let serialized_data = serde_json::json!({
                        "id": account,
                        "hash": password_hash_bytes,
                        "amount" : deposit.replace('.', ""),
                    });

                    let serialized_data_to_encrypt = serde_json::to_string(&serialized_data)
                        .expect("Failed to serialize data to JSON");

                    // Generate a 12-byte nonce
                    let mut nonce = [0u8; 12];
                    rand::thread_rng().fill_bytes(&mut nonce);

                    // Now we use the DH secret as a key for AES256-GCM-SIV
                    let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                    let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                    let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message
                    let aes_gcm_ciphertext = aes_gcm_cipher
                        .encrypt(
                            aes_gcm_nonce,
                            serialized_data_to_encrypt.into_bytes().as_ref(),
                        )
                        .unwrap_or_else(|e| {
                            eprint!("Error encrypting with AES GCM {}", e);
                            exit(255);
                        });

                    let deposit_request = MessageRequest::DepositRequest {
                        msg_id: account.clone(),
                        msg_nonce: aes_gcm_nonce.to_vec(),
                        msg_ciphertext: aes_gcm_ciphertext.to_vec(),
                    };

                    //Send third deposit message
                    serialize_and_send(&mut stream, &deposit_request);

                    //Receive fourth deposit message
                    let mut reader = BufReader::new(&stream);
                    let _ = reader.read_until(b'\n', &mut buffer).unwrap();
                    let message = serde_json::from_slice::<MessageResponse>(&buffer).unwrap();
                    if let MessageResponse::DepositResponse {
                        msg_success,
                        msg_ciphertext,
                        msg_nonce,
                    } = message
                    {
                        if msg_success {
                            // Use the hash as a key for AES256-GCM-SIV
                            let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                            let aes_gcm_nonce = Nonce::from_slice(&msg_nonce); // 96-bits; unique per message
                            let plaintext = aes_gcm_cipher
                                .decrypt(aes_gcm_nonce, msg_ciphertext.as_ref())
                                .unwrap_or_else(|e| {
                                    eprint!("Error decrypting {}", e);
                                    exit(255);
                                });

                            //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                            let account_data: AccountIdHashAmount =
                                serde_json::from_slice(&plaintext).unwrap();

                            if account_data.hash != password_hash_bytes {
                                eprintln!("Something is wron the hashes aren't identical");
                                exit(255);
                            }

                            let json_result_final = json!({
                                "account": account,
                                "deposit": deposit,
                            });

                            println!("{}", json_result_final);
                        }
                    }
                }
            } else {
                println!("Received wrong message!");
            }
        }

        Operation::Withdraw(withdraw) => {
            //Generate ATM DH Public Key
            let csprng = rand::thread_rng();
            let atm_secret = EphemeralSecret::random_from_rng(csprng);
            let atm_public = PublicKey::from(&atm_secret);

            //Read PIN and Salt from card
            let path = Path::new(&card_file);
            let file = File::open(path)?;
            let reader = io::BufReader::new(file);
            let mut lines = reader.lines();
            let pin = lines.next().unwrap().unwrap();
            let salt = lines.next().unwrap().unwrap();
            let pin64: u64 = pin.parse().expect("Failed to parse string to u64");

            //Generate hashed password from PIN and Salt
            let pin_bytes = pin64.to_be_bytes();
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pin_bytes);
            hasher.update(salt.as_bytes());
            let password_hash = hasher.finalize();
            let password_hash_bytes = password_hash.as_bytes();
            let client_dh_public_to_bytes = atm_public.as_bytes();

            //Serialized data to encrypt later
            let serialized_data = serde_json::json!({
                "id": account,
                "dh_uk" : client_dh_public_to_bytes,
                "hash": password_hash_bytes,
            });

            let serialized_data_to_encrypt =
                serde_json::to_string(&serialized_data).expect("Failed to serialize data to JSON");

            // Generate a 12-byte nonce
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);

            // Use the hash as a key for AES256-GCM-SIV

            let aes_gcm_key = GenericArray::from_slice(password_hash_bytes.as_slice());
            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
            let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message
            let aes_gcm_ciphertext = aes_gcm_cipher
                .encrypt(
                    aes_gcm_nonce,
                    serialized_data_to_encrypt.into_bytes().as_ref(),
                )
                .unwrap_or_else(|e| {
                    eprint!("Error encrypting with AES GCM {}", e);
                    exit(255);
                });

            let withdraw_request = MessageRequest::WithdrawRequest {
                msg_id: account.clone(),
                msg_nonce: aes_gcm_nonce.to_vec(),
                msg_ciphertext: aes_gcm_ciphertext.to_vec(),
            };

            serialize_and_send(&mut stream, &withdraw_request);

            /* This part of the code is to receive the response from the bank */

            let mut buffer = Vec::new();
            let mut reader = BufReader::new(&stream);

            let _ = reader.read_until(b'\n', &mut buffer).unwrap();

            let message = serde_json::from_slice::<MessageResponse>(&buffer).unwrap();

            if let MessageResponse::WithdrawResponse {
                msg_success,
                msg_ciphertext,
                msg_nonce,
            } = message
            {
                if msg_success {
                    let response_aes_gcm_nonce = Nonce::from_slice(&msg_nonce); // 96-bits; unique per message
                                                                                //Decrypt the ciphertext with my hashed password
                    let plaintext = aes_gcm_cipher
                        .decrypt(response_aes_gcm_nonce, msg_ciphertext.as_ref())
                        .unwrap_or_else(|e| {
                            eprint!("Error decrypting {}", e);
                            exit(255);
                        });

                    //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                    let account_data: AccountDHHash = serde_json::from_slice(&plaintext).unwrap();

                    if account_data.hash != *password_hash_bytes {
                        eprintln!("Something is wron the hashes aren't identical");
                        exit(255);
                    }

                    //Clean buffer
                    buffer.clear();

                    let public_key = PublicKey::from(account_data.dh_uk);
                    let dh_shared_secret = atm_secret.diffie_hellman(&public_key);

                    //Serialized data to encrypt later
                    let serialized_data = serde_json::json!({
                        "id": account,
                        "hash": password_hash_bytes,
                        "amount" : withdraw.replace('.', ""),
                    });

                    let serialized_data_to_encrypt = serde_json::to_string(&serialized_data)
                        .expect("Failed to serialize data to JSON");

                    // Generate a 12-byte nonce
                    let mut nonce = [0u8; 12];
                    rand::thread_rng().fill_bytes(&mut nonce);

                    // Now we use the DH secret as a key for AES256-GCM-SIV
                    let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                    let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                    let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message
                    let aes_gcm_ciphertext = aes_gcm_cipher
                        .encrypt(
                            aes_gcm_nonce,
                            serialized_data_to_encrypt.into_bytes().as_ref(),
                        )
                        .unwrap_or_else(|e| {
                            eprint!("Error encrypting with AES GCM {}", e);
                            exit(255);
                        });

                    let withdraw_request = MessageRequest::WithdrawRequest {
                        msg_id: account.clone(),
                        msg_nonce: aes_gcm_nonce.to_vec(),
                        msg_ciphertext: aes_gcm_ciphertext.to_vec(),
                    };

                    serialize_and_send(&mut stream, &withdraw_request);

                    let mut reader = BufReader::new(&stream);

                    let _ = reader.read_until(b'\n', &mut buffer).unwrap();

                    let message = serde_json::from_slice::<MessageResponse>(&buffer).unwrap();

                    if let MessageResponse::WithdrawResponse {
                        msg_success,
                        msg_nonce,
                        msg_ciphertext,
                    } = message
                    {
                        if msg_success {
                            // Use the hash as a key for AES256-GCM-SIV
                            let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                            let aes_gcm_nonce = Nonce::from_slice(&msg_nonce); // 96-bits; unique per message
                            let plaintext = aes_gcm_cipher
                                .decrypt(aes_gcm_nonce, msg_ciphertext.as_ref())
                                .unwrap_or_else(|e| {
                                    eprint!("Error decrypting {}", e);
                                    exit(255);
                                });

                            //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                            let account_data: AccountIdHashAmount =
                                serde_json::from_slice(&plaintext).unwrap();

                            if &account_data.hash != password_hash_bytes {
                                eprintln!("Something is wron the hashes aren't identical");
                                exit(255);
                            }

                            let json_result_final = json!({
                                "account": account,
                                "withdraw": withdraw,
                            });

                            println!("{}", json_result_final);
                        }
                    }
                }
            } else {
                println!("Received wrong message!");
            }
        }

        Operation::Get => {
            //Generate ATM DH Public Key
            let csprng = rand::thread_rng();
            let atm_secret = EphemeralSecret::random_from_rng(csprng);
            let atm_public = PublicKey::from(&atm_secret);

            //Read PIN and Salt from card
            let path = Path::new(&card_file);
            let file = File::open(path)?;
            let reader = io::BufReader::new(file);
            let mut lines = reader.lines();
            let pin = lines.next().unwrap().unwrap();
            let salt = lines.next().unwrap().unwrap();
            let pin64: u64 = pin.parse().expect("Failed to parse string to u64");

            //Generate hashed password from PIN and Salt
            let pin_bytes = pin64.to_be_bytes();
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pin_bytes);
            hasher.update(salt.as_bytes());
            let password_hash = hasher.finalize();
            let password_hash_bytes = password_hash.as_bytes();
            let client_dh_public_to_bytes = atm_public.as_bytes();

            //Serialized data to encrypt later
            let serialized_data = serde_json::json!({
                "id": account,
                "dh_uk" : client_dh_public_to_bytes,
                "hash": password_hash_bytes,
            });

            let serialized_data_to_encrypt =
                serde_json::to_string(&serialized_data).expect("Failed to serialize data to JSON");

            // Generate a 12-byte nonce
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);

            // Use the hash as a key for AES256-GCM-SIV
            let aes_gcm_key = GenericArray::from_slice(password_hash_bytes.as_slice());
            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
            let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message
            let aes_gcm_ciphertext = aes_gcm_cipher
                .encrypt(
                    aes_gcm_nonce,
                    serialized_data_to_encrypt.into_bytes().as_ref(),
                )
                .unwrap_or_else(|e| {
                    eprint!("Error encrypting with AES GCM {}", e);
                    exit(255);
                });

            let getbalance_request = MessageRequest::GetBalanceRequest {
                msg_id: account.clone(),
                msg_nonce: aes_gcm_nonce.to_vec(),
                msg_ciphertext: aes_gcm_ciphertext.to_vec(),
            };

            serialize_and_send(&mut stream, &getbalance_request);

            /* This part of the code is to receive the response from the bank */

            let mut buffer = Vec::new();
            let mut reader = BufReader::new(&stream);

            let _ = reader.read_until(b'\n', &mut buffer).unwrap();

            let message = serde_json::from_slice::<MessageResponse>(&buffer).unwrap();

            if let MessageResponse::GetBalanceResponse {
                msg_success,
                msg_ciphertext,
                msg_nonce,
            } = message
            {
                if msg_success {
                    let response_aes_gcm_nonce = Nonce::from_slice(&msg_nonce); // 96-bits; unique per message
                                                                                //Decrypt the ciphertext with my hashed password
                    let plaintext = aes_gcm_cipher
                        .decrypt(response_aes_gcm_nonce, msg_ciphertext.as_ref())
                        .unwrap_or_else(|e| {
                            eprint!("Error decrypting {}", e);
                            exit(255);
                        });

                    //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                    let account_data: AccountDHHash = serde_json::from_slice(&plaintext).unwrap();

                    if account_data.hash != *password_hash_bytes {
                        eprintln!("Something is wron the hashes aren't identical");
                        exit(255);
                    }

                    //Clean buffer
                    buffer.clear();

                    let public_key = PublicKey::from(account_data.dh_uk);
                    let dh_shared_secret = atm_secret.diffie_hellman(&public_key);

                    //Serialized data to encrypt later
                    let serialized_data = serde_json::json!({
                        "id": account,
                        "hash": password_hash_bytes,
                    });

                    let serialized_data_to_encrypt = serde_json::to_string(&serialized_data)
                        .expect("Failed to serialize data to JSON");

                    // Generate a 12-byte nonce
                    let mut nonce = [0u8; 12];
                    rand::thread_rng().fill_bytes(&mut nonce);

                    // Now we use the DH secret as a key for AES256-GCM-SIV
                    let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                    let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                    let aes_gcm_nonce = Nonce::from_slice(&nonce); // 96-bits; unique per message

                    let aes_gcm_ciphertext = aes_gcm_cipher
                        .encrypt(
                            aes_gcm_nonce,
                            serialized_data_to_encrypt.into_bytes().as_ref(),
                        )
                        .unwrap_or_else(|e| {
                            eprint!("Error encrypting with AES GCM {}", e);
                            exit(255);
                        });

                    let getbalance_request = MessageRequest::GetBalanceRequest {
                        msg_id: account.clone(),
                        msg_nonce: aes_gcm_nonce.to_vec(),
                        msg_ciphertext: aes_gcm_ciphertext.to_vec(),
                    };

                    serialize_and_send(&mut stream, &getbalance_request);

                    let mut reader = BufReader::new(&stream);

                    let _ = reader.read_until(b'\n', &mut buffer).unwrap();

                    let message = serde_json::from_slice::<MessageResponse>(&buffer).unwrap();

                    if let MessageResponse::GetBalanceResponse {
                        msg_success,
                        msg_nonce,
                        msg_ciphertext,
                    } = message
                    {
                        if msg_success {
                            // Use the hash as a key for AES256-GCM-SIV
                            let aes_gcm_key = GenericArray::from_slice(dh_shared_secret.as_bytes());
                            let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
                            let aes_gcm_nonce = Nonce::from_slice(&msg_nonce); // 96-bits; unique per message
                            let plaintext = aes_gcm_cipher
                                .decrypt(aes_gcm_nonce, msg_ciphertext.as_ref())
                                .unwrap_or_else(|e| {
                                    eprint!("Error decrypting {}", e);
                                    exit(255);
                                });

                            //Deserialize decrypted data into struct AccoundData(id,hash,balance)
                            let account_data: AccountIdHashAmount =
                                serde_json::from_slice(&plaintext).unwrap();

                            if &account_data.hash != password_hash_bytes {
                                eprintln!("Something is wron the hashes aren't identical");
                                exit(255);
                            }

                            let json_result_final = json!({
                                "account": account,
                                "balance": account_data.amount,
                            });

                            println!("{}", json_result_final);
                        }
                    }
                }
            } else {
                println!("Received wrong message!");
            }
        }
    }

    Ok(())
}
