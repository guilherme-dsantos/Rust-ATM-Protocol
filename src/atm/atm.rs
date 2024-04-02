extern crate utils;
use hmac::{Hmac, Mac};
use pbkdf2::password_hash::{rand_core::OsRng, SaltString};
use rand::Rng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::TcpStream,
    path::Path,
};
use std::{io::BufRead, str::FromStr};
use std::{io::BufReader, process::exit};
use std::{rc::Rc, vec::Vec};
use textnonce::TextNonce;
use utils::{
    atm_parser,
    message_type::{MessageRequest, MessageResponse},
    operations::{AccountData, Operation},
};

type HmacSha256 = Hmac<Sha256>;

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

fn validate_balance(s: &str) {
    let pattern = regex::Regex::new(r"^(0|[1-9][0-9]*)\.[0-9]{2}$").unwrap();
    match pattern.is_match(s) {
        true => {
            let value = f64::from_str(s).unwrap_or_else(|_| {
                eprintln!("Failed to parse balance as a float.");
                exit(252);
            });
            if value < 10.00 {
                exit(301);
            }
        }
        false => {
            eprintln!("Not a match");
            exit(303);
        }
    }
}

fn validate_ip_address(s: &str) {
    println!("Validating IP: {}", &s);
    let pattern = regex::Regex::new(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$").unwrap();
    if !pattern.is_match(s) {
        println!("Regex pattern: {:?}", pattern);
        eprintln!("{}", &s);
        exit(252)
    }
}

fn validate_port(s: &str) {
    if let Ok(port) = s.parse::<u16>() {
        //u16 goes to 65535
        if port < 1024 {
            eprintln!("Port number out of valid range (1024-65535).");
            exit(259);
        }
    } else {
        eprintln!("Invalid input: not a number or too big.");
        exit(251);
    }
}
fn validate_account(account_name: &str) {
    /*if account_name == "." || account_name == ".." {
        println!("Special account name is valid: {}", account_name);
    } else {*/
    let valid_pattern = regex::Regex::new(r"^[_\-\.0-9a-z]+$").unwrap();
    let is_valid_length = !account_name.is_empty() && account_name.len() <= 122;
    let is_valid_name = valid_pattern.is_match(account_name);

    if is_valid_length && is_valid_name {
        println!("Account name is valid: {}", account_name);
    } else {
        eprintln!("Invalid account name: {}", account_name);
        exit(255);
    }
    //}
}

fn validate_file_name(file_name: &str) {
    let valid_pattern = regex::Regex::new(r"^[_\-\.0-9a-z]+$").unwrap();
    let is_valid_length = !file_name.is_empty() && file_name.len() <= 127;
    let is_valid_name = valid_pattern.is_match(file_name);
    let is_not_special = file_name != "." && file_name != "..";
    if !(is_valid_length && is_valid_name && is_not_special) {
        exit(277);
    }
}

fn create_card_file(file_path: &str) {
    let path = Path::new(file_path);
    if path.exists() {
        eprintln!("File already exists.");
        exit(279);
    } else if fs::write(path, "cardfile\n").is_err() {
        eprintln!("Failed to write to file.");
        exit(278);
    }
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
            let ip_address = matches
                .value_of("ip-address")
                .unwrap_or("127.0.0.1")
                .to_string();
            validate_ip_address(&ip_address);

            let port = matches.value_of("port").unwrap_or("3000").to_string();
            validate_port(&port);

            /*let account = matches.value_of("account").unwrap_or_else(|| {
                exit(251);
            }).parse::<u32>().unwrap_or_else(|_| {
                exit(252);
            });*/
            let account = matches
                .value_of("account")
                .unwrap_or_else(|| {
                    exit(251);
                })
                .to_string();
            validate_account(&account);

            let card_file = matches
                .value_of("card-file")
                .map(|s| s.to_string())
                .unwrap_or(format!("{}{}", account, ".card"));
            validate_file_name(&card_file);

            let operation = if matches.is_present("balance") {
                Operation::Balance(matches.value_of("balance").unwrap().to_string())
            } else if matches.is_present("deposit") {
                Operation::Deposit(matches.value_of("deposit").unwrap().to_string())
            } else if matches.is_present("withdraw") {
                Operation::Withdraw(matches.value_of("withdraw").unwrap().to_string())
            } else if matches.is_present("get") {
                Operation::Get(matches.value_of("get").unwrap().to_string())
            } else {
                eprintln!("An operation must be specified.");
                exit(254);
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

    match operation {
        Operation::Balance(balance) => {
            validate_balance(&balance);
            create_card_file(&card_file);

            // Generate RSA keypair
            let bits = 2048;
            let atm_private_key =
                RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap_or_else(|_| {
                    println!("Error generating RSA pair");
                    exit(255);
                });
            let atm_public_key = RsaPublicKey::from(&atm_private_key);
            let atm_public_key_bytes = atm_public_key
                .to_pkcs1_der()
                .expect("Failed to serialize RSA public key to DER")
                .into_vec();
            let nonce = TextNonce::new();
            let salt = SaltString::generate(&mut OsRng);
            let mut rng = rand::thread_rng();
            let pin: u64 = rng.gen_range(1_000_000_000_000_000..10_000_000_000_000_000); //16 digit pin
            let pin_bytes = pin.to_be_bytes();
            /*
            let password_hash = Pbkdf2
                .hash_password(pin_bytes, &salt)
                .unwrap_or_else(|e| {
                    eprint!("Error hashing password {}", e);
                    exit(255);
                })
                .to_string();
            */

            let mut hasher = Sha256::new();
            hasher.update(pin_bytes);
            hasher.update(&salt.to_string());
            let password_hash = hasher.finalize();
            let password_hash_bytes = password_hash.to_vec();

            //Read RSA Public Key From Bank.auth
            let file_path = Path::new(&auth_file);
            let string_path = file_path.to_str().unwrap_or_default();
            let bank_extracted_public_key = extract_public_key(string_path).unwrap_or_else(|e| {
                eprint!("Error reading bank key {}", e);
                exit(255);
            });

            let serialized_data = serde_json::json!({
                "id": account,
                "hash": password_hash_bytes,
                "balance" : balance,
            });

            let serialized_data_str =
                serde_json::to_string(&serialized_data).expect("Failed to serialize data to JSON");

            let mut rng = rand::thread_rng();
            let enc_data = bank_extracted_public_key
                .encrypt(&mut rng, Pkcs1v15Encrypt, &serialized_data_str.into_bytes())
                .expect("failed to encrypt");
            let mut hmac = HmacSha256::new_from_slice(enc_data.as_slice())
                .expect("HMAC can take key of any size");
            hmac.update(password_hash_bytes.as_slice());
            hmac.update(atm_public_key_bytes.as_slice());
            let hmac_result_bytes: Vec<u8> = hmac.finalize().into_bytes().to_vec();
            let rc_hmac = Rc::new(hmac_result_bytes);
            let rc_clone_hmac = Rc::clone(&rc_hmac);
            let rc_hmac_value = Rc::try_unwrap(rc_hmac).unwrap_or_else(|data| (*data).clone());

            //println!("{:?}", hmac_result_bytes);
            let registration_request = MessageRequest::RegistrationRequest {
                nonce: nonce.to_string(),
                ciphertext: enc_data,
                atm_public_key: atm_public_key_bytes,
                hmac: rc_hmac_value,
            };

            let serialized_message =
                serde_json::to_string(&registration_request).unwrap_or_else(|e| {
                    eprint!("Error serializing message {}", e);
                    exit(255);
                });
            println!("{}", serialized_message);
            let serialized_with_newline = format!("{}\n", serialized_message);
            stream
                .write_all(serialized_with_newline.as_bytes())
                .unwrap_or_else(|e| {
                    eprint!("Error sending message {}", e);
                    exit(255);
                });
            //Server vai ter que iterar o hash com por exemplo pbdfk2
            //println!("{}", registration_request);
            println!("{}", pin);

            let mut buffer = Vec::new();
            let mut reader = BufReader::new(&stream);

            let bytes_read = reader.read_until(b'\n', &mut buffer).unwrap();

            if bytes_read == 0 {
                println!("Connection closed");
                exit(0);
            }

            match serde_json::from_slice::<MessageResponse>(&buffer) {
                Ok(message) => match message {
                    MessageResponse::RegistrationResponse {
                        success,
                        ciphertext,
                        hmac,
                    } => {
                        if success {
                            let decrypted_data = atm_private_key
                                .decrypt(Pkcs1v15Encrypt, ciphertext.as_slice())
                                .expect("Error decrypting message");

                            //Deserialize decrypted data
                            let account_data: AccountData =
                                serde_json::from_slice(&decrypted_data).unwrap();
                            println!("{:?}", account_data);

                            //Clean buffer
                            buffer.clear();

                            //Check HMACs for Integrity
                            let rc_hmac_value = Rc::try_unwrap(rc_clone_hmac)
                                .unwrap_or_else(|data| (*data).clone());
                            if hmac != rc_hmac_value {
                                eprintln!("Integrity attack detected");
                                exit(255);
                            }

                            let mut file = OpenOptions::new().append(true).open(card_file).unwrap();
                            let content = format!("{}\n{}", account, pin).to_string();
                            if let Err(e) = writeln!(file, "{}", &content) {
                                eprintln!("Couldn't write to file: {}", e);
                            }
                        }
                    }
                },
                Err(e) => {
                    eprint!("Error receiving bank message {}", e);
                    exit(255);
                }
            }
        }
        Operation::Deposit(deposit) => {
            // Handle deposit operation
            println!("{}", deposit);
        }
        Operation::Withdraw(withdraw) => {
            // Handle withdraw operation
            println!("{}", withdraw);
        }
        Operation::Get(get) => {
            // Handle get operation
            println!("{}", get);
        }
    }

    Ok(())
}
