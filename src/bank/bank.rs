extern crate utils;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::Pkcs1v15Encrypt;
use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey};

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::exit;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::{
    fs::{self},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    thread,
};
use utils::{
    bank_parser,
    message_type::{MessageRequest, MessageResponse},
    operations::AccountData,
};
type HmacSha256 = Hmac<Sha256>;
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn handle_client(
    mut stream: TcpStream,
    _addr: SocketAddr,
    bank_private_key: Arc<RsaPrivateKey>,
    users_table: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    balance_table: Arc<Mutex<HashMap<String, f64>>>,
    nonces: Arc<Mutex<Vec<String>>>,
) {
    let mut buffer = Vec::new();
    let mut reader = BufReader::new(&stream);

    let bytes_read = reader.read_until(b'\n', &mut buffer).unwrap();

    if bytes_read == 0 {
        println!("Connection closed");
        return;
    }
    match serde_json::from_slice::<MessageRequest>(&buffer) {
        Ok(message) => match message {
            MessageRequest::RegistrationRequest {
                ciphertext,
                atm_public_key,
                hmac,
                nonce,
            } => {
                //Decrypt received data
                let decrypted_data = bank_private_key
                    .decrypt(Pkcs1v15Encrypt, ciphertext.as_slice())
                    .expect("Error decrypting message");

                //Deserialize decrypted data
                let account_data: AccountData = serde_json::from_slice(&decrypted_data).unwrap();
                println!("{:?}", account_data);
                let account_id: String = account_data.id;
                let hashed_password = account_data.hash;
                let balance = account_data.balance;
                let balancef64: f64 = balance.parse().unwrap_or_else(|e| {
                    eprintln!("Error parsing string to f64 {}", e);
                    exit(255);
                });

                buffer.clear();

                //Recalculate HMAC for Integrity
                let mut recalculated_hmac = HmacSha256::new_from_slice(ciphertext.as_slice())
                    .expect("HMAC can take key of any size");
                recalculated_hmac.update(&hashed_password);
                recalculated_hmac.update(atm_public_key.as_slice());
                let recalculated_hmac_result_bytes: Vec<u8> =
                    recalculated_hmac.finalize().into_bytes().to_vec();

                //Encrypt with ATM Public Key
                let mut rng = rand::thread_rng();
                let received_atm_public_key = RsaPublicKey::from_pkcs1_der(&atm_public_key)
                    .map_err(|e| format!("Error parsing public key: {}", e))
                    .unwrap();
                let enc_data = received_atm_public_key
                    .encrypt(&mut rng, Pkcs1v15Encrypt, &decrypted_data)
                    .expect("failed to encrypt");

                let rc_encrypted_data = Rc::new(enc_data);
                let rc_clone_encrypted_data = Rc::clone(&rc_encrypted_data);
                let rc_recalculated_hmac = Rc::new(recalculated_hmac_result_bytes);
                let rc_clone_recalculated_hmac = Rc::clone(&rc_recalculated_hmac);
                let rc_clone_recalculated_hmac2 = Rc::clone(&rc_recalculated_hmac);

                /*Create Bad Registration Message in case to let ATM know if something went wrong*/
                let bad_registration_response = MessageResponse::RegistrationResponse {
                    success: false,
                    ciphertext: Rc::try_unwrap(rc_encrypted_data)
                        .unwrap_or_else(|data| (*data).clone()),
                    hmac: Rc::try_unwrap(rc_recalculated_hmac)
                        .unwrap_or_else(|data| (*data).clone()),
                };
                let serialized_bad_message = serde_json::to_string(&bad_registration_response)
                    .unwrap_or_else(|e| {
                        eprint!("Error serializing message {}", e);
                        exit(255);
                    });
                let serialized_bad_with_newline = format!("{}\n", serialized_bad_message);

                //Check for Repeated Nonces for Replay Attacks
                let mut locked_nonces = nonces.lock().unwrap();
                if locked_nonces.contains(&nonce) {
                    println!("Replay attack detected");
                    stream
                        .write_all(serialized_bad_with_newline.as_bytes())
                        .unwrap_or_else(|e| {
                            eprint!("Error sending message {}", e);
                            exit(255);
                        });
                    return;
                } else {
                    locked_nonces.push(nonce);
                }

                //Check if message wasn't changed camparing HMACs for Integrity Attacks
                let rc_clone_hmac_value = Rc::try_unwrap(rc_clone_recalculated_hmac)
                    .unwrap_or_else(|data| (*data).clone());
                if rc_clone_hmac_value != hmac {
                    print!("Integrity attack detected!");
                    stream
                        .write_all(serialized_bad_with_newline.as_bytes())
                        .unwrap_or_else(|e| {
                            eprint!("Error sending message {}", e);
                            exit(255);
                        });
                    return;
                }

                let rc_account_id = Rc::new(account_id);
                let rc_clone_account = Rc::clone(&rc_account_id);
                let rc_value_clone_account =
                    Rc::try_unwrap(rc_account_id).unwrap_or_else(|data| (*data).clone());
                let rc_value_clone_account2 =
                    Rc::try_unwrap(rc_clone_account).unwrap_or_else(|data| (*data).clone());

                //Check if account is already registred, register account if not
                let mut locked_users_table = users_table.lock().unwrap();
                if let std::collections::hash_map::Entry::Vacant(e) =
                    locked_users_table.entry(rc_value_clone_account)
                {
                    e.insert(hashed_password);
                    println!("{}", balancef64);
                } else {
                    eprintln!("Account already registred");
                    stream
                        .write_all(serialized_bad_with_newline.as_bytes())
                        .unwrap_or_else(|e| {
                            eprint!("Error sending message {}", e);
                            exit(255);
                        });
                    return;
                }

                let mut locked_balance_table = balance_table.lock().unwrap();
                if let std::collections::hash_map::Entry::Vacant(e) =
                    locked_balance_table.entry(rc_value_clone_account2)
                {
                    e.insert(balancef64);
                    println!("{}", balancef64);
                } else {
                    stream
                        .write_all(serialized_bad_with_newline.as_bytes())
                        .unwrap_or_else(|e| {
                            eprint!("Error sending message {}", e);
                            exit(255);
                        });
                    return;
                }

                //Create Ok Registration Response to let ATM know the account was created successfully
                let ok_registration_response = MessageResponse::RegistrationResponse {
                    success: true,
                    ciphertext: Rc::try_unwrap(rc_clone_encrypted_data)
                        .unwrap_or_else(|data| (*data).clone()),
                    hmac: Rc::try_unwrap(rc_clone_recalculated_hmac2)
                        .unwrap_or_else(|data| (*data).clone()),
                };
                let serialized_ok_message = serde_json::to_string(&ok_registration_response)
                    .unwrap_or_else(|e| {
                        eprint!("Error serializing message {}", e);
                        exit(255);
                    });
                let serialized_ok_with_newline = format!("{}\n", serialized_ok_message);

                stream
                    .write_all(serialized_ok_with_newline.as_bytes())
                    .unwrap_or_else(|e| {
                        eprint!("Error sending message {}", e);
                        exit(255);
                    });
            }
            MessageRequest::DepositRequest {
                id,
                nonce,
                ciphertext,
                hmac,
            } => {
                todo!()
            }
        },
        Err(e) => {
            println!("Error {}", e);
        }
    }
}

fn main() -> std::io::Result<()> {
    let users_table: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let balance_table: Arc<Mutex<HashMap<String, f64>>> = Arc::new(Mutex::new(HashMap::new()));
    let nonces = Arc::new(Mutex::new(Vec::<String>::new()));

    let (port, auth_file): (String, String) = match bank_parser::cli() {
        Ok(matches) => {
            let port = matches.value_of("port").unwrap_or("3000").to_string();

            let auth_file = matches
                .value_of("auth-file")
                .unwrap_or("bank.auth")
                .to_string();

            (port, auth_file)
        }
        Err(_) => {
            exit(255);
        }
    };

    // Generate RSA keypair
    let bits = 2048;
    let bank_private_key = RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap_or_else(|_| {
        println!("Error generating RSA pair");
        exit(255);
    });

    let bank_public_key = RsaPublicKey::from(&bank_private_key);
    let arc_bank_private_key = Arc::new(bank_private_key);

    //Create bank.auth file, expects error if bank.auth exists
    let file_path = Path::new(&auth_file);
    if file_path.exists() {
        eprint!("Error auth exists");
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

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("ATM connected from {}", addr);
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
            Err(err) => {
                println!("Couldn't accept ATM request {}", err);
                continue;
            }
        }
    }
}
