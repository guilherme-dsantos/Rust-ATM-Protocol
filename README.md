# ATM-Bank Protocol

This application consists of two executables, `atm` and `bank`, which are built using Rust.

# Table of Contents

1. [ATM-Bank Protocol](#atm-bank-protocol)
2. [Prerequisites](#prerequisites)
3. [Security Features and Protocol](#security-features-and-protocol)
   - [Account Registration Phase](#account-registration-phase)
   - [Operations Phase](#operations-phase)
   - [Cryptographic Algorithms Used](#cryptographic-algorithms-used)
   - [Specific Attacks Countered](#specific-attacks-countered)
4. [Primary Libraries Used](#primary-libraries-used)
5. [Building the Application](#building-the-application)
6. [Running the Application](#running-the-application)
   - [Bank](#bank)
   - [ATM](#atm)
7. [Future Improvements](#future-improvements)
8. [Authors](#authors)


## Prerequisites

- Rust: You can download Rust from the [official website](https://www.rust-lang.org/tools/install).

## Security Features and Protocol

This application employs various cryptographic techniques to ensure secure communication between the ATM and the bank.

### Account Registration Phase

During this phase, the ATM generates a 16-digit random PIN and a salt, which are hashed to create a shared secret between the ATM and the Bank. The hashed password and initial balance are sent to the bank with the bank's RSA public key for account registration. The bank records this information and sends a response back to the ATM. The PIN is stored on the card for future authentication.

### Operations Phase

Messages exchanged between the ATM and the bank are encrypted using AES-GCM. This provides both confidentiality and integrity for the messages. A unique nonce is generated for each message to mitigate replay attacks and ensure that the same plaintext message will produce different ciphertexts each time it is encrypted.

### Cryptographic Algorithms Used: ###
- **RSA:** Used for encrypting messages to ensure that only the intended recipient can decrypt them.
- **AES-GCM (Galois/Counter Mode):** Provides authenticated encryption, ensuring data confidentiality and integrity.
- **Blake3:** Used for generating HMACs, ensuring data integrity.
- **ECDH (Elliptic Curve Diffie-Hellman):** Ensures forward secrecy.

### Specific Attacks Countered

**Tampering Attacks:**
Blake3 for HMAC generation and AES-GCM for encryption protect against unauthorized data modification.

```rust
// Recreate HMAC
let mut new_hmac = Hasher::new_keyed(&hashed_password);

new_hmac.update(msg_ciphertext.as_slice());

new_hmac.update(&msg_nonce);

let hmac_bytes = new_hmac.finalize().as_bytes().to_owned();

// Check if HMACs are the same
if msg_hmac != hmac_bytes {

    eprintln!("Integrity attack detected!");
    return;
}


// AES-GCM Encryption
let ciphertext = encrypt_message(dh_shared_secret.as_bytes(), &serialized_data_to_encrypt, &nonce);


fn encrypt_message(key: &[u8], data_to_encrypt: &str, nonce: &[u8]) -> Vec<u8> {

    let aes_gcm_key = GenericArray::from_slice(key);
    let aes_gcm_cipher = Aes256GcmSiv::new(aes_gcm_key);
    let aes_gcm_nonce = Nonce::from_slice(nonce); // 96-bits; unique per message
    aes_gcm_cipher.encrypt(aes_gcm_nonce, aead::Payload {

        msg: data_to_encrypt.as_bytes(),
        aad: aes_gcm_nonce,
    }).unwrap_or_else(|e| {

        eprintln!("Error encrypting with AES GCM {}", e);
        exit(63);
    })

}
```

**Replay Attacks:**
Use of unique nonces for each message ensures that messages cannot be replayed by an attacker.

```rust
MessageRequest::RegistrationRequest {
    msg_ciphertext,
    msg_hmac,

    msg_nonce,
} => {
    // Check for Repeated Nonces for Replay Attacks

    let mut locked_nonces = nonces.lock().unwrap();
    if locked_nonces.contains(&msg_nonce.to_vec()) {
        println!("protocol_error");

        return;
    } else {

        locked_nonces.push(msg_nonce.to_vec());
    }
    // ...
}
```

**Rainbow Table Attacks:**
Passwords are hashed with a unique salt before storage to prevent attacks using precomputed tables.

```rust
// Generate salt to prevent rainbow-table attacks
let salt = SaltString::generate(&mut OsRng);

// Generate a strong random 16 digit pin

let mut rng = rand::thread_rng();
let pin: u64 = rng.gen_range(1_000_000_000_000_000..10_000_000_000_000_000);
let pin_bytes = pin.to_be_bytes();
let password_hash_slice = generate_hash(&pin_bytes, salt.as_ref());
```

**Two-Time Pad Vulnerability:**
Unique nonces are used for each message to prevent encryption vulnerabilities.

```rust
// Generate a 12-byte nonce
let mut response_nonce = [0u8; 12];
rand::thread_rng().fill_bytes(&mut response_nonce);
let ciphertext = encrypt_message(&hashed_password, &data_to_be_encrypted, &response_nonce);
```

**Identity Spoofing and Interception of Sensitive Information:**
RSA public key encryption ensures that only the intended recipient (the bank) can decrypt the messages, preventing unauthorized access.

### Primary Libraries Used

- **Clap:** For parsing command-line arguments. https://docs.rs/clap/latest/clap/
- **RSA:** For RSA asymmetric encryption. https://docs.rs/rsa/latest/rsa/
- **x25519-dalek:** For Elliptic-Curve Diffie-Hellman key exchange. https://docs.rs/x25519-dalek/
- **aes-gcm-siv:** For AES-GCM encryption. https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/
- **Blake3:** For cryptographic hashing. https://docs.rs/blake3/latest/blake3/

## Building the Application

To compile the program, navigate to the directory containing the source code and run the following command:

```bash
cargo build --release
```

This will create the executable files `atm` and `bank` in the `target/release` directory.

## Running the Application

### Bank

To run the `bank` executable, use the following command:

```bash

./target/release/bank [-p <port>] [-s <auth-file>]
```

Replace `<port>` with the port number you want the bank server to listen on, and `<auth-file>` with the path to the file containing the authentication information.

### ATM

To run the `atm` executable, use one of the following commands depending on the operation you want to perform:

- **Check Balance**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -n <balance>
  ```

- **Deposit Money**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -d <amount>
  ```

- **Withdraw Money**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -w <amount>
  ```

- **Get Account Details**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -g
  ```

In these commands, replace `<auth-file>` with the path to the file containing the authentication information, `<ip-address>` with the IP address of the bank server, `<port>` with the port number of the bank server, `<card-file>` with the path to the file containing the card information, `<account>` with the account name, `<balance>` with the balance amount, and `<amount>` with the deposit or withdrawal amount.

## Future Improvements

1. Non-Repudiation: Not implemented due to time constraints.
2. Generate timestamp based nonces. https://docs.rs/textnonce/latest/textnonce/
3. Add timestamps to each message

## Authors
- Guilherme Santos (fc62533)
- Luís Viana (fc62516)

@FCUL<br>
Master in Computer Science and Computer Engineering<br>

