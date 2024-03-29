mod atm_parser;
use std::{fs, io::{Read, Write}, net::TcpStream, path::Path};
use std::process::exit;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};

fn extract_public_key(file_path: &str) -> Result<RsaPublicKey,String> {
    match fs::read_to_string(file_path) {
        Ok(content) => {
            let public_key = RsaPublicKey::from_pkcs1_pem(&content)
                .map_err(|e| format!("Error parsing public key: {}", e))?;
            Ok(public_key)
        }
        Err(err) => Err(format!("Error reading public key from file: {}", err)),
    }

}

fn main() -> std::io::Result<()> {

    let (auth_file, ip_address, port, card_file, account): (String, String, String, String, u32) = match atm_parser::cli() {
        Ok(matches) => {
            let auth_file = matches.value_of("auth-file").unwrap_or_else(|| {
                exit(255);
            }).to_string();

            let ip_address = matches.value_of("ip-address").unwrap_or_else(|| {
                exit(255);
            }).to_string();

            let port = matches.value_of("port").unwrap_or_else(|| {
                exit(255);
            }).to_string();

            let card_file = matches.value_of("card-file").unwrap_or_else(|| {
                exit(255);
            }).to_string();

            let account = matches.value_of("account").unwrap_or_else(|| {
                exit(255);
            }).parse::<u32>().unwrap_or_else(|_| {
                exit(255);
            });

            (auth_file, ip_address, port, card_file, account)
        },
        Err(_) => {
            exit(255);
        }
    };

    let mut stream = TcpStream::connect(String::from("localhost:") + &port).unwrap_or_else(|_| {
        exit(255);
    });

    println!("Connected to the bank!");

    //Read RSA Public Key From Bank.auth
    //Chnage this later because the name can be different
    let file_path = Path::new("bank.auth");
    let string_path = file_path.to_str().unwrap_or_default();
    let extracted_public_key = match extract_public_key(string_path) {
        Ok(public_key) => public_key,
        Err(err) => {
            eprintln!("Error extracting public key: {}", err);
            exit(255);
        } 
    };

    println!("{:?}", extracted_public_key);

    println!("{} {} {} {} {}", auth_file, ip_address, port, card_file, account);
    
    loop {
        let mut input = String::new();
        //Maybe validate input???? Check validator crate
        match std::io::stdin().read_line(&mut input) {
            Ok(_) => 
                println!("Correct input {}", input),
            
            Err(_) => { 
                println!("Incorrect input {}", input);    
                continue; 
            } 
        }

        stream.write_all(input.as_bytes())?;

        let mut buffer = [0; 1024];
        match stream.read(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    println!("Client disconnected!");
                    break;
                }
                println!("Received: {}", String::from_utf8_lossy(&buffer));
            }
            Err(err) => {
                eprintln!("Error reading from server: {}", err);
                // Handle the error here, potentially disconnect or retry
                break;
            }
        }
    }

    Ok(())
}