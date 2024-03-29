mod atm_parser;
use std::{fs, io::{Read, Write}, net::TcpStream, path::Path};
use std::process::exit;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};
use std::str::FromStr;

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

fn validate_balance(s: String){
    let pattern = regex::Regex::new(r"^(0|[1-9][0-9]*)\.[0-9]{2}$").unwrap();
    match pattern.is_match(&s) {
        true => {
            let value = f64::from_str(&s).unwrap_or_else(|_| {
                eprintln!("Failed to parse balance as a float.");
                exit(252);
            });
            if value < 10.00 {
                exit(301);
            }
        },
        false => {
            eprintln!("Not a match");
            exit(303);
        }
    }
}

fn validate_ip_address(s: String){
    println!("Validating IP: {}", &s);
    let pattern = regex::Regex::new(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$").unwrap();
    if !pattern.is_match(&s){
        println!("Regex pattern: {:?}", pattern);
        eprintln!("{}", &s);
        exit(252)
    }
}

fn validate_port(s: String){
    if let Ok(port) = s.parse::<u16>() { //u16 goes to 65535
        if port < 1024{
            eprintln!("Port number out of valid range (1024-65535).");
            exit(259);
        }
    } else {
        eprintln!("Invalid input: not a number or too big.");
        exit(251);
    }
}

fn create_card_file(file_path: &str) {
    let path = Path::new(file_path);
    if path.exists() {
        eprintln!("File already exists.");
        exit(255);
    } else {
        if let Err(_) = fs::write(path, "cardfile\n") {
            eprintln!("Failed to write to file.");
            exit(255);
        }
    }
}

fn main() -> std::io::Result<()> {

    let (auth_file, ip_address, port, card_file, account): (String, String, String, String, String) = match atm_parser::cli() {
        Ok(matches) => {
            let auth_file = matches.value_of("auth-file").unwrap_or("src/bank/bank.auth").to_string(); //alterar para working directory

            let ip_address = matches.value_of("ip-address").unwrap_or("127.0.0.1").to_string();
            validate_ip_address(ip_address.clone());

            let port = matches.value_of("port").unwrap_or("3000").to_string();
            validate_port(port.clone());

            /*let account = matches.value_of("account").unwrap_or_else(|| {
                exit(251);
            }).parse::<u32>().unwrap_or_else(|_| {
                exit(252);
            });*/
            let account = matches.value_of("account").unwrap_or_else(|| {
                exit(251);
            }).to_string();

            let card_file = matches.value_of("card-file").map(|s| s.to_string()).unwrap_or(format!("{}{}", &account, ".card"));

            let operation = if matches.is_present("balance") {
                "balance"
            } else if matches.is_present("deposit") {
                "deposit"
            } else if matches.is_present("withdraw") {
                "withdraw"
            } else if matches.is_present("get") {
                "get"
            } else {
                eprintln!("An operation must be specified.");
                exit(254);
            };
        
            // Perform the operation based on the user input
            match operation {
                "balance" => {
                    let balance = matches.value_of("balance").unwrap_or_else(|| {
                        exit(251);
                    }).to_string();
                    validate_balance(balance);
                    create_card_file(&card_file);
                },
                "deposit" => {
                    // Handle deposit operation
                },
                "withdraw" => {
                    // Handle withdraw operation
                },
                "get" => {
                    // Handle get operation
                },
                _ => unreachable!(), // Since we've already checked for presence
            }

            (auth_file, ip_address, port, card_file, account)
        },
        Err(_) => {
            exit(253);
        }
    };

    let mut stream = TcpStream::connect(String::from("localhost:") + &port).unwrap_or_else(|_| {
        exit(254);
    });

    println!("Connected to the bank!");

    //Read RSA Public Key From Bank.auth
    //Chnage this later because the name can be different
    let file_path = Path::new(&auth_file);
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