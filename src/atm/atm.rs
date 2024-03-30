mod atm_parser;
mod operations;
use operations::Operation;
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

fn validate_balance(s: &str){
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
        },
        false => {
            eprintln!("Not a match");
            exit(303);
        }
    }
}

fn validate_ip_address(s: &str){
    println!("Validating IP: {}", &s);
    let pattern = regex::Regex::new(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$").unwrap();
    if !pattern.is_match(s){
        println!("Regex pattern: {:?}", pattern);
        eprintln!("{}", &s);
        exit(252)
    }
}

fn validate_port(s: &str){
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


fn validate_file_name(file_name: &str){
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

    let (auth_file, ip_address, port, card_file, account, operation): (String, String, String, String, String, Operation) = match atm_parser::cli() {
        Ok(matches) => {
            let auth_file = matches.value_of("auth-file").unwrap_or("bank.auth").to_string(); //alterar para working directory
            validate_file_name(&auth_file);
            let ip_address = matches.value_of("ip-address").unwrap_or("127.0.0.1").to_string();
            validate_ip_address(&ip_address);

            let port = matches.value_of("port").unwrap_or("3000").to_string();
            validate_port(&port);

            /*let account = matches.value_of("account").unwrap_or_else(|| {
                exit(251);
            }).parse::<u32>().unwrap_or_else(|_| {
                exit(252);
            });*/
            let account = matches.value_of("account").unwrap_or_else(|| {
                exit(251);
            }).to_string();
            validate_account(&account);

            let card_file = matches.value_of("card-file").map(|s| s.to_string()).unwrap_or(format!("{}{}", account, ".card"));
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
        },
        Err(_) => {
            exit(253);
        }
    };

    //Connect to the bank
    let mut stream = TcpStream::connect(ip_address.to_owned() + &port).unwrap_or_else(|_| {
        exit(254);
    });

    match operation {
        Operation::Balance(balance) => {
            validate_balance(&balance);
            create_card_file(&card_file);
        },
        Operation::Deposit(deposit) => {
            // Handle deposit operation
            println!("{}",deposit);
        },
        Operation::Withdraw(withdraw) => {
            // Handle withdraw operation
            println!("{}",withdraw);
        },
        Operation::Get(get) => {
            // Handle get operation
            println!("{}",get);
        },
    }

    //Read RSA Public Key From Bank.auth
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