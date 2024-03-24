mod atm_parser;
use std::{io::{Read, Write}, net::TcpStream};
use std::process::exit;

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

    println!("{} {} {} {} {}", auth_file, ip_address, port, card_file, account);

    
    let mut stream = TcpStream::connect("localhost:8080")?;
    println!("Connected to server!");

    loop {
        let mut input = String::new();
        //Maybe validate input???? Check validator crate
        match std::io::stdin().read_line(&mut input) {
            Ok(_) => {
                println!("Correct input {}", input);
            }
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