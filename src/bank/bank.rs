mod bank_parser;
use std::{fs::{self}, io::{Read, Write}, net::{SocketAddr, TcpListener, TcpStream}, path::Path, thread};
use std::process::exit;
use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey};

fn handle_client(mut stream: TcpStream, addr: SocketAddr) {
    loop {
        let mut buffer = [0; 1024];
        match stream.read(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    println!("ATM from {} disconnected", addr);
                    break;
                }
                println!("Received: {}", String::from_utf8_lossy(&buffer[..size]));
                stream.write_all(&buffer[..size]).unwrap();
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                break;
            }
        }
    }
}



fn main() -> std::io::Result<()> {

    let (port, auth_file): (String, String) = match bank_parser::cli() {
        Ok(matches) => {
            let port = matches.value_of("port").unwrap_or_else(|| {
                exit(255);
            }).to_string();

            let auth_file = matches.value_of("auth-file").unwrap_or_else(|| {
                exit(255);
            }).to_string();

            (port, auth_file)
        },
        Err(_) => {
            exit(255);
        }
    };

   
    // Generate RSA keypair
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap_or_else(|_| {
        println!("Error generating RSA pair");
        exit(255);
    });
    let public_key = RsaPublicKey::from(&private_key);

    println!("{:?} {:?}",private_key, public_key);

    //Create bank.auth file, expects error if bank.auth exists
    let file_path = Path::new("bank.auth");
    if file_path.exists() {
        exit(255);
    } else {
        match fs::write(file_path, "bank.auth\n") {
            Ok(_) => println!("Created"),
            Err(_) =>  exit(255),
        }
    }

    //Write RSA Public Key to Bank.auth
    let public_key_pem = public_key.to_pkcs1_pem(LineEnding::CRLF).expect("Failed to covert public key to PEM");
    fs::write(file_path, public_key_pem).expect("Failed to write keys to file");
    

    let listener = TcpListener::bind(String::from("localhost:") + &port).unwrap_or_else(|_| {
        exit(255);
    });
    println!("Bank listening on port 8080");

    println!("{} {}",port, auth_file);

    loop {
        //let (stream, addr) = listener.accept()?;
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("ATM connected from {}", addr);
                let _ = thread::spawn(move || {
                    handle_client(stream, addr)
                });
            }
            Err(err) => {
                println!("Couldn't accept ATM request {}", err);
                continue;
            }
        }
    }
    
}
