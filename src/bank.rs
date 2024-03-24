mod bank_parser;
use std::{io::{Read, Write}, net::{SocketAddr, TcpListener, TcpStream}, thread};
use std::process::exit;


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
