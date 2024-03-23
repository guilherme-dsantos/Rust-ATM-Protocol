mod commands;

use std::{io::{Read, Write}, net::TcpStream};
use std::process::exit;

use crate::commands::parse_cli;

fn main() -> std::io::Result<()> {

    match parse_cli() {
        Ok(_) => {},
        Err(_) => {
            exit(255);
        }
    }

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