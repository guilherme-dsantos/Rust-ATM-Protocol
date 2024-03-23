use std::{io::{Read, Write}, net::TcpStream};

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("localhost:8080")?;
    println!("Connected to server!");

    loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

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
