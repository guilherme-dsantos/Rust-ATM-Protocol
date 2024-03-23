use std::{io::{Read, Write}, net::{SocketAddr, TcpListener, TcpStream}, thread};



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
    let listener = TcpListener::bind("localhost:8080")?;
    println!("Bank listening on port 8080");

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
