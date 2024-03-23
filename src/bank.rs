use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, thread};

fn handle_client(mut stream: TcpStream) {
    println!("Client connected!");
    loop {
        let mut buffer = [0; 1024];
        match stream.read(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    println!("Client disconnected!");
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
    println!("Server listening on port 8080");

    loop {
        let (stream, addr) = listener.accept()?;
        println!("Client connected from: {}", addr);

        // Spawn a new thread and get the JoinHandle
        let thread = thread::spawn(move || {
            handle_client(stream)
        });

        thread.join().unwrap();  
    }
}
