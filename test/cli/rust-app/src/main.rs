use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;

// commit2: uncomment the next line
// use serde;

fn main() {
    let port = env::var("ENCLAVE_APP_PORT").unwrap_or_else(|_| "7074".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).expect("failed to bind");
    println!("listening on {}", addr);

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";
            let _ = stream.write_all(response.as_bytes());
        }
    }
}
