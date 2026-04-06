use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Response {
    status: String,
}

fn main() {
    let port = env::var("ENCLAVE_APP_PORT").unwrap_or_else(|_| "7074".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).expect("failed to bind");
    println!("listening on {}", addr);

    let body = serde_json::to_string(&Response { status: "ok".into() })
        .unwrap_or_else(|_| r#"{"status":"ok"}"#.to_string());

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    }
}
