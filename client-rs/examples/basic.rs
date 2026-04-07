use enclave_client::{Client, Options};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let base_url = std::env::var("ENCLAVE_URL").unwrap_or_else(|_| {
        eprintln!("Usage: ENCLAVE_URL=https://1.2.3.4 PCR0=abc123... cargo run --example basic");
        std::process::exit(1);
    });

    let pcr0 = std::env::var("PCR0").unwrap_or_else(|_| {
        eprintln!("PCR0 environment variable is required");
        std::process::exit(1);
    });

    println!("Connecting to enclave at {base_url}");
    println!("Expected PCR0: {pcr0}");

    let client = Client::new(
        &base_url,
        Options {
            expected_pcr0: pcr0,
            ..Default::default()
        },
    )?;

    // Verify attestation.
    println!("\nVerifying attestation...");
    let attest = client.verify_attestation().await?;
    println!("  PCR0: {}", attest.pcr0);
    println!("  Attestation key: {}", attest.attestation_key);
    println!("  Verified: {}", attest.verified);

    // Make a verified request.
    println!("\nMaking verified GET /health...");
    let resp = client.get("/health").await?;
    println!("  Status: {}", resp.status_code);
    println!("  Signature verified: {}", resp.signature_verified);
    println!("  Body: {}", String::from_utf8_lossy(&resp.body));

    Ok(())
}
