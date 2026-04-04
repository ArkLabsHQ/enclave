//! Main verified HTTP client for AWS Nitro Enclaves.

use crate::error::{Error, Result};
use crate::manifest;
use crate::types::{AttestationResult, Options, Response};
use crate::verify;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// A verified HTTP client for an AWS Nitro Enclave.
///
/// Every request first verifies the enclave's attestation document (PCR0,
/// optional secret PCRs, attestation key binding) and then verifies the
/// Schnorr response signature.
pub struct Client {
    base_url: String,
    http_client: reqwest::Client,
    opts: Options,
    cached_state: Arc<RwLock<Option<AttestationResult>>>,
}

impl Client {
    /// Create a new enclave client that verifies attestation before making
    /// requests. The `base_url` should be the HTTPS endpoint of the enclave
    /// (e.g. `"https://1.2.3.4"`).
    pub fn new(base_url: &str, opts: Options) -> Result<Self> {
        if opts.expected_pcr0.is_empty() {
            return Err(Error::MissingPCR0);
        }

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .use_rustls_tls();

        if opts.insecure_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let http_client = builder.build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http_client,
            opts,
            cached_state: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a client by fetching deployment metadata from a GitHub Release
    /// manifest URL. The manifest provides the enclave's base URL and PCR0.
    ///
    /// When `opts.verify_provenance` is true, verifies that the manifest has
    /// a valid GitHub artifact attestation before trusting its PCR values.
    pub async fn from_manifest(manifest_url: &str, mut opts: Options) -> Result<Self> {
        let (m, raw) = manifest::fetch_manifest_raw(manifest_url).await?;

        if opts.verify_provenance {
            if m.repo.is_empty() {
                return Err(Error::Manifest(
                    "missing repo field, cannot verify provenance".into(),
                ));
            }
            manifest::verify_manifest_provenance(&m.repo, &raw, opts.github_token.as_deref())
                .await?;
        }

        if !opts.expected_pcr0.is_empty()
            && !opts.expected_pcr0.eq_ignore_ascii_case(&m.pcr0)
        {
            return Err(Error::Manifest(format!(
                "manifest PCR0 {} does not match expected {}",
                m.pcr0, opts.expected_pcr0
            )));
        }
        opts.expected_pcr0 = m.pcr0;

        Self::new(&m.base_url, opts)
    }

    /// Make a verified GET request to the enclave.
    pub async fn get(&self, path: &str) -> Result<Response> {
        let url = self.url(path);
        let req = self.http_client.get(&url);
        self.execute(req).await
    }

    /// Make a verified POST request to the enclave with a body.
    pub async fn post(&self, path: &str, body: impl Into<reqwest::Body>) -> Result<Response> {
        let url = self.url(path);
        let req = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body);
        self.execute(req).await
    }

    /// Make a verified HTTP request to the enclave (generic).
    pub async fn request(&self, req: reqwest::RequestBuilder) -> Result<Response> {
        self.execute(req).await
    }

    /// Manually trigger attestation verification, bypassing the cache.
    pub async fn verify_attestation(&self) -> Result<AttestationResult> {
        self.verify_inner().await
    }

    /// Execute a request with attestation verification and signature checking.
    async fn execute(&self, req: reqwest::RequestBuilder) -> Result<Response> {
        // Step 1: Verify attestation (uses cache if valid).
        let attest = self.ensure_verified().await?;

        // Step 2: Execute the actual request.
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.bytes().await?.to_vec();

        // Step 3: Verify response signature.
        let mut sig_verified = false;
        if !attest.attestation_key.is_empty() {
            if let Some(sig_val) = headers.get("X-Attestation-Signature") {
                if let Ok(sig_hex) = sig_val.to_str() {
                    if verify::verify_schnorr_signature(&body, sig_hex, &attest.attestation_key)
                        .is_ok()
                    {
                        sig_verified = true;
                    }
                }
            }
        }

        Ok(Response {
            status_code: status,
            headers,
            body,
            signature_verified: sig_verified,
        })
    }

    /// Return cached attestation or re-verify.
    async fn ensure_verified(&self) -> Result<AttestationResult> {
        {
            let cached = self.cached_state.read().await;
            if let Some(ref state) = *cached {
                if state.verified && state.verified_at.elapsed() < self.opts.cache_ttl {
                    return Ok(state.clone());
                }
            }
        }
        self.verify_inner().await
    }

    /// Perform full attestation verification and cache the result.
    async fn verify_inner(&self) -> Result<AttestationResult> {
        // 1. Fetch and verify attestation document.
        let nitro_result = verify::fetch_and_verify_attestation(
            &self.http_client,
            &self.base_url,
            &self.opts.expected_pcr0,
        )
        .await?;

        // 2. Verify additional PCRs (secret pubkey hashes).
        let mut pcrs = HashMap::new();
        for (idx, bytes) in &nitro_result.document.pcrs {
            if !bytes.is_empty() {
                pcrs.insert(*idx, hex::encode(bytes));
            }
        }

        for (i, expected_hash) in self.opts.expected_pcrs.iter().enumerate() {
            let pcr_index = 16 + i as u32;
            let actual = pcrs
                .get(&pcr_index)
                .ok_or(Error::PcrNotFound(pcr_index))?;
            if !actual.eq_ignore_ascii_case(expected_hash) {
                return Err(Error::PcrMismatch {
                    index: pcr_index,
                    expected: expected_hash.clone(),
                    actual: actual.clone(),
                });
            }
        }

        // 3. Verify attestation key binding.
        let attest_key = verify::verify_key_binding(
            &self.http_client,
            &self.base_url,
            &nitro_result.document,
        )
        .await?;

        let result = AttestationResult {
            pcr0: self.opts.expected_pcr0.clone(),
            pcrs,
            attestation_key: attest_key,
            verified: true,
            verified_at: Instant::now(),
        };

        // Cache the result.
        {
            let mut cached = self.cached_state.write().await;
            *cached = Some(result.clone());
        }

        Ok(result)
    }

    fn url(&self, path: &str) -> String {
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        format!("{}{}", self.base_url, path)
    }
}
