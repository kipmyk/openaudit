//! TLS 1.3 Transport Implementation for OpenAudit M3 D4.
//!
//! Provides strict TLS 1.3 only transport encryption, certificate chain verification,
//! server identity / hostname authentication, and framed protocol message exchange
//! between `openaudit-agent` and `openaudit-server`.
//!
//! # Security Invariants
//! - **TLS 1.3 Strict:** Protocol negotiation is restricted solely to TLS 1.3. Silent downgrade
//!   to TLS 1.2 or earlier is unconditionally rejected.
//! - **Server Identity Authentication:** Hostnames and Subject Alternative Names (SAN) are strictly
//!   validated against the trusted certificate authority anchor.
//! - **Key Protection:** Private keys require restrictive file permissions (`0600`) and are never
//!   logged or passed via command-line flags.
//! - **Fail-Closed:** Expired certificates, invalid signatures, hostname mismatches, or protocol
//!   downgrades immediately abort the connection.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, StreamOwned};
use serde::{Deserialize, Serialize};

use crate::protocol::authority::AuthorityService;
use crate::protocol::error::ProtocolError;
use crate::protocol::trust::UnverifiedRetrievalRequest;
use crate::protocol::types::{EnrollmentTranscript, SharedSecret, TimestampNs};

/// Maximum allowable payload size for framed TLS messages (10 MB).
pub const MAX_FRAMED_MESSAGE_BYTES: usize = 10 * 1024 * 1024;

// =========================================================================
// Certificate & Private Key Loading
// =========================================================================

/// Parses DER certificate chain from PEM-encoded bytes.
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if parsing fails or no valid certificates are found.
pub fn parse_certificates_from_pem(
    pem_bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, ProtocolError> {
    let mut cursor = Cursor::new(pem_bytes);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            ProtocolError::TlsError(format!("failed to parse PEM certificate: {err}"))
        })?;

    if certs.is_empty() {
        return Err(ProtocolError::TlsError(
            "PEM data contains no certificates".to_string(),
        ));
    }

    Ok(certs)
}

/// Reads DER certificate chain from a PEM file.
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if file reading or PEM decoding fails or file is not regular.
pub fn load_certificates_from_file(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, ProtocolError> {
    let meta = fs::symlink_metadata(path).map_err(|err| {
        ProtocolError::TlsError(format!(
            "failed to stat certificate file at '{}': {err}",
            path.display()
        ))
    })?;

    if !meta.file_type().is_file() {
        return Err(ProtocolError::TlsError(format!(
            "certificate path '{}' is not a regular file (symlinks, directories, and special files are forbidden)",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o002 != 0 {
            return Err(ProtocolError::TlsError(format!(
                "insecure permissions on certificate file at '{}': mode 0o{:o} is world-writable",
                path.display(),
                mode
            )));
        }
    }

    let bytes = fs::read(path).map_err(|err| {
        ProtocolError::TlsError(format!(
            "failed to read certificate file at '{}': {err}",
            path.display()
        ))
    })?;
    parse_certificates_from_pem(&bytes)
}

/// Parses a private key from PEM-encoded bytes (supporting PKCS#8, PKCS#1, or SEC1).
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if no valid private key is found.
pub fn parse_private_key_from_pem(
    pem_bytes: &[u8],
) -> Result<PrivateKeyDer<'static>, ProtocolError> {
    let mut cursor = Cursor::new(pem_bytes);
    let key = rustls_pemfile::private_key(&mut cursor)
        .map_err(|err| ProtocolError::TlsError(format!("failed to parse PEM private key: {err}")))?
        .ok_or_else(|| ProtocolError::TlsError("no private key found in PEM data".to_string()))?;

    Ok(key)
}

/// Reads a private key from a PEM file, strictly enforcing regular file type and restrictive permissions (`0600` or `0400`).
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if the file is a symlink, has insecure permissions, or key parsing fails.
pub fn load_private_key_from_file(path: &Path) -> Result<PrivateKeyDer<'static>, ProtocolError> {
    let meta = fs::symlink_metadata(path).map_err(|err| {
        ProtocolError::TlsError(format!(
            "failed to stat private key file at '{}': {err}",
            path.display()
        ))
    })?;

    if !meta.file_type().is_file() {
        return Err(ProtocolError::TlsError(format!(
            "private key path '{}' is not a regular file (symlinks, directories, and special files are forbidden)",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o400 {
            return Err(ProtocolError::TlsError(format!(
                "insecure permissions on private key file at '{}': mode 0o{:o} detected; strictly requires mode 0600 or 0400",
                path.display(),
                mode
            )));
        }
    }

    let bytes = fs::read(path).map_err(|err| {
        ProtocolError::TlsError(format!(
            "failed to read private key file at '{}': {err}",
            path.display()
        ))
    })?;
    parse_private_key_from_pem(&bytes)
}

// =========================================================================
// TLS 1.3 Configuration Builders
// =========================================================================

/// Builds a [`ServerConfig`] strictly enforcing TLS 1.3.
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if configuration fails.
pub fn build_tls13_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, ProtocolError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| {
            ProtocolError::TlsError(format!(
                "failed to configure TLS 1.3 protocol version: {err}"
            ))
        })?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|err| {
            ProtocolError::TlsError(format!("failed to configure server certificate: {err}"))
        })?;

    Ok(config)
}

/// Builds a [`ClientConfig`] strictly enforcing TLS 1.3 with given trusted root CA certificates.
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if configuration or trust store assembly fails.
pub fn build_tls13_client_config(
    root_certs: Vec<CertificateDer<'static>>,
) -> Result<ClientConfig, ProtocolError> {
    let mut root_store = RootCertStore::empty();
    for cert in root_certs {
        root_store.add(cert).map_err(|err| {
            ProtocolError::TlsError(format!(
                "failed to add root certificate to trust store: {err}"
            ))
        })?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| {
            ProtocolError::TlsError(format!(
                "failed to configure TLS 1.3 protocol version: {err}"
            ))
        })?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

// =========================================================================
// Framing Protocol (Length-Prefixed Framing)
// =========================================================================

/// Writes a 4-byte big-endian length-prefixed message to `writer`.
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if write or flush fails or message exceeds size limit.
pub fn write_framed<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), ProtocolError> {
    if data.is_empty() {
        return Err(ProtocolError::TlsError(
            "cannot write empty framed message (zero-length frames forbidden)".to_string(),
        ));
    }

    if data.len() > MAX_FRAMED_MESSAGE_BYTES {
        return Err(ProtocolError::TlsError(format!(
            "message size {} exceeds maximum framed limit {}",
            data.len(),
            MAX_FRAMED_MESSAGE_BYTES
        )));
    }

    let len = u32::try_from(data.len())
        .map_err(|_| ProtocolError::TlsError("payload length overflows u32".to_string()))?;
    writer.write_all(&len.to_be_bytes()).map_err(|err| {
        ProtocolError::TlsError(format!("failed to write message length prefix: {err}"))
    })?;
    writer.write_all(data).map_err(|err| {
        ProtocolError::TlsError(format!("failed to write message payload: {err}"))
    })?;
    writer
        .flush()
        .map_err(|err| ProtocolError::TlsError(format!("failed to flush stream: {err}")))?;

    Ok(())
}

/// Reads a 4-byte big-endian length-prefixed message from `reader`.
///
/// # Errors
/// Returns [`ProtocolError::TlsError`] if read fails, length is 0, or message exceeds `max_bytes`.
pub fn read_framed<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(|err| {
        ProtocolError::TlsError(format!("failed to read message length prefix: {err}"))
    })?;

    let len = usize::try_from(u32::from_be_bytes(len_buf))
        .map_err(|_| ProtocolError::TlsError("invalid length prefix conversion".to_string()))?;

    if len == 0 {
        return Err(ProtocolError::TlsError(
            "incoming message length is zero (empty frames forbidden)".to_string(),
        ));
    }

    if len > max_bytes {
        return Err(ProtocolError::TlsError(format!(
            "incoming message length {len} exceeds permitted limit {max_bytes}"
        )));
    }

    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|err| ProtocolError::TlsError(format!("failed to read message body: {err}")))?;

    Ok(buf)
}

// =========================================================================
// High-Level Request/Response Envelopes for TLS Exchange
// =========================================================================

/// Top-level request sent from Agent to Server over TLS 1.3.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TlsProtocolRequest {
    /// Enrollment attestation request.
    Enrollment {
        /// Canonical 14-element enrollment transcript (hex).
        transcript_hex: String,
        /// HMAC-SHA256 enrollment proof (64 hex characters).
        hmac_proof_hex: String,
    },
    /// Assessment outbox retrieval request.
    Retrieval {
        /// Canonical 5-element retrieval message (89 bytes, 178 hex characters).
        retrieval_message_hex: String,
        /// HMAC-SHA256 retrieval proof (32 bytes, 64 hex characters).
        hmac_proof_hex: String,
    },
}

/// Top-level response sent from Server to Agent over TLS 1.3.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TlsProtocolResponse {
    /// Operation succeeded.
    Success {
        /// Informational or cryptographic payload.
        payload: serde_json::Value,
    },
    /// Request failed validation or was rejected fail-closed.
    Error {
        /// Error code (e.g. `INVALID_PROOF`, `REPLAY_DETECTED`, `EXPIRED_TRANSCRIPT`).
        code: String,
        /// Diagnostic message.
        message: String,
    },
}

/// Dispatches an incoming request against the authoritative service.
///
/// # Errors
/// Returns [`ProtocolError`] if deserialization, validation, or persistence fails.
pub fn dispatch_authority_request(
    request_bytes: &[u8],
    authority: &AuthorityService,
    secret: &SharedSecret,
    now: TimestampNs,
) -> Result<TlsProtocolResponse, ProtocolError> {
    let req: TlsProtocolRequest = serde_json::from_slice(request_bytes)
        .map_err(|err| ProtocolError::TlsError(format!("invalid request JSON: {err}")))?;

    match req {
        TlsProtocolRequest::Enrollment {
            transcript_hex,
            hmac_proof_hex,
        } => {
            let raw_transcript = hex_decode_bytes(&transcript_hex)?;
            let transcript = EnrollmentTranscript::parse_canonical(&raw_transcript)?;
            let proof_bytes = hex_decode_32(&hmac_proof_hex)?;

            match authority.process_enrollment(&transcript, &proof_bytes, secret, now) {
                Ok(verified) => Ok(TlsProtocolResponse::Success {
                    payload: serde_json::json!({
                        "machine_id": verified.machine_id.to_string(),
                        "tx_id": verified.tx_id.to_string(),
                        "generation": verified.generation.0,
                        "counter_base": verified.counter_base.as_u64(),
                        "catalog_base": verified.catalog_base.as_u64(),
                    }),
                }),
                Err(err) => Ok(TlsProtocolResponse::Error {
                    code: "ENROLLMENT_REJECTED".to_string(),
                    message: err.to_string(),
                }),
            }
        }
        TlsProtocolRequest::Retrieval {
            retrieval_message_hex,
            hmac_proof_hex,
        } => {
            let msg_bytes = hex_decode_bytes(&retrieval_message_hex)?;
            let proof_bytes = hex_decode_32(&hmac_proof_hex)?;
            let unverified = UnverifiedRetrievalRequest::new(msg_bytes, proof_bytes);

            match authority.process_retrieval(&unverified, secret, now) {
                Ok(verified) => {
                    let active_catalog = authority.load_active_catalog().ok();
                    Ok(TlsProtocolResponse::Success {
                        payload: serde_json::json!({
                            "machine_id": verified.message.machine_id.to_string(),
                            "tx_id": verified.message.tx_id.to_string(),
                            "req_id": verified.message.req_id.to_string(),
                            "t_req": verified.message.t_req.as_nanos(),
                            "catalog": active_catalog,
                        }),
                    })
                }
                Err(err) => {
                    let code = match err {
                        ProtocolError::ReplayDetected { .. } => "REPLAY_DETECTED",
                        ProtocolError::TimestampOutOfBounds { .. } => "TIMESTAMP_OUT_OF_BOUNDS",
                        ProtocolError::InvalidHmacProof => "INVALID_HMAC_PROOF",
                        ProtocolError::StorageUnavailable(_) => "REPLAY_STORAGE_UNAVAILABLE",
                        _ => "RETRIEVAL_REJECTED",
                    };
                    Ok(TlsProtocolResponse::Error {
                        code: code.to_string(),
                        message: err.to_string(),
                    })
                }
            }
        }
    }
}

// =========================================================================
// TLS Client Transport Connection
// =========================================================================

/// Live TLS 1.3 client stream connecting to an OpenAudit authority endpoint.
pub struct TlsClientTransport {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl std::fmt::Debug for TlsClientTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientTransport").finish_non_exhaustive()
    }
}

impl TlsClientTransport {
    /// Connects to `addr` enforcing TLS 1.3 with server identity `hostname`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::TlsError`] on TCP connection failure, invalid hostname, or TLS handshake error.
    pub fn connect(
        addr: &str,
        hostname: &str,
        client_config: Arc<ClientConfig>,
    ) -> Result<Self, ProtocolError> {
        let server_name = ServerName::try_from(hostname.to_string()).map_err(|err| {
            ProtocolError::TlsError(format!("invalid server hostname '{hostname}': {err}"))
        })?;

        let tcp_stream = TcpStream::connect(addr).map_err(|err| {
            ProtocolError::TlsError(format!("failed to connect to '{addr}': {err}"))
        })?;

        let conn = ClientConnection::new(client_config, server_name).map_err(|err| {
            ProtocolError::TlsError(format!("failed to create TLS client connection: {err}"))
        })?;

        let stream = StreamOwned::new(conn, tcp_stream);

        Ok(Self { stream })
    }

    /// Sends a request and receives the framed response over TLS 1.3.
    ///
    /// # Errors
    /// Returns [`ProtocolError::TlsError`] if sending or receiving fails.
    pub fn exchange(
        &mut self,
        request: &TlsProtocolRequest,
    ) -> Result<TlsProtocolResponse, ProtocolError> {
        let req_bytes = serde_json::to_vec(request).map_err(|err| {
            ProtocolError::TlsError(format!("failed to serialize request: {err}"))
        })?;

        write_framed(&mut self.stream, &req_bytes)?;
        let resp_bytes = read_framed(&mut self.stream, MAX_FRAMED_MESSAGE_BYTES)?;

        let resp: TlsProtocolResponse = serde_json::from_slice(&resp_bytes).map_err(|err| {
            ProtocolError::TlsError(format!("failed to deserialize response: {err}"))
        })?;

        Ok(resp)
    }

    /// Cleanly closes the TLS 1.3 session by sending a `close_notify` alert and flushing the stream.
    ///
    /// # Errors
    /// Returns [`ProtocolError::TlsError`] if flushing fails.
    pub fn shutdown(&mut self) -> Result<(), ProtocolError> {
        self.stream.conn.send_close_notify();
        let _ = self.stream.flush();
        Ok(())
    }
}

// =========================================================================
// Helper Decoders
// =========================================================================

fn hex_decode_32(hex: &str) -> Result<[u8; 32], ProtocolError> {
    let bytes = hex_decode_bytes(hex)?;
    bytes.try_into().map_err(|_| {
        ProtocolError::TlsError(format!(
            "expected 32 bytes for HMAC proof, got {}",
            hex.len() / 2
        ))
    })
}

fn hex_decode_bytes(hex: &str) -> Result<Vec<u8>, ProtocolError> {
    if !hex.len().is_multiple_of(2) {
        return Err(ProtocolError::TlsError(
            "invalid hex string length".to_string(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|err| ProtocolError::TlsError(format!("invalid hex byte: {err}")))
        })
        .collect()
}
