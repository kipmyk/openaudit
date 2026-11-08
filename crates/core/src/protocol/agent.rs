//! Monitored node agent orchestration client for OpenAudit M3 D4.
//!
//! Provides the node-side attestation client coordinating:
//! 1. Gathering TPM hardware identity material (Endorsement Key public SPKI, SRK Name, Lifecycle ID).
//! 2. Constructing canonical 14-element enrollment transcripts and signing HMAC-SHA256 proofs.
//! 3. Constructing fresh outbox retrieval requests with single-use `RequestId` nonces.
//! 4. Managing hardware counter baselines and preventing secret material leakage.

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::protocol::catalog::MonotonicCounter;
use crate::protocol::crypto::compute_hmac_sha256;
use crate::protocol::error::ProtocolError;
use crate::protocol::trust::UnverifiedRetrievalRequest;
use crate::protocol::types::{
    CatalogVersion, ChallengeNonce, CounterValue, EnrollmentGeneration, EnrollmentTokenId,
    EnrollmentTranscript, LifecycleId, MachineId, RequestId, RetrievalMessage, SharedSecret,
    SrkName, TimestampNs, TransactionId,
};

/// Client configuration containing hardware credentials and TPM parameters.
pub struct AgentCredentials {
    /// Monitored machine hardware identifier.
    pub machine_id: MachineId,
    /// Cryptographic shared secret established with Authority.
    pub shared_secret: SharedSecret,
    /// Hardware TPM Endorsement Key canonical SPKI DER bytes.
    pub ek_pub: Vec<u8>,
    /// Exact 34-byte TPM Name of the Storage Root Key.
    pub name_srk: SrkName,
    /// TPM NV lifecycle random identifier.
    pub lifecycle_id: LifecycleId,
    /// Enrollment generation.
    pub generation: EnrollmentGeneration,
}

impl fmt::Debug for AgentCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentCredentials")
            .field("machine_id", &self.machine_id)
            .field("shared_secret", &"[REDACTED]")
            .field("ek_pub_len", &self.ek_pub.len())
            .field("name_srk", &self.name_srk)
            .field("lifecycle_id", &self.lifecycle_id)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Node agent client executing attestation and outbox retrieval workflows.
pub struct AgentAttestationClient {
    credentials: AgentCredentials,
    counter: Arc<Mutex<dyn MonotonicCounter>>,
}

impl fmt::Debug for AgentAttestationClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentAttestationClient")
            .field("machine_id", &self.credentials.machine_id)
            .field("generation", &self.credentials.generation)
            .finish_non_exhaustive()
    }
}

impl AgentAttestationClient {
    /// Creates a new node agent attestation client.
    #[must_use]
    pub fn new(credentials: AgentCredentials, counter: Arc<Mutex<dyn MonotonicCounter>>) -> Self {
        Self {
            credentials,
            counter,
        }
    }

    /// Returns the machine hardware identifier.
    #[must_use]
    pub const fn machine_id(&self) -> MachineId {
        self.credentials.machine_id
    }

    /// Returns the current enrollment generation.
    #[must_use]
    pub const fn generation(&self) -> EnrollmentGeneration {
        self.credentials.generation
    }

    /// Returns a reference to the shared secret.
    #[must_use]
    pub const fn shared_secret(&self) -> &SharedSecret {
        &self.credentials.shared_secret
    }

    /// Constructs a canonical 14-element [`EnrollmentTranscript`] and computes its HMAC-SHA256 proof.
    ///
    /// # Normative Execution Sequence:
    /// 1. Queries the hardware monotonic counter baseline ($C_{\text{base}}$).
    /// 2. Assembles the 14-element `EnrollmentTranscript` bound to this machine and authority challenge.
    /// 3. Serializes the transcript into canonical binary format ($204 + N$ bytes).
    /// 4. Computes $\text{Proof} = \text{HMAC-SHA256}(S, \text{transcript})$.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if counter read or canonical serialization fails.
    pub fn construct_enrollment_transcript(
        &self,
        nonce_auth: ChallengeNonce,
        token_id: EnrollmentTokenId,
        tx_id: TransactionId,
        catalog_base: CatalogVersion,
        timestamp_issued: TimestampNs,
        timestamp_expires: TimestampNs,
    ) -> Result<(EnrollmentTranscript, [u8; 32]), ProtocolError> {
        let counter_val = {
            let counter = self.counter.lock().map_err(|_| {
                ProtocolError::TpmError("monotonic counter lock poisoned".to_string())
            })?;
            counter.read_counter()?
        };

        let transcript = EnrollmentTranscript {
            nonce_auth,
            token_id,
            tx_id,
            machine_id: self.credentials.machine_id,
            ek_pub: self.credentials.ek_pub.clone(),
            name_srk: self.credentials.name_srk,
            lifecycle_id: self.credentials.lifecycle_id,
            generation_mach: self.credentials.generation,
            counter_base: CounterValue::from_u64(counter_val),
            catalog_base,
            timestamp_issued,
            timestamp_expires,
        };

        let canonical_bytes = transcript.serialize_canonical()?;
        let proof = compute_hmac_sha256(&self.credentials.shared_secret, &canonical_bytes);

        Ok((transcript, proof))
    }

    /// Constructs a fresh [`UnverifiedRetrievalRequest`] for outbox retrieval.
    ///
    /// # Normative Execution Sequence:
    /// 1. Generates a fresh, single-use 128-bit [`RequestId`].
    /// 2. Assembles the 5-element [`RetrievalMessage`] (89 bytes fixed width).
    /// 3. Serializes into canonical binary representation.
    /// 4. Computes HMAC-SHA256 proof under the machine's shared secret.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if message serialization fails.
    #[must_use]
    pub fn construct_retrieval_request(
        &self,
        tx_id: TransactionId,
        t_req: TimestampNs,
    ) -> UnverifiedRetrievalRequest {
        let req_id = RequestId::new();
        let message = RetrievalMessage {
            machine_id: self.credentials.machine_id,
            tx_id,
            req_id,
            t_req,
        };

        let raw_payload = message.serialize_canonical();
        let proof = compute_hmac_sha256(&self.credentials.shared_secret, &raw_payload);

        UnverifiedRetrievalRequest::new(raw_payload.to_vec(), proof)
    }
}
