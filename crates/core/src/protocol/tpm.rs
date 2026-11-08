//! Production TPM 2.0 wire protocol client, NV monotonic counter adapter,
//! and four-state provisioning lifecycle engine for OpenAudit M3 D4.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::protocol::catalog::MonotonicCounter;
use crate::protocol::error::ProtocolError;

// =========================================================================
// TPM 2.0 Constants & Specification Codes (TCG TPM 2.0 Architecture Part 2 & Part 3)
// =========================================================================

/// Session tags.
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;

/// Response codes.
pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;
pub const TPM_RC_INITIALIZE: u32 = 0x0000_0100;
pub const TPM_RC_NV_UNINITIALIZED: u32 = 0x0000_014A;
pub const TPM_RC_HANDLE: u32 = 0x0000_018B;
pub const TPM_RC_AUTH_FAIL: u32 = 0x0000_098E;
pub const TPM_RC_POLICY_FAIL: u32 = 0x0000_099D;
pub const TPM_RC_RETRY: u32 = 0x0000_0922;
pub const TPM_RC_YIELDED: u32 = 0x0000_0908;

/// Command codes.
pub const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
pub const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
pub const TPM_CC_NV_INCREMENT: u32 = 0x0000_0134;
pub const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
pub const TPM_CC_NV_WRITE_LOCK: u32 = 0x0000_0138;
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_NV_READ: u32 = 0x0000_014E;
pub const TPM_CC_POLICY_SECRET: u32 = 0x0000_0151;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub const TPM_CC_POLICY_COMMAND_CODE: u32 = 0x0000_016C;
pub const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;

/// Permanent handles & algorithms.
pub const TPM_RH_OWNER: u32 = 0x4000_0001;
pub const TPM_RH_NULL: u32 = 0x4000_0007;
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_SE_POLICY: u8 = 0x01;

/// OpenAudit Normative NV Indices & Masks.
pub const DEFAULT_NV_COUNTER_INDEX: u32 = 0x0180_0001;
pub const DEFAULT_NV_LIFECYCLE_INDEX: u32 = 0x0180_0002;
pub const NV_COUNTER_ATTRIBUTES: u32 = 0x0204_0018;
pub const NV_LIFECYCLE_ATTRIBUTES: u32 = 0x0204_2002;

// =========================================================================
// Transport Abstraction
// =========================================================================

/// Transport abstraction for sending and receiving raw TPM 2.0 command frames.
pub trait TpmTransport: Send + Sync {
    /// Transmits `command` bytes to the TPM and reads the complete response frame.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if connection fails or I/O encounters an error.
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, ProtocolError>;
}

/// Transport connecting to a TPM over a Unix domain socket (e.g. `swtpm socket`).
pub struct UnixSocketTransport {
    path: PathBuf,
    timeout: Duration,
}

impl fmt::Debug for UnixSocketTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixSocketTransport")
            .field("path", &self.path)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl UnixSocketTransport {
    /// Creates a new Unix socket transport targeting `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            timeout: Duration::from_secs(10),
        }
    }
}

impl TpmTransport for UnixSocketTransport {
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let mut stream = UnixStream::connect(&self.path).map_err(|err| {
            ProtocolError::TpmError(format!(
                "failed to connect to TPM socket at '{}': {err}",
                self.path.display()
            ))
        })?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        stream
            .write_all(command)
            .map_err(|err| ProtocolError::TpmError(format!("TPM socket write failed: {err}")))?;

        // Read 10-byte TPM response header
        let mut header = [0u8; 10];
        stream.read_exact(&mut header).map_err(|err| {
            ProtocolError::TpmError(format!("TPM socket header read failed: {err}"))
        })?;

        let size_bytes: [u8; 4] = header[2..6]
            .try_into()
            .map_err(|_| ProtocolError::TpmError("failed to extract size bytes".to_string()))?;
        let total_size = u32::from_be_bytes(size_bytes) as usize;
        if total_size < 10 {
            return Err(ProtocolError::TpmError(format!(
                "invalid TPM response frame size: {total_size} bytes (minimum 10)"
            )));
        }

        let mut response = Vec::with_capacity(total_size);
        response.extend_from_slice(&header);
        let remaining = total_size - 10;
        if remaining > 0 {
            let mut body = vec![0u8; remaining];
            stream.read_exact(&mut body).map_err(|err| {
                ProtocolError::TpmError(format!("TPM socket body read failed: {err}"))
            })?;
            response.extend_from_slice(&body);
        }

        Ok(response)
    }
}

/// Transport connecting to a character device (e.g. `/dev/tpmrm0` or `/dev/tpm0`).
pub struct DeviceTransport {
    path: PathBuf,
    device: Option<File>,
}

impl fmt::Debug for DeviceTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceTransport")
            .field("path", &self.path)
            .field("opened", &self.device.is_some())
            .finish()
    }
}

impl DeviceTransport {
    /// Creates a new device transport targeting `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            device: None,
        }
    }

    fn ensure_opened(&mut self) -> Result<&mut File, ProtocolError> {
        if self.device.is_none() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)
                .map_err(|err| {
                    ProtocolError::TpmError(format!(
                        "failed to open TPM device node at '{}': {err}",
                        self.path.display()
                    ))
                })?;
            self.device = Some(file);
        }
        Ok(self.device.as_mut().expect("file present"))
    }
}

impl TpmTransport for DeviceTransport {
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let file = self.ensure_opened()?;
        file.write_all(command)
            .map_err(|err| ProtocolError::TpmError(format!("TPM device write failed: {err}")))?;

        let mut buffer = vec![0u8; 4096];
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|err| ProtocolError::TpmError(format!("TPM device read failed: {err}")))?;

        if bytes_read < 10 {
            return Err(ProtocolError::TpmError(format!(
                "TPM device returned truncated response: {bytes_read} bytes"
            )));
        }

        buffer.truncate(bytes_read);
        Ok(buffer)
    }
}

// =========================================================================
// TPM 2.0 Wire Protocol Client
// =========================================================================

/// Public information read from an NV index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvPublicInfo {
    /// NV index handle.
    pub nv_index: u32,
    /// Name algorithm (typically SHA-256 = `0x000B`).
    pub name_alg: u16,
    /// Exact 32-bit `TPMA_NV` attributes mask.
    pub attributes: u32,
    /// Authorization policy digest ($D_{\text{target}}$).
    pub auth_policy: Vec<u8>,
    /// Capacity in bytes.
    pub data_size: u16,
}

/// Client implementing standard TPM 2.0 Part 3 commands over a [`TpmTransport`].
pub struct TpmClient<T: TpmTransport> {
    transport: T,
}

impl<T: TpmTransport> fmt::Debug for TpmClient<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmClient").finish_non_exhaustive()
    }
}

impl<T: TpmTransport> TpmClient<T> {
    /// Creates a new TPM client wrapping `transport`.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Transmits a framed command and verifies the return code.
    ///
    /// # Errors
    /// Returns [`ProtocolError::TpmError`] if return code is non-zero.
    pub fn execute_raw(&mut self, cmd: &[u8]) -> Result<(u16, u32, Vec<u8>), ProtocolError> {
        let resp = self.transport.transceive(cmd)?;
        if resp.len() < 10 {
            return Err(ProtocolError::TpmError(
                "TPM response frame too short".to_string(),
            ));
        }
        let tag = u16::from_be_bytes([resp[0], resp[1]]);
        let size = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]);
        let _ = size;
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        let body = if resp.len() > 10 {
            resp[10..].to_vec()
        } else {
            Vec::new()
        };
        Ok((tag, rc, body))
    }

    /// Issues `TPM2_Startup(TPM_SU_CLEAR)`. Tolerates `TPM_RC_INITIALIZE` if already started.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if startup fails.
    pub fn startup(&mut self) -> Result<(), ProtocolError> {
        // Tag 0x8001, Size 12, CC 0x00000144, StartupType 0x0000 (TPM_SU_CLEAR)
        let mut cmd = Vec::with_capacity(12);
        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&12u32.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_STARTUP.to_be_bytes());
        cmd.extend_from_slice(&0u16.to_be_bytes());

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS || rc == TPM_RC_INITIALIZE {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_Startup failed with response code 0x{rc:08X}"
            )))
        }
    }

    /// Queries `TPM2_NV_ReadPublic` for `nv_index`.
    ///
    /// Returns `Ok(None)` if the handle is undefined (`TPM_RC_HANDLE`).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] on transport or unexpected TPM errors.
    pub fn read_nv_public(&mut self, nv_index: u32) -> Result<Option<NvPublicInfo>, ProtocolError> {
        let mut cmd = Vec::with_capacity(14);
        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&14u32.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_NV_READ_PUBLIC.to_be_bytes());
        cmd.extend_from_slice(&nv_index.to_be_bytes());

        let (_tag, rc, body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_HANDLE {
            return Ok(None);
        }
        if rc != TPM_RC_SUCCESS {
            return Err(ProtocolError::TpmError(format!(
                "TPM2_NV_ReadPublic for 0x{nv_index:08X} failed with rc 0x{rc:08X}"
            )));
        }

        // Parse TPMS_NV_PUBLIC:
        // u16 nvPublicSize
        // u32 nvIndex
        // u16 nameAlg
        // u32 attributes
        // u16 authPolicySize, followed by authPolicy bytes
        // u16 dataSize
        if body.len() < 14 {
            return Err(ProtocolError::TpmError(
                "truncated NV_ReadPublic response payload".to_string(),
            ));
        }

        let idx = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
        let name_alg = u16::from_be_bytes([body[6], body[7]]);
        let attributes = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
        let policy_size = u16::from_be_bytes([body[12], body[13]]) as usize;

        if body.len() < 14 + policy_size + 2 {
            return Err(ProtocolError::TpmError(
                "malformed NV public policy structure".to_string(),
            ));
        }

        let policy = body[14..14 + policy_size].to_vec();
        let data_size_offset = 14 + policy_size;
        let data_size = u16::from_be_bytes([body[data_size_offset], body[data_size_offset + 1]]);

        Ok(Some(NvPublicInfo {
            nv_index: idx,
            name_alg,
            attributes,
            auth_policy: policy,
            data_size,
        }))
    }

    /// Computes normative two-stage policy digest $D_{\text{target}}$ per TCG Part 1 §23.17 & D4 spec §7.1.
    #[must_use]
    pub fn compute_target_policy(name_auth: &[u8]) -> [u8; 32] {
        let d0 = [0u8; 32];
        let mut h1 = Sha256::new();
        h1.update(d0);
        h1.update(TPM_CC_POLICY_COMMAND_CODE.to_be_bytes());
        h1.update(TPM_CC_NV_INCREMENT.to_be_bytes());
        let d1 = h1.finalize();

        let mut h2 = Sha256::new();
        h2.update(d1);
        h2.update(TPM_CC_POLICY_SECRET.to_be_bytes());
        h2.update(name_auth);
        let d2 = h2.finalize();

        let mut h_target = Sha256::new();
        h_target.update(d2);
        h_target.finalize().into()
    }

    /// Defines NV counter space (`0x01800001`) with attributes `0x02040018`.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if space definition fails.
    pub fn define_nv_counter(
        &mut self,
        nv_index: u32,
        policy: &[u8; 32],
        owner_auth: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        self.define_nv_space_internal(
            nv_index,
            TPM_ALG_SHA256,
            NV_COUNTER_ATTRIBUTES,
            policy,
            8,
            owner_auth,
        )
    }

    /// Defines NV lifecycle space (`0x01800002`) with attributes `0x02042002`.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if space definition fails.
    pub fn define_nv_lifecycle(
        &mut self,
        nv_index: u32,
        owner_auth: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        self.define_nv_space_internal(
            nv_index,
            TPM_ALG_SHA256,
            NV_LIFECYCLE_ATTRIBUTES,
            &[],
            32,
            owner_auth,
        )
    }

    fn define_nv_space_internal(
        &mut self,
        nv_index: u32,
        name_alg: u16,
        attributes: u32,
        policy: &[u8],
        data_size: u16,
        owner_auth: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        let auth_val = owner_auth.unwrap_or(b"");
        let session_bytes = Self::build_pw_session(auth_val);

        let mut nv_pub = Vec::with_capacity(16 + policy.len());
        nv_pub.extend_from_slice(&nv_index.to_be_bytes());
        nv_pub.extend_from_slice(&name_alg.to_be_bytes());
        nv_pub.extend_from_slice(&attributes.to_be_bytes());
        let policy_len = u16::try_from(policy.len()).map_err(|_| ProtocolError::InvalidLength {
            expected: 32,
            actual: policy.len(),
        })?;
        nv_pub.extend_from_slice(&policy_len.to_be_bytes());
        nv_pub.extend_from_slice(policy);
        nv_pub.extend_from_slice(&data_size.to_be_bytes());

        let mut params = Vec::new();
        params.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        params.extend_from_slice(&session_bytes);
        params.extend_from_slice(&0u16.to_be_bytes()); // empty authValue for NV index itself
        let pub_len = u16::try_from(nv_pub.len())
            .map_err(|_| ProtocolError::TpmError("nv_pub length overflow".to_string()))?;
        params.extend_from_slice(&pub_len.to_be_bytes());
        params.extend_from_slice(&nv_pub);

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("command size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_NV_DEFINE_SPACE.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_NV_DefineSpace for 0x{nv_index:08X} failed with rc 0x{rc:08X}"
            )))
        }
    }

    /// Undefines an NV index under Owner authorization.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if undefine fails.
    pub fn undefine_nv_space(
        &mut self,
        nv_index: u32,
        owner_auth: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        let auth_val = owner_auth.unwrap_or(b"");
        let session = Self::build_pw_session(auth_val);

        let mut params = Vec::new();
        params.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        params.extend_from_slice(&nv_index.to_be_bytes());
        params.extend_from_slice(&session);

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_NV_UNDEFINE_SPACE.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS || rc == TPM_RC_HANDLE {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_NV_UndefineSpace for 0x{nv_index:08X} failed with rc 0x{rc:08X}"
            )))
        }
    }

    /// Writes data to an NV index (e.g. initial lifecycle ID).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if write fails.
    pub fn write_nv(
        &mut self,
        nv_index: u32,
        offset: u16,
        data: &[u8],
        owner_auth: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        let auth_val = owner_auth.unwrap_or(b"");
        let session = Self::build_pw_session(auth_val);

        let mut params = Vec::new();
        params.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        params.extend_from_slice(&nv_index.to_be_bytes());
        params.extend_from_slice(&session);
        let data_len = u16::try_from(data.len()).map_err(|_| ProtocolError::InvalidLength {
            expected: 32,
            actual: data.len(),
        })?;
        params.extend_from_slice(&data_len.to_be_bytes());
        params.extend_from_slice(data);
        params.extend_from_slice(&offset.to_be_bytes());

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_NV_WRITE.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_NV_Write for 0x{nv_index:08X} failed with rc 0x{rc:08X}"
            )))
        }
    }

    /// Permanently locks writes on an ordinary NV index (`TPM2_NV_WriteLock`).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if locking fails.
    pub fn write_lock_nv(
        &mut self,
        nv_index: u32,
        owner_auth: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        let auth_val = owner_auth.unwrap_or(b"");
        let session = Self::build_pw_session(auth_val);

        let mut params = Vec::new();
        params.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        params.extend_from_slice(&nv_index.to_be_bytes());
        params.extend_from_slice(&session);

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_NV_WRITE_LOCK.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_NV_WriteLock for 0x{nv_index:08X} failed with rc 0x{rc:08X}"
            )))
        }
    }

    /// Reads data from an NV index via unprivileged auth session (`TPM_RS_PW` / empty password).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if reading fails.
    pub fn read_nv(
        &mut self,
        nv_index: u32,
        offset: u16,
        size: u16,
    ) -> Result<Vec<u8>, ProtocolError> {
        let session = Self::build_pw_session(b"");

        let mut params = Vec::new();
        params.extend_from_slice(&nv_index.to_be_bytes()); // authHandle = nv_index
        params.extend_from_slice(&nv_index.to_be_bytes()); // nvIndex
        params.extend_from_slice(&session);
        params.extend_from_slice(&size.to_be_bytes());
        params.extend_from_slice(&offset.to_be_bytes());

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_NV_READ.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, body) = self.execute_raw(&cmd)?;
        if rc != TPM_RC_SUCCESS {
            return Err(ProtocolError::TpmError(format!(
                "TPM2_NV_Read for 0x{nv_index:08X} failed with rc 0x{rc:08X}"
            )));
        }

        // Response with session:
        // u32 parameterSize
        // u16 dataSize, data bytes...
        if body.len() < 6 {
            return Err(ProtocolError::TpmError(
                "truncated NV_Read response".to_string(),
            ));
        }
        let data_len = u16::from_be_bytes([body[4], body[5]]) as usize;
        if body.len() < 6 + data_len {
            return Err(ProtocolError::TpmError(
                "truncated NV data buffer in response".to_string(),
            ));
        }

        Ok(body[6..6 + data_len].to_vec())
    }

    /// Starts a policy authorization session (`TPM_SE_POLICY`).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] on session creation failure.
    pub fn start_policy_session(&mut self) -> Result<u32, ProtocolError> {
        let mut params = Vec::new();
        params.extend_from_slice(&TPM_RH_NULL.to_be_bytes()); // tpmKey = NULL
        params.extend_from_slice(&TPM_RH_NULL.to_be_bytes()); // bind = NULL
        params.extend_from_slice(&16u16.to_be_bytes()); // nonceCaller size 16
        params.extend_from_slice(&[0u8; 16]); // caller nonce bytes
        params.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt size 0
        params.push(TPM_SE_POLICY); // sessionType = POLICY
        params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric = NULL
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // authHash = SHA256

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_START_AUTH_SESSION.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, body) = self.execute_raw(&cmd)?;
        if rc != TPM_RC_SUCCESS {
            return Err(ProtocolError::TpmError(format!(
                "TPM2_StartAuthSession failed with rc 0x{rc:08X}"
            )));
        }
        if body.len() < 4 {
            return Err(ProtocolError::TpmError(
                "truncated StartAuthSession response".to_string(),
            ));
        }

        let session_handle = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        Ok(session_handle)
    }

    /// Constrains a policy session to `command_code` (`TPM2_PolicyCommandCode`).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if command code binding fails.
    pub fn policy_command_code(
        &mut self,
        session_handle: u32,
        command_code: u32,
    ) -> Result<(), ProtocolError> {
        let mut cmd = Vec::with_capacity(18);
        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&18u32.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_POLICY_COMMAND_CODE.to_be_bytes());
        cmd.extend_from_slice(&session_handle.to_be_bytes());
        cmd.extend_from_slice(&command_code.to_be_bytes());

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_PolicyCommandCode failed with rc 0x{rc:08X}"
            )))
        }
    }

    /// Evaluates `TPM2_PolicySecret` against `auth_handle` with given authorization.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if secret evaluation fails.
    pub fn policy_secret(
        &mut self,
        auth_handle: u32,
        session_handle: u32,
        auth: Option<&[u8]>,
    ) -> Result<(), ProtocolError> {
        let auth_val = auth.unwrap_or(b"");
        let session = Self::build_pw_session(auth_val);

        let mut params = Vec::new();
        params.extend_from_slice(&auth_handle.to_be_bytes());
        params.extend_from_slice(&session_handle.to_be_bytes());
        params.extend_from_slice(&session);
        params.extend_from_slice(&0u16.to_be_bytes()); // nonceTPM size 0
        params.extend_from_slice(&0u16.to_be_bytes()); // cpHashA size 0
        params.extend_from_slice(&0u16.to_be_bytes()); // policyRef size 0
        params.extend_from_slice(&0i32.to_be_bytes()); // expiration 0

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_POLICY_SECRET.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_PolicySecret failed with rc 0x{rc:08X}"
            )))
        }
    }

    /// Flushes a transient session handle from TPM memory (`TPM2_FlushContext`).
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if flushing fails.
    pub fn flush_context(&mut self, handle: u32) -> Result<(), ProtocolError> {
        let mut cmd = Vec::with_capacity(14);
        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&14u32.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_FLUSH_CONTEXT.to_be_bytes());
        cmd.extend_from_slice(&handle.to_be_bytes());

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS || rc == TPM_RC_HANDLE {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_FlushContext failed for 0x{handle:08X} with rc 0x{rc:08X}"
            )))
        }
    }

    /// Increments an NV counter index using the active policy session.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if increment fails.
    pub fn increment_nv_counter(
        &mut self,
        nv_index: u32,
        session_handle: u32,
    ) -> Result<(), ProtocolError> {
        // Build session using policy session handle
        let mut session = Vec::with_capacity(13);
        session.extend_from_slice(&9u32.to_be_bytes()); // session area size = 9
        session.extend_from_slice(&session_handle.to_be_bytes()); // session handle
        session.extend_from_slice(&0u16.to_be_bytes()); // nonce size 0
        session.push(0x00); // session attributes 0
        session.extend_from_slice(&0u16.to_be_bytes()); // hmac/auth size 0

        let mut params = Vec::new();
        params.extend_from_slice(&nv_index.to_be_bytes()); // authHandle = nv_index
        params.extend_from_slice(&nv_index.to_be_bytes()); // nvIndex
        params.extend_from_slice(&session);

        let total_size = u32::try_from(10 + params.len())
            .map_err(|_| ProtocolError::TpmError("size overflow".to_string()))?;
        let mut cmd = Vec::with_capacity(total_size as usize);
        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_CC_NV_INCREMENT.to_be_bytes());
        cmd.extend_from_slice(&params);

        let (_tag, rc, _body) = self.execute_raw(&cmd)?;
        if rc == TPM_RC_SUCCESS {
            Ok(())
        } else {
            Err(ProtocolError::TpmError(format!(
                "TPM2_NV_Increment for 0x{nv_index:08X} failed with rc 0x{rc:08X}"
            )))
        }
    }

    fn build_pw_session(auth: &[u8]) -> Vec<u8> {
        let auth_len = u16::try_from(auth.len()).unwrap_or(u16::MAX);
        let area_len = 4 + 2 + 1 + 2 + auth.len();
        let area_u32 = u32::try_from(area_len).unwrap_or(u32::MAX);
        let mut s = Vec::with_capacity(4 + area_len);
        s.extend_from_slice(&area_u32.to_be_bytes());
        s.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        s.extend_from_slice(&0u16.to_be_bytes()); // nonceCaller len 0
        s.push(0x00); // sessionAttributes 0
        s.extend_from_slice(&auth_len.to_be_bytes());
        s.extend_from_slice(auth);
        s
    }
}

// =========================================================================
// TPM-backed MonotonicCounter Adapter
// =========================================================================

/// Configuration options for [`TpmMonotonicCounter`].
#[derive(Debug, Clone)]
pub struct TpmCounterConfig {
    /// NV counter index handle (default `0x01800001`).
    pub nv_index: u32,
    /// Authorization handle for policy secret (default `TPM_RH_OWNER`).
    pub auth_handle: u32,
    /// Owner or secret authorization bytes.
    pub owner_auth: Option<Vec<u8>>,
    /// Precomputed target authorization policy ($D_{\text{target}}$).
    pub target_policy: [u8; 32],
    /// Maximum retry attempts for transient TPM errors (`TPM_RC_RETRY`).
    pub max_retries: usize,
    /// Base backoff duration between retries.
    pub retry_backoff: Duration,
}

impl Default for TpmCounterConfig {
    fn default() -> Self {
        let name_owner = TPM_RH_OWNER.to_be_bytes();
        let target_policy = TpmClient::<UnixSocketTransport>::compute_target_policy(&name_owner);
        Self {
            nv_index: DEFAULT_NV_COUNTER_INDEX,
            auth_handle: TPM_RH_OWNER,
            owner_auth: None,
            target_policy,
            max_retries: 3,
            retry_backoff: Duration::from_millis(50),
        }
    }
}

/// Production implementation of [`MonotonicCounter`] backed by a hardware or software TPM 2.0.
pub struct TpmMonotonicCounter<T: TpmTransport> {
    client: Arc<Mutex<TpmClient<T>>>,
    config: TpmCounterConfig,
}

impl<T: TpmTransport> fmt::Debug for TpmMonotonicCounter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmMonotonicCounter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T: TpmTransport> TpmMonotonicCounter<T> {
    /// Creates a new TPM monotonic counter adapter wrapping `client`.
    pub fn new(client: TpmClient<T>, config: TpmCounterConfig) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            config,
        }
    }

    /// Returns a shared reference to the inner client mutex.
    #[must_use]
    pub fn client(&self) -> Arc<Mutex<TpmClient<T>>> {
        Arc::clone(&self.client)
    }
}

impl<T: TpmTransport> MonotonicCounter for TpmMonotonicCounter<T> {
    #[allow(clippy::significant_drop_tightening)]
    fn read_counter(&self) -> Result<u64, ProtocolError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| ProtocolError::TpmError("TPM client mutex poisoned".to_string()))?;

        let bytes = client.read_nv(self.config.nv_index, 0, 8)?;
        if bytes.len() != 8 {
            return Err(ProtocolError::InvalidLength {
                expected: 8,
                actual: bytes.len(),
            });
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
            expected: 8,
            actual: 0,
        })?;
        Ok(u64::from_be_bytes(arr))
    }

    #[allow(clippy::significant_drop_tightening, clippy::needless_continue)]
    fn increment_counter(&mut self) -> Result<u64, ProtocolError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| ProtocolError::TpmError("TPM client mutex poisoned".to_string()))?;

        let mut attempts = 0usize;
        loop {
            attempts += 1;

            // 1. Start Policy Auth Session
            let session_handle = client.start_policy_session()?;

            // 2. Set PolicyCommandCode(TPM_CC_NV_Increment)
            let res = client
                .policy_command_code(session_handle, TPM_CC_NV_INCREMENT)
                .and_then(|()| {
                    // 3. Set PolicySecret(auth_handle, session_handle, owner_auth)
                    client.policy_secret(
                        self.config.auth_handle,
                        session_handle,
                        self.config.owner_auth.as_deref(),
                    )
                })
                .and_then(|()| {
                    // 4. Execute NV_Increment
                    client.increment_nv_counter(self.config.nv_index, session_handle)
                });

            // Always flush session context
            let _ = client.flush_context(session_handle);

            match res {
                Ok(()) => {
                    // Read new counter value
                    let bytes = client.read_nv(self.config.nv_index, 0, 8)?;
                    if bytes.len() != 8 {
                        return Err(ProtocolError::InvalidLength {
                            expected: 8,
                            actual: bytes.len(),
                        });
                    }
                    let arr: [u8; 8] =
                        bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                            expected: 8,
                            actual: 0,
                        })?;
                    return Ok(u64::from_be_bytes(arr));
                }
                Err(ProtocolError::TpmError(msg))
                    if (msg.contains("0x00000922") || msg.contains("0x00000908"))
                        && attempts < self.config.max_retries =>
                {
                    // Transient retry error from TPM
                    let attempts_u32 = u32::try_from(attempts).unwrap_or(u32::MAX);
                    thread::sleep(self.config.retry_backoff.saturating_mul(attempts_u32));
                }
                Err(err) => return Err(err),
            }
        }
    }
}

// =========================================================================
// Four-State Provisioning Lifecycle Machine
// =========================================================================

/// State classification for OpenAudit TPM 2.0 provisioning lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningState {
    /// Fresh machine or newly initialized TPM; clean state required.
    FreshProvisioning,
    /// Existing valid deployment; verified and recovered safely.
    ExistingValidationAndRecovery,
    /// Explicit destructive rotation authorized by operator.
    ExplicitCredentialRotation,
    /// Inconsistent, partial, or cleared TPM; quarantine enforced.
    TpmClearOrLifecycleMismatchQuarantine,
}

/// Manager executing the four-state provisioning lifecycle per specification §7.1.
pub struct TpmProvisioningManager<T: TpmTransport> {
    client: TpmClient<T>,
    state_dir: PathBuf,
}

impl<T: TpmTransport> fmt::Debug for TpmProvisioningManager<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmProvisioningManager")
            .field("state_dir", &self.state_dir)
            .finish_non_exhaustive()
    }
}

impl<T: TpmTransport> TpmProvisioningManager<T> {
    /// Creates a provisioning manager for `state_dir`.
    pub fn new(client: TpmClient<T>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            client,
            state_dir: state_dir.into(),
        }
    }

    /// Determines current lifecycle state based on filesystem artifacts and TPM NV indices.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if TPM query fails.
    pub fn determine_state(
        &mut self,
        rotate_flag: bool,
    ) -> Result<ProvisioningState, ProtocolError> {
        if rotate_flag {
            return Ok(ProvisioningState::ExplicitCredentialRotation);
        }

        let secret_path = self.state_dir.join("tpm-auth.secret");
        let lifecycle_path = self.state_dir.join("lifecycle_id.bin");

        let has_secret = secret_path.is_file();
        let has_lifecycle = lifecycle_path.is_file();

        let counter_info = self.client.read_nv_public(DEFAULT_NV_COUNTER_INDEX)?;
        let lc_info = self.client.read_nv_public(DEFAULT_NV_LIFECYCLE_INDEX)?;

        let has_counter_nv = counter_info.is_some();
        let has_lc_nv = lc_info.is_some();

        if !has_secret && !has_lifecycle && !has_counter_nv && !has_lc_nv {
            Ok(ProvisioningState::FreshProvisioning)
        } else if has_secret && has_lifecycle && has_counter_nv && has_lc_nv {
            Ok(ProvisioningState::ExistingValidationAndRecovery)
        } else {
            Ok(ProvisioningState::TpmClearOrLifecycleMismatchQuarantine)
        }
    }

    /// Executes provisioning according to determined lifecycle state.
    ///
    /// # Errors
    /// Returns [`ProtocolError::QuarantineEnforced`] if state is quarantined and override is false.
    pub fn execute(
        &mut self,
        rotate_flag: bool,
        quarantine_override: bool,
        owner_auth: Option<&[u8]>,
    ) -> Result<u64, ProtocolError> {
        let state = self.determine_state(rotate_flag)?;

        match state {
            ProvisioningState::TpmClearOrLifecycleMismatchQuarantine => {
                if !quarantine_override {
                    return Err(ProtocolError::QuarantineEnforced(
                        "partial or cleared TPM state detected; quarantine enforced to prevent silent state substitution".to_string(),
                    ));
                }
                // Purge broken state and fall through to fresh provisioning
                self.purge_local_files();
                let _ = self
                    .client
                    .undefine_nv_space(DEFAULT_NV_COUNTER_INDEX, owner_auth);
                let _ = self
                    .client
                    .undefine_nv_space(DEFAULT_NV_LIFECYCLE_INDEX, owner_auth);
                self.execute_fresh_provisioning(owner_auth)
            }
            ProvisioningState::ExplicitCredentialRotation => {
                self.purge_local_files();
                let _ = self
                    .client
                    .undefine_nv_space(DEFAULT_NV_COUNTER_INDEX, owner_auth);
                let _ = self
                    .client
                    .undefine_nv_space(DEFAULT_NV_LIFECYCLE_INDEX, owner_auth);
                self.execute_fresh_provisioning(owner_auth)
            }
            ProvisioningState::FreshProvisioning => self.execute_fresh_provisioning(owner_auth),
            ProvisioningState::ExistingValidationAndRecovery => self.validate_existing(owner_auth),
        }
    }

    fn execute_fresh_provisioning(
        &mut self,
        owner_auth: Option<&[u8]>,
    ) -> Result<u64, ProtocolError> {
        std::fs::create_dir_all(&self.state_dir).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to create state dir: {err}"))
        })?;

        // 1. Generate 32-byte authorization secret
        let mut secret = [0u8; 32];
        for b in &mut secret {
            *b = (uuid::Uuid::new_v4().as_u128() & 0xFF) as u8;
        }

        // 2. Compute Target Policy for Owner
        let name_owner = TPM_RH_OWNER.to_be_bytes();
        let target_policy = TpmClient::<T>::compute_target_policy(&name_owner);

        // 3. Define Counter NV Index 0x01800001
        self.client
            .define_nv_counter(DEFAULT_NV_COUNTER_INDEX, &target_policy, owner_auth)?;

        // 4. Define & Lock Lifecycle NV Index 0x01800002
        self.client
            .define_nv_lifecycle(DEFAULT_NV_LIFECYCLE_INDEX, owner_auth)?;

        let mut lifecycle_id = [0u8; 32];
        let (p1, p2) = (
            uuid::Uuid::new_v4().as_u128(),
            uuid::Uuid::new_v4().as_u128(),
        );
        lifecycle_id[..16].copy_from_slice(&p1.to_be_bytes());
        lifecycle_id[16..].copy_from_slice(&p2.to_be_bytes());

        self.client
            .write_nv(DEFAULT_NV_LIFECYCLE_INDEX, 0, &lifecycle_id, owner_auth)?;
        self.client
            .write_lock_nv(DEFAULT_NV_LIFECYCLE_INDEX, owner_auth)?;

        // 5. First Increment to initialize hardware counter baseline
        let session = self.client.start_policy_session()?;
        self.client
            .policy_command_code(session, TPM_CC_NV_INCREMENT)?;
        self.client
            .policy_secret(TPM_RH_OWNER, session, owner_auth)?;
        self.client
            .increment_nv_counter(DEFAULT_NV_COUNTER_INDEX, session)?;
        let _ = self.client.flush_context(session);

        // 6. Persist local state files with strict 0600 permissions
        let secret_path = self.state_dir.join("tpm-auth.secret");
        let lifecycle_path = self.state_dir.join("lifecycle_id.bin");

        let mut sf = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&secret_path)
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to write secret file: {err}"))
            })?;
        sf.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to chmod secret file: {err}"))
            })?;
        sf.write_all(&secret).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to write secret bytes: {err}"))
        })?;

        let mut lf = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lifecycle_path)
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to write lifecycle file: {err}"))
            })?;
        lf.write_all(&lifecycle_id).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to write lifecycle bytes: {err}"))
        })?;

        // 7. Read baseline counter
        let counter_bytes = self.client.read_nv(DEFAULT_NV_COUNTER_INDEX, 0, 8)?;
        let arr: [u8; 8] = counter_bytes
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength {
                expected: 8,
                actual: 0,
            })?;
        Ok(u64::from_be_bytes(arr))
    }

    fn validate_existing(&mut self, _owner_auth: Option<&[u8]>) -> Result<u64, ProtocolError> {
        let secret_path = self.state_dir.join("tpm-auth.secret");
        let lifecycle_path = self.state_dir.join("lifecycle_id.bin");

        let secret = std::fs::read(&secret_path)
            .map_err(|err| ProtocolError::SecretError(format!("missing secret file: {err}")))?;
        if secret.len() != 32 {
            return Err(ProtocolError::SecretError(format!(
                "secret file size is {} bytes (expected 32)",
                secret.len()
            )));
        }

        let stored_lifecycle = std::fs::read(&lifecycle_path)
            .map_err(|err| ProtocolError::SecretError(format!("missing lifecycle file: {err}")))?;
        if stored_lifecycle.len() != 32 {
            return Err(ProtocolError::SecretError(format!(
                "lifecycle file size is {} bytes (expected 32)",
                stored_lifecycle.len()
            )));
        }

        // Validate counter index
        let counter_info = self
            .client
            .read_nv_public(DEFAULT_NV_COUNTER_INDEX)?
            .ok_or_else(|| {
                ProtocolError::QuarantineEnforced("counter NV index 0x01800001 missing".to_string())
            })?;

        // Validate counter index: mask out runtime TPMA_NV_WRITTEN (0x2000_0000)
        if (counter_info.attributes & !0x2000_0000) != NV_COUNTER_ATTRIBUTES {
            return Err(ProtocolError::QuarantineEnforced(format!(
                "counter attributes mismatch: expected 0x{NV_COUNTER_ATTRIBUTES:08X}, observed 0x{:08X}",
                counter_info.attributes
            )));
        }

        // Validate lifecycle index: mask out runtime TPMA_NV_WRITTEN (0x2000_0000) and TPMA_NV_WRITELOCKED (0x0000_0800)
        let lc_info = self
            .client
            .read_nv_public(DEFAULT_NV_LIFECYCLE_INDEX)?
            .ok_or_else(|| {
                ProtocolError::QuarantineEnforced(
                    "lifecycle NV index 0x01800002 missing".to_string(),
                )
            })?;

        if (lc_info.attributes & !(0x2000_0000 | 0x0000_0800)) != NV_LIFECYCLE_ATTRIBUTES {
            return Err(ProtocolError::QuarantineEnforced(format!(
                "lifecycle attributes mismatch: expected 0x{NV_LIFECYCLE_ATTRIBUTES:08X}, observed 0x{:08X}",
                lc_info.attributes
            )));
        }

        // Confirm lifecycle index is write-locked
        if (lc_info.attributes & 0x0000_0800) == 0 {
            return Err(ProtocolError::QuarantineEnforced(
                "lifecycle NV index is not write-locked".to_string(),
            ));
        }

        // Validate lifecycle value matches file
        let tpm_lc = self.client.read_nv(DEFAULT_NV_LIFECYCLE_INDEX, 0, 32)?;
        if tpm_lc != stored_lifecycle {
            return Err(ProtocolError::QuarantineEnforced(
                "stored lifecycle ID does not match hardware TPM lifecycle index".to_string(),
            ));
        }

        // Read counter baseline
        let counter_bytes = self.client.read_nv(DEFAULT_NV_COUNTER_INDEX, 0, 8)?;
        let arr: [u8; 8] = counter_bytes
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength {
                expected: 8,
                actual: 0,
            })?;
        Ok(u64::from_be_bytes(arr))
    }

    fn purge_local_files(&self) {
        let _ = std::fs::remove_file(self.state_dir.join("tpm-auth.secret"));
        let _ = std::fs::remove_file(self.state_dir.join("lifecycle_id.bin"));
    }
}

// =========================================================================
// Tests: Specification Vectors & Live swtpm Integration Suite
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AssessmentCatalog, CatalogManager, RecoveryOutcome};
    use std::path::Path;
    use std::process::{Child, Command};
    use std::sync::Mutex;
    use tempfile::TempDir;

    static SWTPM_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// Helper harness managing a live local `swtpm` instance.
    pub struct SwtpmTestHarness {
        _temp_dir: TempDir,
        state_dir: PathBuf,
        ctrl_path: PathBuf,
        sock_path: PathBuf,
        child: Option<Child>,
    }

    impl SwtpmTestHarness {
        #[must_use]
        pub fn new() -> Option<Self> {
            let swtpm_bin = if Path::new("/opt/homebrew/bin/swtpm").is_file() {
                "/opt/homebrew/bin/swtpm".to_string()
            } else if let Ok(out) = Command::new("which").arg("swtpm").output() {
                if out.status.success() {
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                } else {
                    return None;
                }
            } else {
                return None;
            };

            let temp_dir = tempfile::tempdir().ok()?;
            let state_dir = temp_dir.path().join("tpmstate");
            std::fs::create_dir_all(&state_dir).ok()?;
            let ctrl_path = state_dir.join("ctrl.sock");
            let sock_path = state_dir.join("tpm.sock");

            let child = Command::new(&swtpm_bin)
                .args([
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    &format!("dir={}", state_dir.display()),
                    "--ctrl",
                    &format!("type=unixio,path={}", ctrl_path.display()),
                    "--server",
                    &format!("type=unixio,path={}", sock_path.display()),
                    "--flags",
                    "not-need-init,startup-clear",
                ])
                .spawn()
                .ok()?;

            let mut connected = false;
            for _ in 0..50 {
                thread::sleep(Duration::from_millis(50));
                if sock_path.exists() {
                    thread::sleep(Duration::from_millis(50));
                    connected = true;
                    break;
                }
            }

            if !connected {
                let mut c = child;
                let _ = c.kill();
                let _ = c.wait();
                return None;
            }

            Some(Self {
                _temp_dir: temp_dir,
                state_dir,
                ctrl_path,
                sock_path,
                child: Some(child),
            })
        }

        #[must_use]
        pub fn connect_client(&self) -> TpmClient<UnixSocketTransport> {
            let transport = UnixSocketTransport::new(&self.sock_path);
            TpmClient::new(transport)
        }

        pub fn restart(&mut self) -> Result<(), ProtocolError> {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }

            let _ = std::fs::remove_file(&self.sock_path);
            let _ = std::fs::remove_file(&self.ctrl_path);

            let swtpm_bin = if Path::new("/opt/homebrew/bin/swtpm").is_file() {
                "/opt/homebrew/bin/swtpm".to_string()
            } else {
                "swtpm".to_string()
            };

            let child = Command::new(&swtpm_bin)
                .args([
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    &format!("dir={}", self.state_dir.display()),
                    "--ctrl",
                    &format!("type=unixio,path={}", self.ctrl_path.display()),
                    "--server",
                    &format!("type=unixio,path={}", self.sock_path.display()),
                    "--flags",
                    "not-need-init,startup-clear",
                ])
                .spawn()
                .map_err(|err| {
                    ProtocolError::TpmError(format!("failed to respawn swtpm: {err}"))
                })?;

            let mut connected = false;
            for _ in 0..50 {
                thread::sleep(Duration::from_millis(50));
                if self.sock_path.exists() {
                    thread::sleep(Duration::from_millis(50));
                    connected = true;
                    break;
                }
            }

            if !connected {
                let mut c = child;
                let _ = c.kill();
                let _ = c.wait();
                return Err(ProtocolError::TpmError(
                    "respawned swtpm failed to become ready".to_string(),
                ));
            }

            self.child = Some(child);
            Ok(())
        }
    }

    impl Drop for SwtpmTestHarness {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn test_target_policy_calculation_matches_spec() {
        // Spec §7.1 normative test reference template:
        // Name_auth = 000b98687a71842813589b917578ec6b5e0c52bbbc0b2c1f93f6b7c9aa029f6db805
        // D_target = 4e9e12f58b0f9bf049703727ca2c2bb7d33737b1d4d7ea2c629ffb02b0058bbe
        let name_auth_hex = "000b98687a71842813589b917578ec6b5e0c52bbbc0b2c1f93f6b7c9aa029f6db805";
        let name_auth: Vec<u8> = (0..name_auth_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&name_auth_hex[i..i + 2], 16).unwrap())
            .collect();

        let target_policy = TpmClient::<UnixSocketTransport>::compute_target_policy(&name_auth);
        let target_hex = target_policy.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });

        assert_eq!(
            target_hex,
            "4e9e12f58b0f9bf049703727ca2c2bb7d33737b1d4d7ea2c629ffb02b0058bbe"
        );
    }

    #[test]
    fn test_swtpm_startup_and_connection() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };
        let mut client = harness.connect_client();
        let res = client.startup();
        assert!(res.is_ok(), "TPM2_Startup must succeed: {res:?}");
    }

    #[test]
    fn test_swtpm_nv_counter_provisioning_and_read() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let prov_dir = tempfile::tempdir().unwrap();
        let baseline = {
            let client = harness.connect_client();
            let mut prov = TpmProvisioningManager::new(client, prov_dir.path());
            prov.execute(false, false, None)
                .expect("fresh provisioning must succeed")
        };
        assert_eq!(baseline, 1);

        // Verify artifacts on disk
        let secret_file = prov_dir.path().join("tpm-auth.secret");
        let lc_file = prov_dir.path().join("lifecycle_id.bin");
        assert!(secret_file.is_file());
        assert!(lc_file.is_file());

        let sf_meta = std::fs::metadata(&secret_file).unwrap();
        #[cfg(unix)]
        assert_eq!(sf_meta.permissions().mode() & 0o777, 0o600);

        // Verify NV attributes
        let mut client = harness.connect_client();
        let counter_info = client
            .read_nv_public(DEFAULT_NV_COUNTER_INDEX)
            .unwrap()
            .expect("counter NV index defined");
        assert_eq!(
            counter_info.attributes & !0x2000_0000,
            NV_COUNTER_ATTRIBUTES
        );
        assert_eq!(counter_info.data_size, 8);

        let lc_info = client
            .read_nv_public(DEFAULT_NV_LIFECYCLE_INDEX)
            .unwrap()
            .expect("lifecycle NV index defined");
        assert_eq!(
            lc_info.attributes & !(0x2000_0000 | 0x0000_0800),
            NV_LIFECYCLE_ATTRIBUTES
        );
        assert_ne!(lc_info.attributes & 0x0000_0800, 0);
        assert_eq!(lc_info.data_size, 32);
    }

    #[test]
    fn test_swtpm_repeated_increments_and_monotonicity() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let prov_dir = tempfile::tempdir().unwrap();
        {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            let baseline = prov.execute(false, false, None).unwrap();
            assert_eq!(baseline, 1);
        }

        let client = harness.connect_client();
        let mut counter = TpmMonotonicCounter::new(client, TpmCounterConfig::default());

        // Repeated increments: 2, 3, 4, 5, 6
        for expected in 2..=6 {
            let val = counter.increment_counter().expect("increment must succeed");
            assert_eq!(val, expected);
        }

        // Direct read returns current committed counter
        let final_val = counter.read_counter().expect("read must succeed");
        assert_eq!(final_val, 6);
    }

    #[test]
    fn test_swtpm_persistence_across_process_restart() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let prov_dir = tempfile::tempdir().unwrap();
        {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            prov.execute(false, false, None).unwrap();
        }

        {
            let client = harness.connect_client();
            let mut counter = TpmMonotonicCounter::new(client, TpmCounterConfig::default());

            // Increment counter to 5
            for expected in 2..=5 {
                let val = counter.increment_counter().unwrap();
                assert_eq!(val, expected);
            }
            assert_eq!(counter.read_counter().unwrap(), 5);
        }

        // Kill and restart swtpm process!
        harness.restart().expect("swtpm restart must succeed");

        // Reconnect new client pointing to the restarted swtpm instance
        let restarted_client = harness.connect_client();
        let mut restarted_counter =
            TpmMonotonicCounter::new(restarted_client, TpmCounterConfig::default());

        // Value must persist across process restart!
        let val_after_restart = restarted_counter
            .read_counter()
            .expect("read after restart must succeed");
        assert_eq!(val_after_restart, 5);

        // Further increments continue monotonically
        let val_next = restarted_counter.increment_counter().unwrap();
        assert_eq!(val_next, 6);
    }

    #[test]
    fn test_swtpm_authorization_failure() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let prov_dir = tempfile::tempdir().unwrap();
        {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            prov.execute(false, false, None).unwrap();
        }

        let client = harness.connect_client();
        let config = TpmCounterConfig {
            owner_auth: Some(b"WRONG_UNAUTHORIZED_OWNER_PASSWORD_9999".to_vec()),
            ..Default::default()
        };

        let mut counter = TpmMonotonicCounter::new(client, config);
        let res = counter.increment_counter();
        assert!(
            res.is_err(),
            "increment with invalid auth must fail: {res:?}"
        );
        match res {
            Err(ProtocolError::TpmError(msg)) => {
                assert!(
                    msg.contains("TPM2_PolicySecret") || msg.contains("0x0000098E"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected ProtocolError::TpmError, got {other:?}"),
        }
    }

    #[test]
    fn test_swtpm_missing_or_incorrect_nv_indices() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let mut client = harness.connect_client();
        let public_missing = client.read_nv_public(0x0180_00FF).unwrap();
        assert!(public_missing.is_none());

        let read_missing = client.read_nv(0x0180_00FF, 0, 8);
        assert!(read_missing.is_err());
    }

    #[test]
    fn test_swtpm_unavailable_and_transient_error_handling() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let non_existent = PathBuf::from("/tmp/non_existent_openaudit_swtpm_socket_12345.sock");
        let transport = UnixSocketTransport::new(non_existent);
        let mut client = TpmClient::new(transport);

        let res = client.startup();
        assert!(res.is_err());
        match res {
            Err(ProtocolError::TpmError(msg)) => {
                assert!(msg.contains("failed to connect"));
            }
            other => panic!("expected TpmError, got {other:?}"),
        }
    }

    #[test]
    fn test_swtpm_provisioning_state_machine_and_quarantine() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let prov_dir = tempfile::tempdir().unwrap();

        // 1. Fresh provisioning
        {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            let state = prov.determine_state(false).unwrap();
            assert_eq!(state, ProvisioningState::FreshProvisioning);
            let base = prov.execute(false, false, None).unwrap();
            assert_eq!(base, 1);
        }

        // 2. Existing validation
        {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            let state = prov.determine_state(false).unwrap();
            assert_eq!(state, ProvisioningState::ExistingValidationAndRecovery);
            let base = prov.execute(false, false, None).unwrap();
            assert_eq!(base, 1);
        }

        // 3. Corrupt/delete local secret while TPM has NV indices -> Quarantine!
        let secret_file = prov_dir.path().join("tpm-auth.secret");
        std::fs::remove_file(&secret_file).unwrap();
        {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            let state = prov.determine_state(false).unwrap();
            assert_eq!(
                state,
                ProvisioningState::TpmClearOrLifecycleMismatchQuarantine
            );

            // Without override, execute fails closed with QuarantineEnforced
            let res = prov.execute(false, false, None);
            assert!(matches!(res, Err(ProtocolError::QuarantineEnforced(_))));

            // With quarantine override, purges and recovers cleanly
            let res_override = prov.execute(false, true, None);
            assert!(res_override.is_ok());
        }
    }

    #[test]
    fn test_swtpm_catalog_transaction_integration_and_recovery() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let prov_dir = tempfile::tempdir().unwrap();
        let baseline = {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            prov.execute(false, false, None).unwrap()
        };

        let client = harness.connect_client();
        let mut counter = TpmMonotonicCounter::new(client, TpmCounterConfig::default());

        let catalog_dir = tempfile::tempdir().unwrap();
        let mgr = CatalogManager::open(catalog_dir.path()).unwrap();

        // Initialize catalog at baseline counter = 1, version = 1
        let v1 =
            AssessmentCatalog::new(1, baseline, serde_json::json!({"release": "initial_m3_d4"}))
                .unwrap();
        mgr.initialize_new(&v1).unwrap();

        // Transaction to version 2, counter target = baseline + 1 = 2
        let v2 = AssessmentCatalog::new(
            2,
            baseline + 1,
            serde_json::json!({"release": "updated_m3_d4"}),
        )
        .unwrap();
        mgr.execute_transaction(&v2, &mut counter).unwrap();

        // Verify active catalog and TPM counter match
        let active = mgr.load_active_catalog().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.counter, baseline + 1);

        let tpm_val = counter.read_counter().unwrap();
        assert_eq!(tpm_val, baseline + 1);

        // Recovery on clean state reports CleanCurrent
        let outcome = mgr.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::CleanCurrent);
    }

    #[test]
    fn test_swtpm_catalog_recovery_fails_closed_on_tpm_desync() {
        let _lock = SWTPM_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(harness) = SwtpmTestHarness::new() else {
            eprintln!("SKIP: swtpm not available on host environment");
            return;
        };

        let prov_dir = tempfile::tempdir().unwrap();
        {
            let mut prov = TpmProvisioningManager::new(harness.connect_client(), prov_dir.path());
            let _ = prov.execute(false, false, None).unwrap();
        }

        let client = harness.connect_client();
        let counter = TpmMonotonicCounter::new(client, TpmCounterConfig::default());

        let catalog_dir = tempfile::tempdir().unwrap();
        let mgr = CatalogManager::open(catalog_dir.path()).unwrap();

        // Catalog claims version 1, counter 9999 (far desynced from TPM counter = 1)
        let v_desync =
            AssessmentCatalog::new(1, 9999, serde_json::json!({"release": "desynced"})).unwrap();
        mgr.initialize_new(&v_desync).unwrap();

        // Recovery must fail closed with CatalogDesync!
        let res = mgr.recover(&counter);
        assert!(matches!(res, Err(ProtocolError::CatalogDesync(_))));
    }
}
