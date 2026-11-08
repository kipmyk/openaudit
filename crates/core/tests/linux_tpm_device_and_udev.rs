//! Comprehensive acceptance tests for Linux TPM 2.0 device node handling,
//! permission diagnostics, character device validation, and udev rules (Dimension 4, Phase F.3).

use std::fs;
use std::path::{Path, PathBuf};

use openaudit_core::protocol::error::ProtocolError;
use openaudit_core::protocol::tpm::{
    resolve_tpm_device_path, DeviceTransport, DEFAULT_LINUX_TPM_RM_PATH,
    FALLBACK_LINUX_TPM_RAW_PATH,
};

#[test]
fn test_default_device_path_resolution() {
    // 1. Explicit path is always preserved exactly
    let explicit = Path::new("/custom/tpm/device");
    assert_eq!(
        resolve_tpm_device_path(Some(explicit)),
        PathBuf::from("/custom/tpm/device")
    );

    // 2. Default path resolves to /dev/tpmrm0 when neither exists, or whichever exists
    let resolved = resolve_tpm_device_path(None);
    if Path::new(DEFAULT_LINUX_TPM_RM_PATH).exists() {
        assert_eq!(resolved, PathBuf::from(DEFAULT_LINUX_TPM_RM_PATH));
    } else if Path::new(FALLBACK_LINUX_TPM_RAW_PATH).exists() {
        assert_eq!(resolved, PathBuf::from(FALLBACK_LINUX_TPM_RAW_PATH));
    } else {
        assert_eq!(resolved, PathBuf::from(DEFAULT_LINUX_TPM_RM_PATH));
    }
}

#[test]
fn test_device_transport_enoent_diagnostic() {
    let nonexistent = Path::new("/tmp/openaudit_test_nonexistent_tpm_device_node_98765");
    let res = DeviceTransport::validate_device_node(nonexistent);

    assert!(res.is_err(), "nonexistent device node must fail validation");
    let err = match res {
        Err(ProtocolError::TpmError(msg)) => msg,
        other => panic!("expected ProtocolError::TpmError, got {other:?}"),
    };

    assert!(
        err.contains("TPM 2.0 device node not found"),
        "error must give diagnostic device not found message: {err}"
    );
    assert!(
        err.contains("tpm_tis") && err.contains("tpm_crb"),
        "error must mention Linux kernel drivers: {err}"
    );
}

#[test]
fn test_device_transport_rejects_regular_file() {
    let temp_dir = std::env::temp_dir().join(format!("oa_tpm_test_reg_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let regular_file = temp_dir.join("fake_tpm_node");
    fs::write(&regular_file, b"not a character device").expect("write regular file");

    let res = DeviceTransport::validate_device_node(&regular_file);

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);

    #[cfg(unix)]
    {
        assert!(res.is_err(), "regular file must be rejected as TPM device");
        let err = match res {
            Err(ProtocolError::TpmError(msg)) => msg,
            other => panic!("expected ProtocolError::TpmError, got {other:?}"),
        };
        assert!(
            err.contains("expected character device") && err.contains("non-character file type"),
            "error must explain non-character device rejection: {err}"
        );
    }
}

#[test]
fn test_device_transport_rejects_directory() {
    let temp_dir = std::env::temp_dir().join(format!("oa_tpm_test_dir_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let res = DeviceTransport::validate_device_node(&temp_dir);

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);

    #[cfg(unix)]
    {
        assert!(res.is_err(), "directory must be rejected as TPM device");
        let err = match res {
            Err(ProtocolError::TpmError(msg)) => msg,
            other => panic!("expected ProtocolError::TpmError, got {other:?}"),
        };
        assert!(
            err.contains("expected character device") && err.contains("non-character file type"),
            "error must explain directory rejection: {err}"
        );
    }
}

#[test]
fn test_udev_rules_syntax_and_security() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("must find repo root");
    let rules_path = repo_root.join("packaging/udev/99-openaudit-tpm.rules");

    assert!(
        rules_path.is_file(),
        "packaging/udev/99-openaudit-tpm.rules must exist at '{}'",
        rules_path.display()
    );

    let content = fs::read_to_string(&rules_path).expect("read udev rules");

    // 1. Must target in-kernel resource manager (tpmrm)
    assert!(
        content.contains("KERNEL==\"tpmrm[0-9]*\""),
        "udev rules must target in-kernel resource manager"
    );

    // 2. Must target raw character device (tpm)
    assert!(
        content.contains("KERNEL==\"tpm[0-9]*\""),
        "udev rules must target raw TPM character device"
    );

    // 3. Must enforce mode 0660
    assert!(
        content.contains("MODE=\"0660\""),
        "udev rules must enforce restrictive mode 0660"
    );

    // 4. SECURITY INVARIANT: Must strictly prohibit world-writable or overly permissive modes
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            assert!(
                !trimmed.contains("MODE=\"0666\""),
                "SECURITY VIOLATION: udev rules must not permit world-writable access 0666: '{trimmed}'"
            );
            assert!(
                !trimmed.contains("MODE=\"0664\""),
                "SECURITY VIOLATION: udev rules must not permit world-readable access 0664: '{trimmed}'"
            );
            assert!(
                !trimmed.contains("MODE=\"0777\""),
                "SECURITY VIOLATION: udev rules must not permit world-executable access 0777: '{trimmed}'"
            );
        }
    }

    // 5. Must designate group and tag
    assert!(
        content.contains("GROUP=\"openaudit\""),
        "udev rules must assign group openaudit"
    );
    assert!(
        content.contains("TAG+=\"openaudit\""),
        "udev rules must tag openaudit devices"
    );
}
