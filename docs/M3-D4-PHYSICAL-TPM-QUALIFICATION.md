# OpenAudit M3 Dimension 4: Physical TPM 2.0 Hardware Qualification Procedure

**Specification Reference:** D4 Architecture Specification v1.24 §7.1, §8, §11.1  
**Qualification Status:** **`BLOCKED (Awaiting Bare-Metal Linux Physical TPM 2.0 Hardware)`**  
**Evidentiary Integrity Notice:** In conformance with evidentiary governance mandates, OpenAudit explicitly separates software TPM execution (`swtpm 0.10.2_1`) from physical silicon qualification. Software emulation must never be labeled or represented as physical hardware qualification.

---

## 1. Scope & Objective

The physical TPM qualification verifies that OpenAudit's Part 3 TPM 2.0 client, monotonic NV counter implementation (`0x01800001`), policy secret session authorization, and four-state agent provisioning lifecycle execute reliably against genuine discrete (dTPM) or firmware (fTPM) physical silicon under bare-metal Linux kernel timing and bus characteristics.

---

## 2. Hardware & Firmware Prerequisites

To execute physical qualification, the target system must satisfy:
1. **Physical Motherboard Silicon:** TCG 2.0 compliant discrete TPM (e.g., Infineon SLB9670/SLB9672, Nuvoton NPCT750, STMicroelectronics ST33) or AMD fTPM / Intel PTT.
2. **UEFI Firmware Configuration:**
   - Security Device Support: `Enabled`
   - TPM 2.0 Interface: `CRB` (Command Response Buffer) or `TIS` (TPM Interface Specification)
   - SHA-256 PCR bank: `Enabled`
3. **Linux Kernel & Modules:**
   - Linux kernel version $\ge 5.15$
   - Drivers loaded: `tpm`, `tpm_tis` (or `tpm_crb`), `tpm_tis_core`
   - In-kernel resource manager exposed at `/dev/tpmrm0` (major/minor character device `10:224`)
4. **Permissions & Udev Rules:**
   - Installed `/etc/udev/rules.d/99-openaudit-tpm.rules`
   - User executing qualification belongs to group `openaudit` with mode `0660` on `/dev/tpmrm0`.

---

## 3. Step-by-Step Execution Procedure

1. **Verify Device Node and Permissions:**
   ```bash
   ls -la /dev/tpmrm0 /dev/tpm0
   # Expected output:
   # crw-rw---- 1 root openaudit 10, 224 ... /dev/tpmrm0
   ```

2. **Execute Qualification Script:**
   ```bash
   ./scripts/qualify_physical_tpm.sh
   ```

3. **Verify Script Invariants:**
   - Confirms Linux OS (`uname -s` == `Linux`).
   - Verifies character device type (`S_IFCHR`).
   - Executes `openaudit-agent provision --tpm /dev/tpmrm0 --state-dir <DIR>`.
   - Validates baseline counter allocation at NV Index `0x01800001` with `TPMA_NV` attributes `0x02040018`.
   - Validates that `tpm-auth.secret` is created with strict POSIX permissions `0600`.
   - Confirms deterministic machine ID generation.

---

## 4. Current Status: `BLOCKED`

- **Development Platform:** macOS Darwin 24.3.0 (Apple Silicon ARM64).
- **Emulation Evidence:** Fully verified (204+ workspace tests passing against live `swtpm 0.10.2_1` daemons).
- **Physical Hardware Gating:** Bare-metal Linux host with physical TPM 2.0 character device `/dev/tpmrm0` is required for physical silicon ratification.
- **Disposition:** Marked as **`BLOCKED`** until physical hardware bench testing is conducted in staging.

