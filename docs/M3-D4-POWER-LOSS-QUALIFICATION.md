# OpenAudit M3 Dimension 4: Physical Power-Loss Qualification Procedure

**Specification Reference:** D4 Architecture Specification v1.24 §6.1, §6.2, §11.1  
**Qualification Status:** **`BLOCKED (Awaiting Hardware Power-Cut Laboratory Testbench)`**  
**Evidentiary Integrity Notice:** Simulated crash recovery, process interruptions, and uncommitted journal rollbacks (CB-01 through CB-13) are fully proven in software integration tests. However, in accordance with rigorous evidentiary standards, qualification under raw non-volatile hardware storage controller power cuts must remain designated as `BLOCKED` until tested on physical hardware.

---

## 1. Scope & Objective

The physical power-loss qualification assesses the durability and atomic recovery of OpenAudit's persistence layers:
1. **Catalog Durability Engine:** 6-stage crash-safe update transaction, parent directory `fsync` barriers, and CB-01 through CB-13 state recovery matrix.
2. **SQLite WAL Authority & Replay Databases:** Write-Ahead Logging (`PRAGMA journal_mode = WAL`), synchronous disk flush (`PRAGMA synchronous = FULL`), and check-and-consume write transactions under sudden power interruption.

---

## 2. Testbench Architecture

Physical qualification requires:
1. **Target Hardware:** Dedicated bare-metal x86_64 or ARM64 Linux server with NVMe or SATA SSD storage.
2. **Power Delivery Interrupter:** Programmable PDU (Power Distribution Unit) or solid-state relay capable of abruptly cutting AC mains or DC drive power under sub-millisecond software control.
3. **Automated Stress Loop:** Script `./scripts/qualify_power_loss.sh` generating high-concurrency catalog updates and enrollment/retrieval transactions, while an external harness commands random power cuts during active disk I/O.
4. **Post-Reboot Verification:**
   - Mount filesystem and run `fsck`.
   - Execute `openaudit-server authority recover-catalog --data-dir <DIR>`.
   - Confirm active catalog version is strictly monotonic and matches the highest valid committed counter.
   - Run SQLite integrity check: `PRAGMA integrity_check` on `authority.db` and `replay.db`.

---

## 3. Existing Software Durability Evidence

While physical power cut qualification is gated on testbench hardware, the underlying software durability architecture is proven through automated tests:
- **`catalog_resilience_integration` (13/13 passing):** Validates deterministic recovery across all CB-01..13 failure modes, including broken symlinks, partial writes, corrupted candidate metadata, and process crashes midway through promotion.
- **`SqliteReplayStore` & `SqliteAuthorityStore` Integration:** Tests verify `PRAGMA synchronous = FULL`, `PRAGMA journal_mode = WAL`, and rollback of uncommitted token consumption upon simulated worker process termination.

---

## 4. Current Status: `BLOCKED`

- **Disposition:** Designated as **`BLOCKED`** pending availability of laboratory power-switch testbench instrumentation.
- **Safety Standard:** No unverified claims of physical power cut qualification are asserted.

