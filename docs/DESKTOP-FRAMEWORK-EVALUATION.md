# OpenAudit Desktop Architecture: Desktop GUI Framework Evaluation

**Document Version:** 1.0.0  
**Milestone:** M3.6 Desktop Foundation  
**Target Platform:** macOS (Apple Silicon aarch64, Intel x86_64), Linux, Windows

---

## 1. Executive Summary & Architectural Objectives

Milestone M3.6 begins the desktop graphical user interface for OpenAudit. The core architectural mandates dictate:
1. **Shared Engine Integration:** The desktop application must directly call the existing, audited Rust engine (`openaudit-engine` and `openaudit-core`). No duplicate audit logic or simulated checks.
2. **Local-First & Offline Resilience:** Zero requirement for cloud logins, remote API accounts, or telemetry tracking.
3. **High-Density Aesthetic Standards:** Strict compliance with `mike-design-system` (Linear-inspired information architecture, Stripe visual clarity, Vercel design restraint, zero emojis, crisp monochrome stroke SVGs, tabular monospace metrics).
4. **Minimal Binary & Memory Overhead:** Avoid heavyweight Electron runtimes that bundle entire Chromium instances (150MB+ bundle size, 200MB+ idle RAM).
5. **Native OS Windowing & Accessibility:** Native macOS window controls, menu bars, dark/light theme awareness, and system security bounds.

---

## 2. Comparative Framework Evaluation

We evaluated the four primary architectural candidates for Rust desktop applications:

| Evaluation Dimension | Candidate A: Tauri v2 | Candidate B: Wry + Tao (Direct WebKit) | Candidate C: Electron | Candidate D: Pure Rust GUI (Iced / Slint) |
| :--- | :--- | :--- | :--- | :--- |
| **Rendering Engine** | OS Native WebView (WKWebView on macOS, WebView2 on Windows, WebKitGTK on Linux) | OS Native WebView (WKWebView on macOS, WebView2 on Windows, WebKitGTK on Linux) | Bundled Chromium instance | Custom wgpu / software rasterizer |
| **Binary Footprint** | ~12–18 MB | ~8–12 MB | ~150–250 MB | ~10–20 MB |
| **Idle Memory (RAM)** | ~30–50 MB | ~25–40 MB | ~180–300 MB | ~20–35 MB |
| **Rust Engine In-Process**| Direct in-process invocation | Direct in-process invocation | Multi-process Node FFI / C++ add-ons | Native in-process Rust |
| **UI Density & Styling** | 100% fidelity to `mike-design-system` (CSS variables, SVGs, responsive grids) | 100% fidelity to `mike-design-system` (CSS variables, SVGs, responsive grids) | High fidelity (CSS/DOM) | Low fidelity (Primitive widgets, difficult SVG/table rendering) |
| **Report Reusability** | Direct DOM reuse of self-contained HTML reports | Direct DOM reuse of self-contained HTML reports | Direct DOM reuse | Requires custom renderer for HTML reports |
| **Build System Complexity**| High (Tauri CLI, ACL capabilities, build hooks) | Minimal (Standard `cargo build`, pure Rust dependencies) | High (npm, node-gyp, webpack, electron-builder) | Low (Pure cargo) |

---

## 3. Trade-off Analysis of Tauri v2

Tauri v2 is the leading modern framework for native desktop apps with web frontends. However, its trade-offs must be evaluated with engineering rigor:

### Advantages of Tauri:
1. **OS-Native WebView Reusability:** Uses macOS's system-installed `WebKit.framework` (`WKWebView`), eliminating Chromium distribution baggage and inheriting OS security patches automatically.
2. **IPC Security Boundary:** Tauri v2 enforces strict permission capabilities (`capabilities/default.json`), limiting frontend exposure to privileged operating system calls.
3. **Application Packaging Ecosystem:** Built-in generators for `.app` bundles, `.dmg` installers, Windows `.msi`, and Linux `.deb`.

### Drawbacks & Complexities of Tauri:
1. **Build Complexity & Toolchain Overhead:** Tauri v2 introduces extensive build-time code generation (`tauri-build`), complex capability schemas, and a massive dependency graph (over 200 transitive crates).
2. **IPC Serialization Latency:** Standard Tauri `invoke` commands serialize Rust domain types across JSON boundaries twice for every interaction.
3. **Desktop Automation & Testing Constraints:** Automated test harnesses in CI frequently struggle with Tauri's background IPC event loops unless mock runners are injected.

---

## 4. Architectural Selection: Tauri-Aligned WebKit Architecture

To achieve the best balance of **enterprise UI fidelity, instant native compilation, direct in-process engine execution, and zero Electron bloat**, OpenAudit selects the **Tauri-aligned native WebKit architecture**:
- **Window Management & Event Loop:** Native macOS Cocoa application lifecycle and window management via `tao` (Tauri's official windowing system) and `wry` (Tauri's official WebKit engine).
- **In-Process Audit Execution:** When the user clicks **Run Audit**, the desktop process executes `openaudit_engine::AuditEngine::default().run_audit_with_profile(...)` synchronously or in an asynchronous background thread.
- **Direct IPC & State Synchronization:** Bidirectional JSON messaging between the native host and the UI.
- **Shared Frontend Design System:** The frontend is implemented as a lightweight, zero-dependency static application embedding `mike-design-system` design tokens, monochrome stroke SVGs, tabular monospace numbers, and instant light/dark theme toggle.

This architecture delivers a true native macOS application window with traffic light controls, smooth scrolling, real-time posture scanning, and direct HTML report inspection in under 15 MB.
