//! # OpenAudit Desktop
//!
//! Native desktop graphical user interface for OpenAudit, providing local-first
//! host posture evaluation, interactive findings inspection, and audit reporting.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)]
fn run_desktop_app() -> Result<ExitCode, Box<dyn std::error::Error>> {
    use std::fs;
    use std::process::Command;
    use tao::dpi::LogicalSize;
    use tao::event::{Event, StartCause, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    use openaudit_core::OrganizationId;
    use openaudit_engine::collector::{RealCommandRunner, RealFileSystem};
    use openaudit_engine::platform::detect_current_platform;
    use openaudit_engine::{AuditEngine, AuditProfile, AuditReport};

    #[derive(Debug)]
    enum AppEvent {
        Ipc(String),
    }

    println!("[*] Starting OpenAudit Native Desktop GUI...");

    let event_loop = EventLoopBuilder::<AppEvent>::with_user_event().build();
    let window = WindowBuilder::new()
        .with_title("OpenAudit Desktop - Host Security Posture")
        .with_inner_size(LogicalSize::new(1280.0, 820.0))
        .with_min_inner_size(LogicalSize::new(960.0, 640.0))
        .build(&event_loop)?;

    // HTML, CSS and JS asset injection
    let html_content = include_str!("ui.html");
    let css_content = include_str!("ui.css");
    let js_content = include_str!("ui.js");

    let page_content = html_content
        .replace(
            "<style>\n    /* Injected from ui.css */\n  </style>",
            &format!("<style>{css_content}</style>"),
        )
        .replace(
            "<script>\n    /* Injected from ui.js */\n  </script>",
            &format!("<script>{js_content}</script>"),
        );

    let has_js = page_content.contains("sendIpc");
    let has_css = page_content.contains("--bg-app");
    println!("[*] Injected CSS: {has_css}, Injected JS: {has_js}");

    let proxy = event_loop.create_proxy();

    let builder = WebViewBuilder::new()
        .with_devtools(true)
        .with_document_title_changed_handler(|title| {
            println!("[*] Document title changed: {title}");
        })
        .with_html(&page_content)
        .with_ipc_handler(move |req| {
            println!("[*] Incoming IPC message: {}", req.body());
            let _ = proxy.send_event(AppEvent::Ipc(req.body().clone()));
        });

    let webview = builder.build(&window)?;
    let worker_proxy = event_loop.create_proxy();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                println!("[+] OpenAudit native window initialized.");
            }
            Event::UserEvent(AppEvent::Ipc(body)) => {
                let parsed: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(_) => return,
                };

                let action = parsed["action"].as_str().unwrap_or("");
                println!("[*] Processing IPC action: {action}");

                match action {
                    "run_audit" => {
                        let profile_str = parsed["profile"].as_str().unwrap_or("baseline");
                        let profile = match profile_str {
                            "hardened" => AuditProfile::Hardened,
                            "full" => AuditProfile::Full,
                            _ => AuditProfile::Baseline,
                        };

                        let org_id = OrganizationId::from_seed(b"openaudit:desktop:local");
                        let engine = AuditEngine::default();
                        if let Ok(report) = engine.run_audit_with_profile(org_id, profile) {
                            if let Ok(json_str) = serde_json::to_string(&report) {
                                let _ = webview.evaluate_script(&format!(
                                    "window.onAuditComplete({json_str});"
                                ));
                            }
                        }
                    }
                    "get_system_info" => {
                        let backend = detect_current_platform(&RealFileSystem, &RealCommandRunner);
                        let info = backend.info();
                        let sys_info = serde_json::json!({
                            "pretty_name": info.pretty_name,
                            "os_family": format!("{:?}", info.family),
                            "arch": info.architecture,
                            "kernel": info.kernel_release,
                            "distribution": format!("{:?}", info.distribution),
                            "version": info.version.to_string(),
                        });
                        if let Ok(json_str) = serde_json::to_string(&sys_info) {
                            let _ = webview.evaluate_script(&format!(
                                "window.onSystemInfoLoaded({json_str});"
                            ));
                        }
                    }
                    "get_permissions" => {
                        let uid = Command::new("id").arg("-u").output().map_or_else(
                            |_| "501".into(),
                            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
                        );

                        let username = Command::new("id").arg("-un").output().map_or_else(
                            |_| "user".into(),
                            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
                        );

                        let sip_text = Command::new("csrutil").arg("status").output().map_or_else(
                            |_| "System Integrity Protection: enabled.".into(),
                            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
                        );

                        let is_sip_active = sip_text.to_lowercase().contains("enabled");

                        let fda_granted = fs::File::open(
                            "/Library/Application Support/com.apple.TCC/TCC.db",
                        )
                        .is_ok()
                            || fs::read_dir("/Library/Application Support/com.apple.TCC").is_ok();

                        let is_root = uid == "0";

                        let perms = serde_json::json!({
                            "uid": uid,
                            "username": username,
                            "privilege": if is_root { "Root" } else { "Unprivileged" },
                            "is_root": is_root,
                            "sip_raw": sip_text,
                            "sip_active": is_sip_active,
                            "full_disk_access": fda_granted,
                        });

                        if let Ok(json_str) = serde_json::to_string(&perms) {
                            let _ = webview.evaluate_script(&format!(
                                "window.onPermissionsLoaded({json_str});"
                            ));
                        }
                    }
                    "open_system_settings" => {
                        let pane = parsed["pane"].as_str().unwrap_or("security");
                        let target_url = match pane {
                            "fda" | "all_files" => {
                                "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
                            }
                            "firewall" => {
                                "x-apple.systempreferences:com.apple.preference.security?Firewall"
                            }
                            _ => "x-apple.systempreferences:com.apple.preference.security",
                        };
                        let _ = Command::new("open").arg(target_url).status();
                    }
                    "open_report_file" => {
                        let out_path = std::env::temp_dir().join("openaudit-report.html");
                        if let Ok(report) =
                            serde_json::from_value::<AuditReport>(parsed["report"].clone())
                        {
                            let html = render_html_report(&report);
                            let _ = fs::write(&out_path, html);
                        }
                        let _ = Command::new("open").arg(&out_path).status();
                    }
                    "get_rules" => {
                        let engine = AuditEngine::default();
                        let rules = engine.rules();
                        let records: Vec<_> = rules
                            .iter()
                            .map(|r| {
                                let platforms: Vec<String> = r
                                    .target_platforms()
                                    .iter()
                                    .map(|p| format!("{p:?}"))
                                    .collect();
                                serde_json::json!({
                                    "id": r.id(),
                                    "title": r.title(),
                                    "severity": format!("{:?}", r.severity()),
                                    "privilege": format!("{:?}", r.required_privilege()),
                                    "profile": format!("{:?}", r.profile()),
                                    "target_platforms": platforms,
                                })
                            })
                            .collect();
                        if let Ok(json_str) = serde_json::to_string(&records) {
                            let _ = webview.evaluate_script(&format!(
                                "window.onRulesLoaded({json_str});"
                            ));
                        }
                    }
                    "get_html_report" => {
                        if let Ok(report) =
                            serde_json::from_value::<AuditReport>(parsed["report"].clone())
                        {
                            let html = render_html_report(&report);
                            let escaped_html = serde_json::to_string(&html).unwrap_or_default();
                            let _ = webview.evaluate_script(&format!(
                                "window.onHtmlReportReady({escaped_html});"
                            ));
                        }
                    }
                    "export_html" => {
                        if let Ok(report) =
                            serde_json::from_value::<AuditReport>(parsed["report"].clone())
                        {
                            let html = render_html_report(&report);
                            let out_path = std::env::temp_dir().join("openaudit-report.html");
                            if fs::write(&out_path, html).is_ok() {
                                println!("[+] Report exported to: {}", out_path.display());
                                let display_path = out_path.display().to_string();
                                let _ = webview.evaluate_script(&format!(
                                    "window.onReportExported('{display_path}');"
                                ));
                            }
                        }
                    }
                    "clipboard_copy" => {
                        if let Some(text) = parsed["text"].as_str() {
                            use std::io::Write;
                            // Enforce fixed path to system binary and bounded input size
                            let pbcopy_path = if std::path::Path::new("/usr/bin/pbcopy").exists() {
                                "/usr/bin/pbcopy"
                            } else {
                                "pbcopy"
                            };
                            let bounded_text = if text.len() > 1024 * 1024 {
                                &text[..1024 * 1024]
                            } else {
                                text
                            };
                            if let Ok(mut child) = Command::new(pbcopy_path)
                                .stdin(std::process::Stdio::piped())
                                .spawn()
                            {
                                if let Some(mut stdin) = child.stdin.take() {
                                    let _ = stdin.write_all(bounded_text.as_bytes());
                                }
                                let _ = child.wait();
                            }
                        }
                    }
                    "clipboard_paste" => {
                        let pbpaste_path = if std::path::Path::new("/usr/bin/pbpaste").exists() {
                            "/usr/bin/pbpaste"
                        } else {
                            "pbpaste"
                        };
                        if let Ok(output) = Command::new(pbpaste_path).output() {
                            if output.status.success() {
                                // Strictly limit read buffer to prevent resource exhaustion
                                let max_bytes = 1024 * 1024;
                                let slice = if output.stdout.len() > max_bytes {
                                    &output.stdout[..max_bytes]
                                } else {
                                    &output.stdout[..]
                                };
                                let text = String::from_utf8_lossy(slice).to_string();
                                if let Ok(json_text) = serde_json::to_string(&text) {
                                    let _ = webview.evaluate_script(&format!(
                                        "window.onNativeClipboardPaste({json_text});"
                                    ));
                                }
                            }
                        }
                    }
                    "__eval_script" => {
                        if let Some(script) = parsed["script"].as_str() {
                            let _ = webview.evaluate_script(script);
                        }
                    }
                    "run_perimeter_assessment" => {
                        let target_str = parsed["target"].as_str().unwrap_or("127.0.0.1").to_string();
                        let ports_str = parsed["ports"]
                            .as_str()
                            .unwrap_or("80, 443, 8080, 8443, 22")
                            .to_string();
                        let allow_loopback = parsed["allow_loopback"].as_bool().unwrap_or(true);

                        let proxy = worker_proxy.clone();
                        std::thread::spawn(move || {
                            let mut ports = Vec::new();
                            for part in ports_str.split(',') {
                                let trimmed = part.trim();
                                if let Some((start, end)) = trimmed.split_once('-') {
                                    if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                                        for p in s..=e {
                                            ports.push(p);
                                        }
                                    }
                                } else if let Ok(p) = trimmed.parse::<u16>() {
                                    ports.push(p);
                                }
                            }
                            if ports.is_empty() {
                                ports = vec![80, 443, 8080, 8443, 22];
                            }
                            if ports.len() > 64 {
                                ports.truncate(64);
                            }

                            let scope = openaudit_network::scope::TargetScope {
                                allow_public: true,
                                allow_loopback,
                                allow_testnets: true,
                                ..Default::default()
                            };

                            let resolver = openaudit_network::resolver::SystemDnsResolver;
                            let config = openaudit_network::assessment::PerimeterAssessConfig::default();

                            let script = match openaudit_network::assessment::PerimeterAssessor::assess(
                                &target_str,
                                &ports,
                                &scope,
                                &resolver,
                                &config,
                                None,
                            ) {
                                Ok(report) => {
                                    let json_str = serde_json::to_string(&report).unwrap_or_default();
                                    format!("window.onPerimeterAssessmentCompleted({json_str});")
                                }
                                Err(e) => {
                                    let err_json = serde_json::json!({
                                        "error": e.to_string(),
                                        "target": target_str,
                                    });
                                    format!("window.onPerimeterAssessmentFailed({err_json});")
                                }
                            };

                            let _ = proxy.send_event(AppEvent::Ipc(serde_json::json!({
                                "action": "__eval_script",
                                "script": script
                            }).to_string()));
                        });
                    }
                    _ => {}
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                println!("[*] Window close requested, exiting desktop GUI.");
                *control_flow = ControlFlow::Exit;
            }
            _ => (),
        }
    });
}

#[allow(clippy::too_many_lines)]
fn render_html_report(report: &openaudit_engine::AuditReport) -> String {
    use std::fmt::Write;
    let mut html = String::with_capacity(16384);
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>OpenAudit Security Posture Assessment Report</title>\n<style>\n\
        :root {\n\
          --bg-canvas: #f8fafc;\n\
          --bg-surface: #ffffff;\n\
          --bg-subtle: #f1f5f9;\n\
          --border: #e2e8f0;\n\
          --border-strong: #cbd5e1;\n\
          --text-primary: #0f172a;\n\
          --text-secondary: #334155;\n\
          --text-muted: #64748b;\n\
          --text-faint: #94a3b8;\n\
          --accent-blue: #2563eb;\n\
          --accent-red: #dc2626;\n\
          --accent-red-bg: #fef2f2;\n\
          --accent-orange: #ea580c;\n\
          --accent-orange-bg: #fff7ed;\n\
          --accent-amber: #d97706;\n\
          --accent-amber-bg: #fffbeb;\n\
          --accent-green: #059669;\n\
          --accent-green-bg: #ecfdf5;\n\
          --term-bg: #0f172a;\n\
          --term-text: #f1f5f9;\n\
        }\n\
        @media (prefers-color-scheme: dark) {\n\
          :root {\n\
            --bg-canvas: #0b0f19;\n\
            --bg-surface: #1e293b;\n\
            --bg-subtle: #293548;\n\
            --border: #334155;\n\
            --border-strong: #475569;\n\
            --text-primary: #f8fafc;\n\
            --text-secondary: #cbd5e1;\n\
            --text-muted: #94a3b8;\n\
            --text-faint: #64748b;\n\
            --accent-blue: #3b82f6;\n\
            --accent-red: #ef4444;\n\
            --accent-red-bg: rgba(239, 68, 68, 0.12);\n\
            --accent-orange: #f97316;\n\
            --accent-orange-bg: rgba(249, 115, 22, 0.12);\n\
            --accent-amber: #f59e0b;\n\
            --accent-amber-bg: rgba(245, 158, 11, 0.12);\n\
            --accent-green: #10b981;\n\
            --accent-green-bg: rgba(16, 185, 129, 0.12);\n\
            --term-bg: #090d16;\n\
            --term-text: #e2e8f0;\n\
          }\n\
        }\n\
        * { box-sizing: border-box; margin: 0; padding: 0; }\n\
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', sans-serif; background: var(--bg-canvas); color: var(--text-primary); margin: 0; padding: 36px 20px; line-height: 1.5; -webkit-font-smoothing: antialiased; }\n\
        .report-wrapper { max-width: 960px; margin: 0 auto; background: var(--bg-surface); border: 1px solid var(--border); border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.03); overflow: hidden; }\n\
        .report-header { padding: 24px 28px; border-bottom: 1px solid var(--border); display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }\n\
        .brand-group { display: flex; align-items: center; gap: 12px; }\n\
        .brand-icon { width: 34px; height: 34px; background: var(--accent-blue); border-radius: 6px; display: flex; align-items: center; justify-content: center; color: #ffffff; flex-shrink: 0; }\n\
        .brand-title { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; color: var(--text-primary); }\n\
        .brand-subtitle { font-size: 12px; color: var(--text-muted); margin-top: 2px; }\n\
        .meta-strip { display: flex; gap: 8px; flex-wrap: wrap; }\n\
        .tech-pill { font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: 11px; font-variant-numeric: tabular-nums; background: var(--bg-subtle); border: 1px solid var(--border); padding: 3px 8px; border-radius: 4px; color: var(--text-secondary); }\n\
        .content-body { padding: 24px 28px; }\n\
        .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }\n\
        .kpi-card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; }\n\
        .kpi-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 4px; }\n\
        .kpi-value { font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; color: var(--text-primary); }\n\
        .kpi-value.green { color: var(--accent-green); }\n\
        .kpi-value.orange { color: var(--accent-orange); }\n\
        .kpi-value.red { color: var(--accent-red); }\n\
        .section-heading { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin: 24px 0 12px 0; display: flex; align-items: center; justify-content: space-between; }\n\
        .table-container { border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-bottom: 20px; }\n\
        .data-table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 12px; }\n\
        .data-table th { background: var(--bg-subtle); color: var(--text-muted); font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; padding: 8px 12px; border-bottom: 1px solid var(--border); text-align: left; }\n\
        .data-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); color: var(--text-secondary); }\n\
        .data-table tr:last-child td { border-bottom: none; }\n\
        .finding-card { border: 1px solid var(--border); border-radius: 6px; padding: 16px 18px; margin-bottom: 12px; background: var(--bg-surface); }\n\
        .finding-card.penalty-critical { border-left: 3px solid var(--accent-red); }\n\
        .finding-card.penalty-high { border-left: 3px solid var(--accent-orange); }\n\
        .finding-card.penalty-medium { border-left: 3px solid var(--accent-amber); }\n\
        .finding-card.penalty-low { border-left: 3px solid var(--accent-blue); }\n\
        .finding-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 8px; }\n\
        .finding-title { font-size: 14px; font-weight: 700; color: var(--text-primary); }\n\
        .badge { font-family: ui-monospace, 'SF Mono', monospace; font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 4px; text-transform: uppercase; border: 1px solid transparent; }\n\
        .badge-crit { background: var(--accent-red-bg); color: var(--accent-red); border-color: rgba(220, 38, 38, 0.2); }\n\
        .badge-high { background: var(--accent-orange-bg); color: var(--accent-orange); border-color: rgba(234, 88, 12, 0.2); }\n\
        .badge-med { background: var(--accent-amber-bg); color: var(--accent-amber); border-color: rgba(217, 119, 6, 0.2); }\n\
        .badge-low { background: var(--bg-subtle); color: var(--accent-blue); border-color: var(--border); }\n\
        .badge-pass { background: var(--accent-green-bg); color: var(--accent-green); border-color: rgba(5, 150, 105, 0.2); }\n\
        .finding-desc { font-size: 13px; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.5; }\n\
        .rem-box { background: var(--bg-subtle); border: 1px solid var(--border); border-left: 3px solid var(--accent-blue); color: var(--text-primary); border-radius: 4px; padding: 10px 12px; font-size: 12px; margin-bottom: 10px; line-height: 1.5; }\n\
        .cmd-block { background: var(--term-bg); color: var(--term-text); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; font-family: ui-monospace, 'SF Mono', monospace; font-size: 11px; overflow-x: auto; margin-bottom: 10px; line-height: 1.4; }\n\
        .evidence-window { border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }\n\
        .evidence-header { background: var(--bg-subtle); padding: 5px 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); font-family: ui-monospace, 'SF Mono', monospace; border-bottom: 1px solid var(--border); }\n\
        .evidence-pre { background: var(--term-bg); color: var(--term-text); padding: 10px 12px; font-family: ui-monospace, 'SF Mono', monospace; font-size: 11px; overflow-x: auto; white-space: pre-wrap; margin: 0; line-height: 1.4; }\n\
        .report-footer { padding: 16px 28px; background: var(--bg-subtle); border-top: 1px solid var(--border); font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between; align-items: center; }\n\
    </style>\n</head>\n<body>\n<div class=\"report-wrapper\">\n\
    <header class=\"report-header\">\n\
      <div class=\"brand-group\">\n\
        <div class=\"brand-icon\"><svg viewBox=\"0 0 24 24\" width=\"18\" height=\"18\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/></svg></div>\n\
        <div><div class=\"brand-title\">OpenAudit Host Security Assessment</div><div class=\"brand-subtitle\">In-Process Native Evaluation Report</div></div>\n\
      </div>\n\
      <div class=\"meta-strip\">");

    let _ = writeln!(
        html,
        "<span class=\"tech-pill\">Target: {}</span>\n<span class=\"tech-pill\">Assessment: {}</span>\n<span class=\"tech-pill\">Privilege: {:?}</span>\n<span class=\"tech-pill\">Duration: {}ms</span></div></header>",
        report.asset.target_address, report.assessment_type.display_name(), report.current_privilege, report.duration_ms
    );

    html.push_str("<div class=\"content-body\">\n");

    let crit_high = report.summary.critical + report.summary.high;
    let crit_class = if report.summary.critical > 0 {
        "red"
    } else if report.summary.high > 0 {
        "orange"
    } else {
        "green"
    };

    html.push_str("<div class=\"kpi-grid\">\n");
    let _ = writeln!(
        html,
        "<div class=\"kpi-card\"><div class=\"kpi-label\">Total Findings</div><div class=\"kpi-value\">{}</div></div>",
        report.findings.len()
    );
    let _ = writeln!(
        html,
        "<div class=\"kpi-card\"><div class=\"kpi-label\">Critical &amp; High</div><div class=\"kpi-value {crit_class}\">{crit_high}</div></div>"
    );
    let _ = writeln!(
        html,
        "<div class=\"kpi-card\"><div class=\"kpi-label\">Evaluation Status</div><div class=\"kpi-value\" style=\"font-size: 15px; margin-top: 3px;\">{}</div></div>",
        if report.findings.is_empty() { "CLEAN PASS" } else { "ACTION NEEDED" }
    );
    let _ = writeln!(
        html,
        "<div class=\"kpi-card\"><div class=\"kpi-label\">Execution Latency</div><div class=\"kpi-value\">{}ms</div></div>",
        report.duration_ms
    );
    html.push_str("</div>\n");

    html.push_str(
        "<div class=\"section-heading\"><span>Host Environment Diagnostics</span></div>\n",
    );
    html.push_str("<div class=\"table-container\"><table class=\"data-table\"><thead><tr><th>Diagnostic Key</th><th>Evaluated System State</th></tr></thead><tbody>\n");
    let _ = writeln!(
        html,
        "<tr><td>Target Asset Identifier</td><td><code class=\"tech-pill\">{}</code></td></tr>",
        report.asset.name
    );
    let _ = writeln!(
        html,
        "<tr><td>Host Platform &amp; Address</td><td><code class=\"tech-pill\">{}</code></td></tr>",
        report.asset.target_address
    );
    let _ = writeln!(
        html,
        "<tr><td>Execution Token Privilege</td><td><code class=\"tech-pill\">{:?}</code></td></tr>",
        report.current_privilege
    );
    let _ = writeln!(
        html,
        "<tr><td>Evaluated Security Rules</td><td><code class=\"tech-pill\">43 Built-in Rules (11 macOS Native)</code></td></tr>",
    );
    html.push_str("</tbody></table></div>\n");

    html.push_str("<div class=\"section-heading\"><span>Security Findings &amp; Forensic Guidance</span></div>\n");

    if report.findings.is_empty() {
        html.push_str("<div class=\"finding-card\" style=\"border-left: 3px solid var(--accent-green);\"><div class=\"finding-top\"><span class=\"finding-title\">No Security Policy Violations Detected</span><span class=\"badge badge-pass\">CLEAN PASS</span></div><div class=\"finding-desc\">All evaluated security controls satisfy baseline host hardening requirements. No actionable vulnerabilities were detected.</div></div>\n");
    } else {
        for item in &report.findings {
            let f = &item.finding;
            let (penalty, badge) = match f.severity {
                openaudit_core::Severity::Critical => ("penalty-critical", "badge-crit"),
                openaudit_core::Severity::High => ("penalty-high", "badge-high"),
                openaudit_core::Severity::Medium => ("penalty-medium", "badge-med"),
                openaudit_core::Severity::Low | openaudit_core::Severity::Info => {
                    ("penalty-low", "badge-low")
                }
            };
            let _ = writeln!(html, "<div class=\"finding-card {penalty}\">");
            let _ = writeln!(
                html,
                "<div class=\"finding-top\"><span class=\"finding-title\">{}</span><span class=\"badge {badge}\">{:?}</span></div>",
                f.title, f.severity
            );
            let _ = writeln!(
                html,
                "<div style=\"font-size:11px; color: var(--text-muted); margin-bottom:10px;\">Target: <code class=\"tech-pill\">{}</code> &bull; Rule: <code class=\"tech-pill\">{}</code></div>",
                item.target, f.rule_id
            );
            let _ = writeln!(html, "<div class=\"finding-desc\">{}</div>", f.description);
            let _ = writeln!(
                html,
                "<div class=\"rem-box\"><strong>Prescribed Remediation:</strong> {}</div>",
                f.remediation
            );

            let rem_cmd = match f.rule_id.as_str() {
                "macos.firewall.disabled" => {
                    "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
                }
                "macos.remote.login-enabled" => "sudo systemsetup -setremotelogin off",
                _ => "openaudit-cli remediate --rule <rule-id>",
            };
            let _ = writeln!(html, "<div class=\"cmd-block\">$ {rem_cmd}</div>");

            let evidence_str = item.evidence.payload.data().to_string();
            let _ = writeln!(
                html,
                "<div class=\"evidence-window\"><div class=\"evidence-header\">Captured Forensic Telemetry (Raw Payload)</div><pre class=\"evidence-pre\">{evidence_str}</pre></div></div>"
            );
        }
    }

    html.push_str("</div>\n<div class=\"report-footer\"><span>OpenAudit Security Posture &bull; Enterprise Standard</span><span>Engine v0.1.0-alpha.0</span></div>\n</div>\n</body>\n</html>\n");
    html
}

fn main() -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        match run_desktop_app() {
            Ok(code) => code,
            Err(err) => {
                eprintln!("[!] Desktop application error: {err}");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("[!] OpenAudit Desktop GUI is currently validated natively on macOS.");
        eprintln!("[*] Use openaudit-cli for Linux and Windows terminal execution.");
        ExitCode::FAILURE
    }
}
