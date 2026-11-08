//! # OpenAudit CLI
//!
//! Command-line interface for OpenAudit, enabling operators to run direct local
//! host posture audits, inspect platform capabilities, and generate audit reports.

use std::env;
use std::fmt::Write as _;
use std::process::ExitCode;

use openaudit_core::{OrganizationId, Severity};
use openaudit_engine::{
    default_platform_backend, AuditEngine, AuditProfile, AuditReport, CheckExecutionStatus,
};

/// CLI process exit codes according to OpenAudit specification.
pub mod exit_codes {
    use std::process::ExitCode;

    /// Audit execution completed successfully and no findings exceed policy thresholds.
    pub const SUCCESS: ExitCode = ExitCode::SUCCESS;
    /// Operational error, platform incompatibility, or command-line syntax failure.
    pub const FAILURE: ExitCode = ExitCode::FAILURE;
    /// Policy failure: security findings detected at or above the failure threshold.
    #[must_use]
    pub fn findings_detected() -> ExitCode {
        ExitCode::from(2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Html,
}

#[derive(Debug, Clone)]
pub struct CliConfig {
    pub format: OutputFormat,
    pub min_severity: Severity,
    pub profile: AuditProfile,
    pub fail_on: Option<Severity>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Human,
            min_severity: Severity::Info,
            profile: AuditProfile::Baseline,
            fail_on: None,
        }
    }
}

fn print_help() {
    println!(
        "OpenAudit CLI v{}\n\n\
        Usage: openaudit-cli <COMMAND> [OPTIONS]\n\n\
        Commands:\n  \
          scan                         Run a security audit against the local host\n  \
          audit local                  Run local host audit (backward compatible with M2)\n  \
          system info                  Display detected platform metadata and capabilities\n  \
          rules list                   List available security audit rules\n  \
          report                       Generate or export audit reports (human, json, html)\n  \
          version                      Print version information\n  \
          help                         Print this help message\n\n\
        Options:\n  \
          --profile <baseline|full|hardened>  Audit profile (default: baseline)\n  \
          --format <human|json|html>          Output format (default: human)\n  \
          --min-severity <level>              Filter findings by minimum severity (info..critical)\n  \
          --fail-on <level>                   Exit with code 2 if findings >= level are found\n  \
          --strict                            Equivalent to --fail-on high\n",
        openaudit_core::version()
    );
}

fn print_version() {
    println!("OpenAudit CLI v{}", openaudit_core::version());
}

fn run_scan(config: &CliConfig) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let org_id = OrganizationId::from_seed(b"openaudit:local:default-org");
    let engine = AuditEngine::default();
    let report = engine.run_audit_with_profile(org_id, config.profile)?;

    match config.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Human => {
            render_human_report(&report, config.min_severity);
        }
        OutputFormat::Html => {
            println!("{}", render_html_report(&report));
        }
    }

    if let Some(threshold) = config.fail_on {
        let has_violations = report
            .findings
            .iter()
            .any(|item| item.finding.severity >= threshold);
        if has_violations {
            return Ok(exit_codes::findings_detected());
        }
    }

    Ok(exit_codes::SUCCESS)
}

fn run_system_info(format: OutputFormat) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let backend = default_platform_backend();
    let info = backend.info();

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(info)?);
        }
        OutputFormat::Human | OutputFormat::Html => {
            println!("OpenAudit Host Platform Diagnostics");
            println!("--------------------------------------------------");
            println!("Operating System:  {}", info.family);
            println!("Distribution:      {}", info.distribution);
            println!("Version:           {}", info.version);
            println!("Architecture:      {}", info.architecture);
            println!("Kernel Release:    {}", info.kernel_release);
            println!("Hostname:          {}", info.hostname);
            println!("Display Name:      {}", info.pretty_name);
            println!(
                "Machine ID:        {}",
                info.machine_id.as_deref().unwrap_or("none")
            );
            println!("Supported Target:  {}", backend.is_supported());
            println!("Platform Capabilities ({}):", info.capabilities.len());
            for cap in &info.capabilities {
                println!("  [+] {cap}");
            }
        }
    }

    Ok(exit_codes::SUCCESS)
}

fn run_rules_list(format: OutputFormat) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let engine = AuditEngine::default();
    let rules = engine.rules();

    match format {
        OutputFormat::Json => {
            let records: Vec<_> = rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id(),
                        "title": r.title(),
                        "severity": r.severity(),
                        "privilege": r.required_privilege(),
                        "profile": r.profile(),
                        "target_platforms": r.target_platforms(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        OutputFormat::Human | OutputFormat::Html => {
            println!(
                "OpenAudit Available Security Rules (Total: {})",
                rules.len()
            );
            println!(
                "--------------------------------------------------------------------------------"
            );
            for r in rules {
                println!("{:<36} {:<10} {:?}", r.id(), r.severity(), r.profile());
                println!("  Title:       {}", r.title());
                println!("  Privilege:   {:?}", r.required_privilege());
                println!("  Platforms:   {:?}", r.target_platforms());
                println!();
            }
        }
    }

    Ok(exit_codes::SUCCESS)
}

#[allow(clippy::too_many_lines)]
fn render_human_report(report: &AuditReport, min_severity: Severity) {
    let host_label = report.platform_info.as_ref().map_or_else(
        || {
            report
                .os_info
                .as_ref()
                .map_or("localhost", |os| os.pretty_name.as_str())
        },
        |p| p.pretty_name.as_str(),
    );

    let arch = report.platform_info.as_ref().map_or_else(
        || {
            report
                .os_info
                .as_ref()
                .map_or("unknown", |os| os.architecture.as_str())
        },
        |p| p.architecture.as_str(),
    );

    let kernel = report.platform_info.as_ref().map_or_else(
        || {
            report
                .os_info
                .as_ref()
                .map_or("unknown", |os| os.kernel_release.as_str())
        },
        |p| p.kernel_release.as_str(),
    );

    println!(
        "OpenAudit Host Security Audit v{}",
        openaudit_core::version()
    );
    println!("Host: {host_label} ({kernel} {arch})");
    println!("Execution Privilege: {:?}", report.current_privilege);
    println!();

    let filtered_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|item| item.finding.severity >= min_severity)
        .collect();

    if filtered_findings.is_empty() {
        println!("[+] No security findings detected meeting severity threshold >= {min_severity}.");
    } else {
        println!(
            "[!] {} Security Findings Detected ({} Critical, {} High, {} Medium, {} Low, {} Info)",
            filtered_findings.len(),
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
            report.summary.info,
        );
        println!();

        for item in &filtered_findings {
            let finding = &item.finding;
            let severity_label = match finding.severity {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH    ",
                Severity::Medium => "MEDIUM  ",
                Severity::Low => "LOW     ",
                Severity::Info => "INFO    ",
            };

            println!("{severity_label}  {}", finding.rule_id);
            println!("  Target:      {}", item.target);
            println!("  Title:       {}", finding.title);
            println!("  Description: {}", finding.description);
            println!("  Remediation: {}", finding.remediation);

            let evidence_preview = item.evidence.payload.data().to_string();
            let truncated_evidence = if evidence_preview.len() > 120 {
                format!("{}...", &evidence_preview[..117])
            } else {
                evidence_preview
            };
            println!("  Evidence:    {truncated_evidence}");
            println!();
        }
    }

    if !report.check_statuses.is_empty() {
        let unsupported_count = report
            .check_statuses
            .iter()
            .filter(|s| {
                matches!(
                    s.status,
                    CheckExecutionStatus::UnsupportedPlatform { .. }
                        | CheckExecutionStatus::UnsupportedDistribution { .. }
                )
            })
            .count();

        if unsupported_count > 0 {
            println!(
                "Note: {unsupported_count} checks were skipped due to platform/distribution boundaries."
            );
        }
    }

    println!("--------------------------------------------------------------------------------");
    println!(
        "Scan Summary: {} Critical, {} High, {} Medium, {} Low, {} Info | Total: {}",
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info,
        report.summary.total(),
    );
    println!(
        "Execution Time: {}ms | Status: Completed",
        report.duration_ms
    );
}

#[allow(clippy::too_many_lines)]
fn render_html_report(report: &AuditReport) -> String {
    let title = format!("OpenAudit Report - {}", report.asset.name);
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    let _ = writeln!(html, "<title>{title}</title>");
    html.push_str("<style>\n\
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', Helvetica, Arial, sans-serif; background: #09090b; color: #f4f4f5; margin: 0; padding: 24px; line-height: 1.5; }\n\
        .container { max-width: 960px; margin: 0 auto; }\n\
        header { border-bottom: 1px solid #27272a; padding-bottom: 16px; margin-bottom: 24px; }\n\
        h1 { font-size: 20px; font-weight: 600; margin: 0 0 8px 0; color: #fafafa; }\n\
        .meta { color: #a1a1aa; font-size: 13px; }\n\
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 24px; }\n\
        .card { background: #18181b; border: 1px solid #27272a; border-radius: 6px; padding: 12px; }\n\
        .card-num { font-size: 20px; font-weight: 600; font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-variant-numeric: tabular-nums; }\n\
        .card-label { font-size: 11px; font-weight: 700; color: #a1a1aa; text-transform: uppercase; letter-spacing: 0.05em; }\n\
        .crit { color: #ef4444; } .high { color: #f97316; } .med { color: #eab308; } .low { color: #3b82f6; } .info { color: #71717a; }\n\
        .finding { background: #18181b; border: 1px solid #27272a; border-radius: 6px; padding: 16px; margin-bottom: 12px; }\n\
        .finding-title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }\n\
        .finding-desc { font-size: 13px; color: #d4d4d8; margin-bottom: 8px; }\n\
        .finding-rem { font-size: 12px; color: #10b981; background: #064e3b22; padding: 8px; border-radius: 4px; border: 1px solid #05966944; }\n\
        pre { background: #09090b; border: 1px solid #27272a; border-radius: 4px; padding: 8px; font-size: 11px; font-family: ui-monospace, 'SF Mono', monospace; overflow-x: auto; color: #a1a1aa; }\n\
    </style>\n</head>\n<body>\n<div class=\"container\">\n");

    html.push_str("<header>\n");
    let _ = writeln!(html, "<h1>{}</h1>", report.asset.name);
    let _ = writeln!(
        html,
        "<div class=\"meta\">Host: {} | Duration: {}ms | Privilege: {:?}</div>",
        report.asset.target_address, report.duration_ms, report.current_privilege
    );
    html.push_str("</header>\n");

    html.push_str("<div class=\"summary\">\n");
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-num crit\">{}</div><div class=\"card-label\">Critical</div></div>", report.summary.critical);
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-num high\">{}</div><div class=\"card-label\">High</div></div>", report.summary.high);
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-num med\">{}</div><div class=\"card-label\">Medium</div></div>", report.summary.medium);
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-num low\">{}</div><div class=\"card-label\">Low</div></div>", report.summary.low);
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-num info\">{}</div><div class=\"card-label\">Info</div></div>", report.summary.info);
    html.push_str("</div>\n");

    html.push_str("<h2>Findings</h2>\n");
    if report.findings.is_empty() {
        html.push_str("<p class=\"meta\">No security violations detected.</p>\n");
    } else {
        for item in &report.findings {
            let sev_class = match item.finding.severity {
                Severity::Critical => "crit",
                Severity::High => "high",
                Severity::Medium => "med",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            let _ = writeln!(
                html,
                "<div class=\"finding\">\n\
                <div class=\"finding-title\"><span class=\"{}\">[{:?}]</span> {} - {}</div>\n\
                <div class=\"finding-desc\">{}</div>\n\
                <div class=\"finding-rem\"><strong>Remediation:</strong> {}</div>\n\
                <pre>Target: {}\nEvidence: {}</pre>\n\
                </div>",
                sev_class,
                item.finding.severity,
                item.finding.rule_id,
                item.finding.title,
                item.finding.description,
                item.finding.remediation,
                item.target,
                item.evidence.payload.data()
            );
        }
    }

    html.push_str("</div>\n</body>\n</html>");
    html
}

#[allow(clippy::too_many_lines)]
fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return exit_codes::SUCCESS;
    }

    let mut config = CliConfig::default();
    let mut i = 1;
    let mut command = String::new();

    while i < args.len() {
        match args[i].as_str() {
            "help" | "--help" | "-h" => {
                print_help();
                return exit_codes::SUCCESS;
            }
            "version" | "--version" | "-v" => {
                print_version();
                return exit_codes::SUCCESS;
            }
            "scan" => {
                command = "scan".into();
                if i + 1 < args.len() && args[i + 1] == "local" {
                    i += 1;
                }
            }
            "audit" => {
                if i + 1 < args.len() && args[i + 1] == "local" {
                    command = "audit_local".into();
                    i += 1;
                } else {
                    eprintln!("Unknown audit subcommand. Expected: 'openaudit-cli audit local'");
                    return exit_codes::FAILURE;
                }
            }
            "system" => {
                if i + 1 < args.len() && args[i + 1] == "info" {
                    command = "system_info".into();
                    i += 1;
                } else {
                    eprintln!("Unknown system subcommand. Expected: 'openaudit-cli system info'");
                    return exit_codes::FAILURE;
                }
            }
            "rules" => {
                if i + 1 < args.len() && args[i + 1] == "list" {
                    command = "rules_list".into();
                    i += 1;
                } else {
                    eprintln!("Unknown rules subcommand. Expected: 'openaudit-cli rules list'");
                    return exit_codes::FAILURE;
                }
            }
            "report" => {
                command = "report".into();
            }
            "--profile" => {
                if i + 1 < args.len() {
                    match args[i + 1].to_lowercase().as_str() {
                        "baseline" => config.profile = AuditProfile::Baseline,
                        "full" => config.profile = AuditProfile::Full,
                        "hardened" => config.profile = AuditProfile::Hardened,
                        other => {
                            eprintln!(
                                "Unknown audit profile '{other}'. Supported: baseline, full, hardened"
                            );
                            return exit_codes::FAILURE;
                        }
                    }
                    i += 1;
                }
            }
            "--format" => {
                if i + 1 < args.len() {
                    match args[i + 1].to_lowercase().as_str() {
                        "json" => config.format = OutputFormat::Json,
                        "human" => config.format = OutputFormat::Human,
                        "html" => config.format = OutputFormat::Html,
                        other => {
                            eprintln!("Unknown format '{other}'. Supported: human, json, html");
                            return exit_codes::FAILURE;
                        }
                    }
                    i += 1;
                }
            }
            "--min-severity" => {
                if i + 1 < args.len() {
                    if let Ok(sev) = args[i + 1].parse::<Severity>() {
                        config.min_severity = sev;
                    } else {
                        eprintln!(
                            "Unknown severity '{}'. Expected: info, low, medium, high, critical",
                            args[i + 1]
                        );
                        return exit_codes::FAILURE;
                    }
                    i += 1;
                }
            }
            "--fail-on" => {
                if i + 1 < args.len() {
                    if let Ok(sev) = args[i + 1].parse::<Severity>() {
                        config.fail_on = Some(sev);
                    } else {
                        eprintln!(
                            "Unknown severity '{}'. Expected: info, low, medium, high, critical",
                            args[i + 1]
                        );
                        return exit_codes::FAILURE;
                    }
                    i += 1;
                }
            }
            "--strict" => {
                config.fail_on = Some(Severity::High);
            }
            other => {
                eprintln!("Unknown argument '{other}'. Run 'openaudit-cli --help' for usage.");
                return exit_codes::FAILURE;
            }
        }
        i += 1;
    }

    match command.as_str() {
        "scan" | "audit_local" => match run_scan(&config) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("Audit failed: {err}");
                exit_codes::FAILURE
            }
        },
        "system_info" => match run_system_info(config.format) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("System diagnostics failed: {err}");
                exit_codes::FAILURE
            }
        },
        "rules_list" => match run_rules_list(config.format) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("Rule listing failed: {err}");
                exit_codes::FAILURE
            }
        },
        "report" => match run_scan(&config) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("Report generation failed: {err}");
                exit_codes::FAILURE
            }
        },
        _ => {
            print_help();
            exit_codes::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_entry_point() {
        assert_ne!(openaudit_core::version(), "");
    }

    #[test]
    fn test_default_cli_config() {
        let config = CliConfig::default();
        assert_eq!(config.format, OutputFormat::Human);
        assert_eq!(config.min_severity, Severity::Info);
        assert_eq!(config.profile, AuditProfile::Baseline);
        assert_eq!(config.fail_on, None);
    }

    #[test]
    fn test_exit_codes_constants() {
        assert_eq!(exit_codes::SUCCESS, ExitCode::SUCCESS);
        assert_eq!(exit_codes::FAILURE, ExitCode::FAILURE);
        assert_eq!(exit_codes::findings_detected(), ExitCode::from(2));
    }

    #[test]
    fn test_render_html_report() {
        let org_id = OrganizationId::new();
        let asset = openaudit_core::Asset::new(
            org_id,
            "Ubuntu Test",
            openaudit_core::AssetType::LinuxHost,
            "127.0.0.1",
        )
        .unwrap();
        let report = AuditReport {
            asset,
            os_info: None,
            platform_info: None,
            current_privilege: openaudit_engine::PrivilegeLevel::Unprivileged,
            findings: Vec::new(),
            check_statuses: Vec::new(),
            summary: openaudit_core::ScanSummary::default(),
            duration_ms: 42,
        };
        let html = render_html_report(&report);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<title>OpenAudit Report - Ubuntu Test</title>"));
        assert!(html.contains("Critical"));
    }
}
