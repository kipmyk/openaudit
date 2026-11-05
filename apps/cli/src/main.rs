//! # OpenAudit CLI
//!
//! Command-line interface for OpenAudit, enabling operators to run direct local
//! host posture audits and interact with remote OpenAudit servers.

use std::env;
use std::process::ExitCode;

use openaudit_core::{OrganizationId, Severity};
use openaudit_engine::{AuditEngine, AuditReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone)]
struct CliConfig {
    format: OutputFormat,
    min_severity: Severity,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Human,
            min_severity: Severity::Info,
        }
    }
}

fn print_help() {
    println!(
        "OpenAudit CLI v{}\n\n\
        Usage: openaudit-cli <COMMAND> [OPTIONS]\n\n\
        Commands:\n  \
          audit local                  Run a strictly read-only local host security audit\n  \
          version                      Print version information\n  \
          help                         Print this help message\n\n\
        Options:\n  \
          --format <human|json>        Output format (default: human)\n  \
          --min-severity <level>       Filter findings by minimum severity (info, low, medium, high, critical)\n",
        openaudit_core::version()
    );
}

fn print_version() {
    println!("OpenAudit CLI v{}", openaudit_core::version());
}

fn run_audit(config: &CliConfig) -> Result<(), Box<dyn std::error::Error>> {
    let org_id = OrganizationId::from_seed(b"openaudit:local:default-org");
    let engine = AuditEngine::default();
    let report = engine.run_local_audit(org_id)?;

    match config.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Human => {
            render_human_report(&report, config.min_severity);
        }
    }

    Ok(())
}

fn render_human_report(report: &AuditReport, min_severity: Severity) {
    let host_label = report
        .os_info
        .as_ref()
        .map_or("localhost", |os| os.pretty_name.as_str());
    let arch = report
        .os_info
        .as_ref()
        .map_or("unknown", |os| os.architecture.as_str());
    let kernel = report
        .os_info
        .as_ref()
        .map_or("unknown", |os| os.kernel_release.as_str());

    println!(
        "OpenAudit Local Linux Security Audit v{}",
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

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return ExitCode::SUCCESS;
    }

    let mut config = CliConfig::default();
    let mut i = 1;
    let mut command = String::new();

    while i < args.len() {
        match args[i].as_str() {
            "help" | "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "version" | "--version" | "-v" => {
                print_version();
                return ExitCode::SUCCESS;
            }
            "audit" => {
                if i + 1 < args.len() && args[i + 1] == "local" {
                    command = "audit_local".into();
                    i += 1;
                } else {
                    eprintln!("Unknown audit subcommand. Expected: 'openaudit-cli audit local'");
                    return ExitCode::FAILURE;
                }
            }
            "--format" => {
                if i + 1 < args.len() {
                    match args[i + 1].to_lowercase().as_str() {
                        "json" => config.format = OutputFormat::Json,
                        "human" => config.format = OutputFormat::Human,
                        other => {
                            eprintln!("Unknown format '{other}'. Supported: human, json");
                            return ExitCode::FAILURE;
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
                        return ExitCode::FAILURE;
                    }
                    i += 1;
                }
            }
            other => {
                eprintln!("Unknown argument '{other}'. Run 'openaudit-cli --help' for usage.");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    if command == "audit_local" {
        if let Err(err) = run_audit(&config) {
            eprintln!("Audit failed: {err}");
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    } else {
        print_help();
        ExitCode::SUCCESS
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
    }
}
