//! # OpenAudit CLI
//!
//! Command-line interface for OpenAudit, enabling operators to run direct local
//! host posture audits, inspect platform capabilities, generate audit reports,
//! and perform agentless remote network perimeter assessments.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use openaudit_core::{OrganizationId, Severity};
use openaudit_engine::{
    default_platform_backend, AuditEngine, AuditProfile, AuditReport, CheckExecutionStatus,
};
use openaudit_network::{
    IpCidr, NetworkAssessmentReport, NetworkFindingSeverity, PerimeterAssessConfig,
    PerimeterAssessor, PerimeterProfile, SystemDnsResolver, TargetScope,
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

/// Supported report and output serialization formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Html,
    Markdown,
}

/// Configuration for local host posture auditing.
#[derive(Debug, Clone)]
pub struct CliConfig {
    pub format: OutputFormat,
    pub min_severity: Severity,
    pub profile: AuditProfile,
    pub fail_on: Option<Severity>,
    pub input_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Human,
            min_severity: Severity::Info,
            profile: AuditProfile::Baseline,
            fail_on: None,
            input_file: None,
            output_file: None,
        }
    }
}

/// Arguments and options governing agentless remote network perimeter assessment.
#[derive(Debug, Clone)]
pub struct NetworkScanCliArgs {
    pub target: Option<String>,
    pub authorized: bool,
    pub allow_cidr: Vec<String>,
    pub allow_loopback: bool,
    pub allow_link_local: bool,
    pub ports: Option<Vec<u16>>,
    pub profile: PerimeterProfile,
    pub timeout_ms: Option<u64>,
    pub fail_on: Option<NetworkFindingSeverity>,
    pub format: OutputFormat,
    pub output_file: Option<PathBuf>,
}

impl Default for NetworkScanCliArgs {
    fn default() -> Self {
        Self {
            target: None,
            authorized: false,
            allow_cidr: Vec::new(),
            allow_loopback: false,
            allow_link_local: false,
            ports: None,
            profile: PerimeterProfile::Standard,
            timeout_ms: None,
            fail_on: None,
            format: OutputFormat::Human,
            output_file: None,
        }
    }
}

/// Numerical rank for network finding severities to permit safe threshold comparisons.
#[must_use]
pub const fn severity_rank(sev: NetworkFindingSeverity) -> u8 {
    match sev {
        NetworkFindingSeverity::Critical => 5,
        NetworkFindingSeverity::High => 4,
        NetworkFindingSeverity::Medium => 3,
        NetworkFindingSeverity::Low => 2,
        NetworkFindingSeverity::Info => 1,
    }
}

/// Parses comma-separated lists and ranges of port numbers into a deduplicated list.
///
/// # Errors
///
/// Returns an error if port string syntax is invalid, port 0 is given, or bounds are exceeded.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("Invalid start port in range: '{start}'"))?;
            let e: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("Invalid end port in range: '{end}'"))?;
            if s == 0 || e == 0 {
                return Err("Port 0 is reserved and invalid".into());
            }
            if s > e {
                return Err(format!("Invalid port range: '{s}-{e}' (start > end)"));
            }
            if (e - s) > 1000 {
                return Err(format!(
                    "Port range '{s}-{e}' spans more than 1000 ports (bounded discovery limit)"
                ));
            }
            for p in s..=e {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port number: '{part}'"))?;
            if p == 0 {
                return Err("Port 0 is reserved and invalid".into());
            }
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
    }
    if ports.is_empty() {
        return Err("No valid ports specified".into());
    }
    if ports.len() > 1000 {
        return Err("Total ports exceed maximum limit of 1000 ports".into());
    }
    Ok(ports)
}

/// Parses a string into a typed `NetworkFindingSeverity`.
///
/// # Errors
///
/// Returns an error if string is not a valid severity level.
pub fn parse_network_severity(s: &str) -> Result<NetworkFindingSeverity, String> {
    match s.to_lowercase().as_str() {
        "critical" => Ok(NetworkFindingSeverity::Critical),
        "high" => Ok(NetworkFindingSeverity::High),
        "medium" => Ok(NetworkFindingSeverity::Medium),
        "low" => Ok(NetworkFindingSeverity::Low),
        "info" => Ok(NetworkFindingSeverity::Info),
        other => Err(format!(
            "Unknown severity '{other}'. Expected: critical, high, medium, low, info"
        )),
    }
}

fn print_help() {
    println!(
        "OpenAudit CLI v{}\n\n\
        Usage: openaudit-cli <COMMAND> [OPTIONS]\n\n\
        Commands:\n  \
          scan                         Run a security audit against the local host (Local Host Assessment)\n  \
          scan remote <TARGET>         Agentless remote perimeter assessment (Milestone 4)\n  \
          network scan <TARGET>        Alias for perimeter assessment (Milestone 4)\n  \
          perimeter scan <TARGET>      Alias for perimeter assessment (Milestone 4)\n  \
          scan agent                   Enrolled server agent assessment (Milestone 6 roadmap)\n  \
          audit local                  Run local host audit (backward compatible with M2)\n  \
          system info                  Display detected platform metadata and capabilities\n  \
          rules list                   List available security audit rules\n  \
          report                       Generate or export audit reports (human, json, html, markdown)\n  \
          version                      Print version information\n  \
          help                         Print this help message\n\n\
        General Options:\n  \
          --profile <profile>          Profile: baseline|full|hardened (local) or conservative|standard|deep (perimeter)\n  \
          --format <human|json|html|markdown> Output format (default: human)\n  \
          --min-severity <level>       Filter findings by minimum severity (info..critical)\n  \
          --fail-on <level>            Exit with code 2 if findings >= level are found\n  \
          --strict                     Equivalent to --fail-on high\n  \
          --input <path>               Input audit report JSON file for report generation\n  \
          --output <path>              Write report output directly to file\n\n\
        Perimeter Assessment Options:\n  \
          --target <IP|HOST>           Target hostname or IP address\n  \
          --authorized, --certified    Confirm explicit authorization to assess target (REQUIRED)\n  \
          --allow-cidr <CIDR>          Explicitly authorized private CIDR block (e.g. 10.20.0.0/16, repeatable)\n  \
          --allow-loopback             Permit loopback destinations (127.0.0.1, localhost)\n  \
          --allow-link-local           Permit link-local destinations (169.254.0.0/16, fe80::/10)\n  \
          --ports <PORTS>              Custom comma/range list of ports (e.g. 80,443,8000-8010)\n  \
          --timeout <MS>               Probe and connection timeout in milliseconds\n",
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

    let output_str = match config.format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Human => {
            render_human_report(&report, config.min_severity);
            String::new()
        }
        OutputFormat::Html => render_html_report(&report),
        OutputFormat::Markdown => render_markdown_host_report(&report),
    };

    if !output_str.is_empty() {
        if let Some(ref out_path) = config.output_file {
            fs::write(out_path, output_str)?;
        } else {
            println!("{output_str}");
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

fn run_report(config: &CliConfig) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let report: AuditReport = if let Some(ref in_path) = config.input_file {
        let content = fs::read_to_string(in_path)?;
        serde_json::from_str(&content)?
    } else {
        let org_id = OrganizationId::from_seed(b"openaudit:local:default-org");
        let engine = AuditEngine::default();
        engine.run_audit_with_profile(org_id, config.profile)?
    };

    let output_str = match config.format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Human => {
            render_human_report(&report, config.min_severity);
            String::new()
        }
        OutputFormat::Html => render_html_report(&report),
        OutputFormat::Markdown => render_markdown_host_report(&report),
    };

    if !output_str.is_empty() {
        if let Some(ref out_path) = config.output_file {
            fs::write(out_path, output_str)?;
        } else {
            println!("{output_str}");
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
        OutputFormat::Human | OutputFormat::Html | OutputFormat::Markdown => {
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
        OutputFormat::Human | OutputFormat::Html | OutputFormat::Markdown => {
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
    println!("Assessment Type: {}", report.assessment_type.display_name());
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

        let profile_excluded_count = report
            .check_statuses
            .iter()
            .filter(|s| matches!(s.status, CheckExecutionStatus::NotApplicable { .. }))
            .count();

        let executed_count = report
            .check_statuses
            .iter()
            .filter(|s| matches!(s.status, CheckExecutionStatus::Executed { .. }))
            .count();

        let total_checks = report.check_statuses.len();

        if unsupported_count > 0 {
            println!("Note: {unsupported_count} checks were skipped due to platform boundaries.");
        }
        if profile_excluded_count > 0 {
            println!(
                "Note: {profile_excluded_count} checks were excluded by current audit profile (evaluate with --profile hardened)."
            );
        }
        println!(
            "Evaluated: {executed_count} active controls ({total_checks} total registered across all platforms)."
        );
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

fn render_markdown_host_report(report: &AuditReport) -> String {
    let mut md = String::new();
    let _ = writeln!(
        md,
        "# OpenAudit Host Security Report - {}",
        report.asset.name
    );
    let _ = writeln!(md);
    let _ = writeln!(md, "- **Host Target**: `{}`", report.asset.target_address);
    let _ = writeln!(
        md,
        "- **Assessment Type**: {}",
        report.assessment_type.display_name()
    );
    let _ = writeln!(
        md,
        "- **Execution Privilege**: `{:?}`",
        report.current_privilege
    );
    let _ = writeln!(md, "- **Duration**: `{}ms`", report.duration_ms);
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "| Critical | High | Medium | Low | Info | Total |\n\
        |----------|------|--------|-----|------|-------|\n\
        | {} | {} | {} | {} | {} | {} |",
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info,
        report.summary.total(),
    );
    let _ = writeln!(md);
    let _ = writeln!(md, "## Findings ({})", report.findings.len());
    let _ = writeln!(md);

    if report.findings.is_empty() {
        let _ = writeln!(md, "No security findings detected.");
    } else {
        for item in &report.findings {
            let f = &item.finding;
            let _ = writeln!(md, "### [{:?}] {}", f.severity, f.title);
            let _ = writeln!(md, "- **Rule ID**: `{}`", f.rule_id);
            let _ = writeln!(md, "- **Target**: `{}`", item.target);
            let _ = writeln!(md, "- **Description**: {}", f.description);
            let _ = writeln!(md, "- **Remediation**: {}", f.remediation);
            let _ = writeln!(md, "- **Evidence**: `{}`", item.evidence.payload.data());
            let _ = writeln!(md);
        }
    }

    md
}

/// Generates human-readable text for a network perimeter assessment report.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn generate_human_perimeter_report_text(report: &NetworkAssessmentReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "OpenAudit Network Perimeter Assessment v{}",
        openaudit_core::version()
    );
    let _ = writeln!(
        out,
        "================================================================================"
    );
    let _ = writeln!(
        out,
        "Target:             {} ({})",
        report.canonical_host, report.raw_target
    );
    let _ = writeln!(
        out,
        "Pinned IP:          {} [SSRF Pinning Enforced]",
        report.pinned_ip
    );
    let _ = writeln!(out, "IP Classification:  {}", report.ip_classification);
    let _ = writeln!(
        out,
        "Assessment Time:    {}",
        report.completed_at.to_rfc3339()
    );
    let _ = writeln!(out, "Duration:           {} ms", report.duration_ms);
    let _ = writeln!(
        out,
        "Ports Evaluated:    {} ({} open)",
        report.ports_scanned, report.open_ports_count
    );
    let _ = writeln!(
        out,
        "================================================================================"
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "Discovered Endpoints:");
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    let _ = writeln!(
        out,
        "{:<10} {:<8} {:<12} {:<10} {:<11} BANNER / EVIDENCE",
        "PORT", "STATUS", "PROTOCOL", "SERVICE", "CONFIDENCE"
    );
    for ep in &report.endpoints {
        let port_label = format!("{}/tcp", ep.port);
        let status_label = match ep.status {
            openaudit_network::PortStatus::Open => "open",
            openaudit_network::PortStatus::Closed => "closed",
            openaudit_network::PortStatus::TimedOut => "timeout",
            openaudit_network::PortStatus::Filtered => "filtered",
        };
        let proto_label = format!("{:?}", ep.protocol).to_lowercase();
        let conf_label = format!("{:?}", ep.confidence);
        let evidence_label = ep
            .banner
            .as_deref()
            .or(ep.evidence.as_deref())
            .unwrap_or("-");
        let truncated_evidence = if evidence_label.len() > 30 {
            format!("{}...", &evidence_label[..27])
        } else {
            evidence_label.to_string()
        };
        let _ = writeln!(
            out,
            "{:<10} {:<8} {:<12} {:<10} {:<11} {}",
            port_label, status_label, proto_label, ep.service_name, conf_label, truncated_evidence
        );
    }
    let _ = writeln!(out);

    if let Some(ref tls) = report.tls_assessment {
        let _ = writeln!(out, "TLS Security Posture:");
        let _ = writeln!(
            out,
            "--------------------------------------------------------------------------------"
        );
        let tls12_status = if tls.supports_tls12 {
            "Supported"
        } else {
            "Not observed"
        };
        let tls13_status = if tls.supports_tls13 {
            "Supported"
        } else {
            "Not observed"
        };
        let _ = writeln!(out, "  TLS 1.2:            {tls12_status}");
        let _ = writeln!(out, "  TLS 1.3:            {tls13_status}");
        if let Some(ref ver) = tls.negotiated_version {
            let _ = writeln!(out, "  Negotiated Version: {ver}");
        }
        if let Some(ref cipher) = tls.negotiated_cipher {
            let _ = writeln!(
                out,
                "  Negotiated Cipher:  {} ({:?})",
                cipher.name, cipher.security_rating
            );
        }
        let _ = writeln!(out, "  Trust Status:       {:?}", tls.trust_status);
        let _ = writeln!(out, "  Hostname Matched:   {}", tls.hostname_matched);
        if let Some(ref leaf) = tls.leaf_certificate {
            let cn = leaf.common_name.as_deref().unwrap_or("none");
            let _ = writeln!(out, "  Certificate Subject:CN={cn}");
            let _ = writeln!(
                out,
                "  Subject Alt Names:  {}",
                leaf.subject_alternative_names.join(", ")
            );
            let _ = writeln!(
                out,
                "  Validity:           Valid until {} ({} days remaining)",
                leaf.not_after.format("%Y-%m-%d"),
                leaf.days_until_expiration
            );
            let _ = writeln!(
                out,
                "  Key & Signature:    {} / {}",
                leaf.public_key_algorithm, leaf.signature_algorithm
            );
        }
        let _ = writeln!(out);
    }

    if let Some(ref http) = report.http_assessment {
        let _ = writeln!(out, "HTTP Security Posture:");
        let _ = writeln!(
            out,
            "--------------------------------------------------------------------------------"
        );
        let _ = writeln!(
            out,
            "  HTTPS Available:    {}",
            if http.https_available { "Yes" } else { "No" }
        );
        let _ = writeln!(
            out,
            "  HTTP->HTTPS Enforced:{}",
            if http.http_to_https_redirect {
                "Yes"
            } else {
                "No"
            }
        );
        let _ = writeln!(
            out,
            "  HSTS Enforced:      {}",
            if http.hsts_enabled { "Yes" } else { "No" }
        );
        let _ = writeln!(
            out,
            "  CSP Configured:     {}",
            if http.csp_present { "Yes" } else { "No" }
        );
        let _ = writeln!(
            out,
            "  X-Content-Type:     {}",
            if http.x_content_type_options_nosniff {
                "nosniff"
            } else {
                "Missing"
            }
        );
        let server_str = http.server_header.as_deref().unwrap_or("None disclosed");
        let _ = writeln!(out, "  Server Header:      {server_str}");
        let _ = writeln!(out, "  Cookies Evaluated:  {}", http.observed_cookies.len());
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "Security Findings ({}):", report.findings.len());
    let _ = writeln!(
        out,
        "--------------------------------------------------------------------------------"
    );
    if report.findings.is_empty() {
        let _ = writeln!(out, "[+] No security findings detected.");
    } else {
        for f in &report.findings {
            let sev_label = match f.severity {
                NetworkFindingSeverity::Critical => "CRITICAL",
                NetworkFindingSeverity::High => "HIGH    ",
                NetworkFindingSeverity::Medium => "MEDIUM  ",
                NetworkFindingSeverity::Low => "LOW     ",
                NetworkFindingSeverity::Info => "INFO    ",
            };
            let _ = writeln!(out, "[{sev_label}] {} ({})", f.id, f.confidence);
            let _ = writeln!(out, "  Title:          {}", f.title);
            let _ = writeln!(out, "  Endpoint:       {}", f.endpoint);
            let _ = writeln!(out, "  Category:       {}", f.category);
            let _ = writeln!(out, "  Evidence:       {}", f.evidence);
            let _ = writeln!(out, "  Recommendation: {}", f.recommendation);
            let _ = writeln!(out);
        }
    }

    let _ = writeln!(
        out,
        "================================================================================"
    );
    let _ = writeln!(out, "{}", report.architecture_disclaimer);
    let _ = writeln!(
        out,
        "================================================================================"
    );

    out
}

/// Prints formatted human report to stdout.
pub fn render_human_perimeter_report(report: &NetworkAssessmentReport) {
    let text = generate_human_perimeter_report_text(report);
    print!("{text}");
}

/// Renders a Markdown-formatted perimeter assessment report.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_markdown_perimeter_report(report: &NetworkAssessmentReport) -> String {
    let mut md = String::new();
    let _ = writeln!(md, "# OpenAudit Network Perimeter Assessment Report");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "- **Target**: `{}` (`{}`)",
        report.canonical_host, report.raw_target
    );
    let _ = writeln!(
        md,
        "- **Pinned IP**: `{}` (SSRF Protection Enforced)",
        report.pinned_ip
    );
    let _ = writeln!(
        md,
        "- **IP Classification**: `{}`",
        report.ip_classification
    );
    let _ = writeln!(
        md,
        "- **Completed At**: `{}`",
        report.completed_at.to_rfc3339()
    );
    let _ = writeln!(md, "- **Duration**: `{} ms`", report.duration_ms);
    let _ = writeln!(
        md,
        "- **Ports Evaluated**: `{} ({} open)`",
        report.ports_scanned, report.open_ports_count
    );
    let _ = writeln!(md);

    let _ = writeln!(md, "## Discovered Endpoints");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "| Port | Status | Protocol | Service | Confidence | Evidence / Banner |\n\
        |------|--------|----------|---------|------------|-------------------|"
    );
    for ep in &report.endpoints {
        let status = match ep.status {
            openaudit_network::PortStatus::Open => "open",
            openaudit_network::PortStatus::Closed => "closed",
            openaudit_network::PortStatus::TimedOut => "timeout",
            openaudit_network::PortStatus::Filtered => "filtered",
        };
        let banner = ep
            .banner
            .as_deref()
            .or(ep.evidence.as_deref())
            .unwrap_or("-");
        let _ = writeln!(
            md,
            "| {} | {} | {:?} | {} | {:?} | {} |",
            ep.port, status, ep.protocol, ep.service_name, ep.confidence, banner
        );
    }
    let _ = writeln!(md);

    if let Some(ref tls) = report.tls_assessment {
        let _ = writeln!(md, "## TLS Security Posture");
        let _ = writeln!(md);
        let _ = writeln!(md, "- **TLS 1.2 Supported**: `{}`", tls.supports_tls12);
        let _ = writeln!(md, "- **TLS 1.3 Supported**: `{}`", tls.supports_tls13);
        if let Some(ref ver) = tls.negotiated_version {
            let _ = writeln!(md, "- **Negotiated Version**: `{ver}`");
        }
        if let Some(ref cipher) = tls.negotiated_cipher {
            let _ = writeln!(
                md,
                "- **Negotiated Cipher**: `{}` (`{:?}`)",
                cipher.name, cipher.security_rating
            );
        }
        let _ = writeln!(md, "- **Trust Status**: `{:?}`", tls.trust_status);
        let _ = writeln!(md, "- **Hostname Matched**: `{}`", tls.hostname_matched);
        if let Some(ref leaf) = tls.leaf_certificate {
            let _ = writeln!(md, "- **Certificate Subject**: `{}`", leaf.subject_dn);
            let _ = writeln!(
                md,
                "- **Subject Alternative Names**: `{}`",
                leaf.subject_alternative_names.join(", ")
            );
            let _ = writeln!(
                md,
                "- **Validity**: until `{}` ({} days remaining)",
                leaf.not_after.to_rfc3339(),
                leaf.days_until_expiration
            );
            let _ = writeln!(
                md,
                "- **Public Key**: `{}` (weak: `{}`)",
                leaf.public_key_algorithm, leaf.weak_key
            );
        }
        let _ = writeln!(md);
    }

    if let Some(ref http) = report.http_assessment {
        let _ = writeln!(md, "## HTTP Security Posture");
        let _ = writeln!(md);
        let _ = writeln!(md, "- **HTTPS Available**: `{}`", http.https_available);
        let _ = writeln!(
            md,
            "- **HTTP->HTTPS Redirect**: `{}`",
            http.http_to_https_redirect
        );
        let _ = writeln!(md, "- **HSTS Enabled**: `{}`", http.hsts_enabled);
        let _ = writeln!(md, "- **CSP Present**: `{}`", http.csp_present);
        let _ = writeln!(
            md,
            "- **X-Content-Type-Options**: `{}`",
            http.x_content_type_options_nosniff
        );
        let _ = writeln!(
            md,
            "- **Server Header**: `{}`",
            http.server_header.as_deref().unwrap_or("None")
        );
        let _ = writeln!(
            md,
            "- **Cookies Inspected**: `{}`",
            http.observed_cookies.len()
        );
        let _ = writeln!(md);
    }

    let _ = writeln!(md, "## Security Findings ({})", report.findings.len());
    let _ = writeln!(md);
    if report.findings.is_empty() {
        let _ = writeln!(md, "No perimeter security findings detected.");
    } else {
        for f in &report.findings {
            let _ = writeln!(md, "### [{:?}] {}", f.severity, f.title);
            let _ = writeln!(md, "- **Rule ID**: `{}`", f.id);
            let _ = writeln!(md, "- **Endpoint**: `{}`", f.endpoint);
            let _ = writeln!(md, "- **Category**: `{}`", f.category);
            let _ = writeln!(md, "- **Confidence**: `{}`", f.confidence);
            let _ = writeln!(md, "- **Evidence**: {}", f.evidence);
            let _ = writeln!(md, "- **Recommendation**: {}", f.recommendation);
            let _ = writeln!(md);
        }
    }

    let _ = writeln!(md, "## Architectural Boundary Notice");
    let _ = writeln!(md);
    let _ = writeln!(md, "> {}", report.architecture_disclaimer);
    let _ = writeln!(md);

    md
}

/// Renders a self-contained HTML-formatted perimeter assessment report.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_html_perimeter_report(report: &NetworkAssessmentReport) -> String {
    let title = format!("OpenAudit Perimeter Report - {}", report.canonical_host);
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    let _ = writeln!(html, "<title>{title}</title>");
    html.push_str("<style>\n\
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', Helvetica, Arial, sans-serif; background: #0d1117; color: #f0f6fc; margin: 0; padding: 24px; line-height: 1.5; }\n\
        .container { max-width: 980px; margin: 0 auto; }\n\
        header { border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; }\n\
        h1 { font-size: 22px; font-weight: 600; margin: 0 0 8px 0; color: #58a6ff; }\n\
        .meta { color: #8b949e; font-size: 13px; }\n\
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }\n\
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 14px; }\n\
        .card-val { font-size: 18px; font-weight: 600; font-family: ui-monospace, Menlo, monospace; }\n\
        .card-lbl { font-size: 11px; font-weight: 700; color: #8b949e; text-transform: uppercase; margin-top: 4px; }\n\
        table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }\n\
        th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #21262d; font-size: 13px; }\n\
        th { background: #21262d; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; }\n\
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }\n\
        .badge-crit { background: #f8514933; color: #f85149; border: 1px solid #f8514966; }\n\
        .badge-high { background: #d2992233; color: #e3b341; border: 1px solid #d2992266; }\n\
        .badge-med { background: #bb800933; color: #d29922; border: 1px solid #bb800966; }\n\
        .badge-low { background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb66; }\n\
        .badge-info { background: #30363d; color: #8b949e; border: 1px solid #8b949e66; }\n\
        .finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 12px; }\n\
        .finding-title { font-weight: 600; font-size: 14px; margin-bottom: 6px; }\n\
        .finding-evidence { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 8px 12px; font-family: ui-monospace, Menlo, monospace; font-size: 12px; color: #c9d1d9; margin: 8px 0; overflow-x: auto; }\n\
        .finding-rec { font-size: 12px; color: #3fb950; background: #23863622; border: 1px solid #23863644; border-radius: 4px; padding: 8px 12px; }\n\
        .disclaimer-card { background: #161b22; border-left: 4px solid #f0883e; padding: 16px; border-radius: 0 6px 6px 0; font-size: 12px; color: #8b949e; line-height: 1.6; margin-top: 32px; }\n\
    </style>\n</head>\n<body>\n<div class=\"container\">\n");

    html.push_str("<header>\n");
    let _ = writeln!(html, "<h1>Network Perimeter Assessment</h1>");
    let _ = writeln!(
        html,
        "<div class=\"meta\">Target: <strong>{}</strong> (pinned: {}) | Classification: {} | Completed: {} | Duration: {}ms</div>",
        report.canonical_host, report.pinned_ip, report.ip_classification, report.completed_at.to_rfc3339(), report.duration_ms
    );
    html.push_str("</header>\n");

    html.push_str("<div class=\"summary-grid\">\n");
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-val\">{}</div><div class=\"card-lbl\">Ports Scanned</div></div>", report.ports_scanned);
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-val\">{}</div><div class=\"card-lbl\">Open Ports</div></div>", report.open_ports_count);
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-val\">{}</div><div class=\"card-lbl\">Findings</div></div>", report.findings.len());
    let _ = writeln!(html, "<div class=\"card\"><div class=\"card-val\">{}ms</div><div class=\"card-lbl\">Duration</div></div>", report.duration_ms);
    html.push_str("</div>\n");

    html.push_str("<h2>Discovered Endpoints</h2>\n");
    html.push_str("<table><thead><tr><th>Port</th><th>Status</th><th>Protocol</th><th>Service</th><th>Confidence</th><th>Banner / Evidence</th></tr></thead><tbody>\n");
    for ep in &report.endpoints {
        let banner = ep
            .banner
            .as_deref()
            .or(ep.evidence.as_deref())
            .unwrap_or("-");
        let _ = writeln!(
            html,
            "<tr><td>{}/tcp</td><td>{:?}</td><td>{:?}</td><td>{}</td><td>{:?}</td><td>{}</td></tr>",
            ep.port, ep.status, ep.protocol, ep.service_name, ep.confidence, banner
        );
    }
    html.push_str("</tbody></table>\n");

    html.push_str("<h2>Security Findings</h2>\n");
    if report.findings.is_empty() {
        html.push_str("<p class=\"meta\">No security violations detected.</p>\n");
    } else {
        for f in &report.findings {
            let badge_cls = match f.severity {
                NetworkFindingSeverity::Critical => "badge-crit",
                NetworkFindingSeverity::High => "badge-high",
                NetworkFindingSeverity::Medium => "badge-med",
                NetworkFindingSeverity::Low => "badge-low",
                NetworkFindingSeverity::Info => "badge-info",
            };
            let _ = writeln!(
                html,
                "<div class=\"finding\">\n\
                <div class=\"finding-title\"><span class=\"badge {badge_cls}\">[{:?}]</span> {} - {}</div>\n\
                <div class=\"meta\">Endpoint: {} | Category: {} | Confidence: {}</div>\n\
                <div class=\"finding-evidence\">{}</div>\n\
                <div class=\"finding-rec\"><strong>Recommendation:</strong> {}</div>\n\
                </div>",
                f.severity,
                f.id,
                f.title,
                f.endpoint,
                f.category,
                f.confidence,
                f.evidence,
                f.recommendation
            );
        }
    }

    let _ = writeln!(
        html,
        "<div class=\"disclaimer-card\"><strong>Architectural Boundary Notice:</strong><br>{}</div>",
        report.architecture_disclaimer
    );

    html.push_str("</div>\n</body>\n</html>");
    html
}

/// Executes agentless network perimeter assessment using the shared `PerimeterAssessor`.
///
/// # Errors
///
/// Returns an error if target assessment or report file writing encounters an I/O failure.
pub fn run_network_scan(args: &NetworkScanCliArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let target = match args.target.as_deref() {
        Some(t) if !t.trim().is_empty() => t.trim(),
        _ => {
            eprintln!(
                "Error: Target not specified. Usage: openaudit-cli network scan <TARGET> [OPTIONS]"
            );
            return Ok(exit_codes::FAILURE);
        }
    };

    if !args.authorized {
        eprintln!(
            "Error: Remote perimeter scanning requires explicit authorization.\n\
            Re-run with `--authorized` (or `--certified`) after verifying authorization to assess this target."
        );
        return Ok(exit_codes::FAILURE);
    }

    let mut scope = TargetScope {
        allow_public: true,
        authorized_cidrs: Vec::new(),
        allow_loopback: args.allow_loopback,
        allow_link_local: args.allow_link_local,
        allow_testnets: true,
        explicit_allowed_ips: std::collections::HashSet::new(),
    };

    for cidr_str in &args.allow_cidr {
        match IpCidr::parse(cidr_str) {
            Ok(cidr) => scope.add_authorized_cidr(cidr),
            Err(err) => {
                eprintln!("Invalid CIDR '{cidr_str}': {err}");
                return Ok(exit_codes::FAILURE);
            }
        }
    }

    let ports = args
        .ports
        .as_ref()
        .map_or_else(|| args.profile.default_ports(), Clone::clone);

    let mut config = PerimeterAssessConfig::default();
    if let Some(timeout_ms) = args.timeout_ms {
        let dur = Duration::from_millis(timeout_ms);
        config.tcp_config.timeout = dur;
        config.service_config.probe_timeout = dur;
        config.tls_config.timeout = dur;
        config.http_config.connect_timeout = dur;
        config.http_config.read_timeout = dur;
    }

    let resolver = SystemDnsResolver;
    let report = match PerimeterAssessor::assess(target, &ports, &scope, &resolver, &config, None) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("Perimeter assessment failed: {err}");
            return Ok(exit_codes::FAILURE);
        }
    };

    let output_str = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Human => {
            render_human_perimeter_report(&report);
            String::new()
        }
        OutputFormat::Markdown => render_markdown_perimeter_report(&report),
        OutputFormat::Html => render_html_perimeter_report(&report),
    };

    if !output_str.is_empty() {
        if let Some(ref out_path) = args.output_file {
            fs::write(out_path, &output_str)?;
            println!("Report saved to: {}", out_path.display());
        } else {
            println!("{output_str}");
        }
    } else if let Some(ref out_path) = args.output_file {
        let text = generate_human_perimeter_report_text(&report);
        fs::write(out_path, &text)?;
        println!("Report saved to: {}", out_path.display());
    }

    if let Some(threshold) = args.fail_on {
        let threshold_rank = severity_rank(threshold);
        let has_violations = report
            .findings
            .iter()
            .any(|f| severity_rank(f.severity) >= threshold_rank);
        if has_violations {
            return Ok(exit_codes::findings_detected());
        }
    }

    Ok(exit_codes::SUCCESS)
}

#[allow(clippy::too_many_lines)]
fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return exit_codes::SUCCESS;
    }

    let mut config = CliConfig::default();
    let mut network_args = NetworkScanCliArgs::default();
    let mut i = 1;
    let mut command = String::new();
    let mut remote_target: Option<String> = None;

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
                if i + 1 < args.len() && args[i + 1] == "local" {
                    command = "scan".into();
                    i += 1;
                } else if i + 1 < args.len() && args[i + 1] == "remote" {
                    command = "scan_remote".into();
                    i += 1;
                    if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                        remote_target = Some(args[i + 1].clone());
                        i += 1;
                    }
                } else if i + 1 < args.len() && args[i + 1] == "agent" {
                    command = "scan_agent".into();
                    i += 1;
                } else {
                    command = "scan".into();
                }
            }
            "network" | "perimeter" => {
                if i + 1 < args.len() && args[i + 1] == "scan" {
                    command = "scan_remote".into();
                    i += 1;
                    if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                        remote_target = Some(args[i + 1].clone());
                        i += 1;
                    }
                } else {
                    eprintln!(
                        "Unknown subcommand for '{}'. Expected: 'openaudit-cli {} scan <TARGET>'",
                        args[i], args[i]
                    );
                    return exit_codes::FAILURE;
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
            "--target" => {
                if i + 1 < args.len() {
                    remote_target = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--authorized" | "--certified" => {
                network_args.authorized = true;
            }
            "--allow-cidr" => {
                if i + 1 < args.len() {
                    network_args.allow_cidr.push(args[i + 1].clone());
                    i += 1;
                }
            }
            "--allow-loopback" => {
                network_args.allow_loopback = true;
            }
            "--allow-link-local" => {
                network_args.allow_link_local = true;
            }
            "--ports" => {
                if i + 1 < args.len() {
                    match parse_ports(&args[i + 1]) {
                        Ok(p) => network_args.ports = Some(p),
                        Err(err) => {
                            eprintln!("Invalid --ports specification '{}': {err}", args[i + 1]);
                            return exit_codes::FAILURE;
                        }
                    }
                    i += 1;
                }
            }
            "--timeout" => {
                if i + 1 < args.len() {
                    if let Ok(ms) = args[i + 1].parse::<u64>() {
                        network_args.timeout_ms = Some(ms);
                    } else {
                        eprintln!(
                            "Invalid --timeout specification '{}': must be positive integer milliseconds",
                            args[i + 1]
                        );
                        return exit_codes::FAILURE;
                    }
                    i += 1;
                }
            }
            "--profile" => {
                if i + 1 < args.len() {
                    match args[i + 1].to_lowercase().as_str() {
                        "baseline" => config.profile = AuditProfile::Baseline,
                        "full" => config.profile = AuditProfile::Full,
                        "hardened" => config.profile = AuditProfile::Hardened,
                        "conservative" => network_args.profile = PerimeterProfile::Conservative,
                        "standard" => network_args.profile = PerimeterProfile::Standard,
                        "deep" => network_args.profile = PerimeterProfile::Deep,
                        other => {
                            eprintln!(
                                "Unknown profile '{other}'. Supported: baseline, full, hardened (local) or conservative, standard, deep (perimeter)"
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
                        "json" => {
                            config.format = OutputFormat::Json;
                            network_args.format = OutputFormat::Json;
                        }
                        "human" => {
                            config.format = OutputFormat::Human;
                            network_args.format = OutputFormat::Human;
                        }
                        "html" => {
                            config.format = OutputFormat::Html;
                            network_args.format = OutputFormat::Html;
                        }
                        "markdown" | "md" => {
                            config.format = OutputFormat::Markdown;
                            network_args.format = OutputFormat::Markdown;
                        }
                        other => {
                            eprintln!(
                                "Unknown format '{other}'. Supported: human, json, html, markdown"
                            );
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
                    let matched_host = if let Ok(sev) = args[i + 1].parse::<Severity>() {
                        config.fail_on = Some(sev);
                        true
                    } else {
                        false
                    };
                    let matched_net = if let Ok(net_sev) = parse_network_severity(&args[i + 1]) {
                        network_args.fail_on = Some(net_sev);
                        true
                    } else {
                        false
                    };
                    if !matched_host && !matched_net {
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
                network_args.fail_on = Some(NetworkFindingSeverity::High);
            }
            "--input" => {
                if i + 1 < args.len() {
                    config.input_file = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    let out_path = PathBuf::from(&args[i + 1]);
                    config.output_file = Some(out_path.clone());
                    network_args.output_file = Some(out_path);
                    i += 1;
                }
            }
            other => {
                eprintln!("Unknown argument '{other}'. Run 'openaudit-cli --help' for usage.");
                return exit_codes::FAILURE;
            }
        }
        i += 1;
    }

    if network_args.target.is_none() {
        network_args.target = remote_target;
    }

    match command.as_str() {
        "scan" | "audit_local" => match run_scan(&config) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("Audit failed: {err}");
                exit_codes::FAILURE
            }
        },
        "scan_remote" => match run_network_scan(&network_args) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("Network perimeter scan failed: {err}");
                exit_codes::FAILURE
            }
        },
        "scan_agent" => {
            println!("OpenAudit Enrolled Server Agent Assessment");
            println!("Assessment Type: Enrolled Agent Host Assessment");
            println!("Status: Scheduled for Milestone 6 (Secure Agent Communication & Enrollment)");
            println!();
            println!("Notice: Centralized server management and securely attested agent communication are part of Milestones 5 and 6.");
            println!("Requirements: Install openaudit-agent on target servers, enroll with the OpenAudit control plane using secure D4 attestation, and run audits via the shared Rust engine.");
            exit_codes::SUCCESS
        }
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
        "report" => match run_report(&config) {
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
    use openaudit_network::{DiscoveredEndpointService, UnifiedNetworkFinding};

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
    fn test_default_network_scan_cli_args() {
        let args = NetworkScanCliArgs::default();
        assert_eq!(args.target, None);
        assert!(!args.authorized);
        assert!(args.allow_cidr.is_empty());
        assert!(!args.allow_loopback);
        assert_eq!(args.profile, PerimeterProfile::Standard);
        assert_eq!(args.format, OutputFormat::Human);
    }

    #[test]
    fn test_severity_rank_hierarchy() {
        assert!(
            severity_rank(NetworkFindingSeverity::Critical)
                > severity_rank(NetworkFindingSeverity::High)
        );
        assert!(
            severity_rank(NetworkFindingSeverity::High)
                > severity_rank(NetworkFindingSeverity::Medium)
        );
        assert!(
            severity_rank(NetworkFindingSeverity::Medium)
                > severity_rank(NetworkFindingSeverity::Low)
        );
        assert!(
            severity_rank(NetworkFindingSeverity::Low)
                > severity_rank(NetworkFindingSeverity::Info)
        );
    }

    #[test]
    fn test_parse_ports_single_and_range() {
        let ports = parse_ports("80,443,8000-8003").expect("valid ports");
        assert_eq!(ports, vec![80, 443, 8000, 8001, 8002, 8003]);

        assert!(parse_ports("").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("100-50").is_err());
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn test_parse_network_severity() {
        assert_eq!(
            parse_network_severity("CRITICAL").unwrap(),
            NetworkFindingSeverity::Critical
        );
        assert_eq!(
            parse_network_severity("high").unwrap(),
            NetworkFindingSeverity::High
        );
        assert_eq!(
            parse_network_severity("Medium").unwrap(),
            NetworkFindingSeverity::Medium
        );
        assert_eq!(
            parse_network_severity("low").unwrap(),
            NetworkFindingSeverity::Low
        );
        assert_eq!(
            parse_network_severity("info").unwrap(),
            NetworkFindingSeverity::Info
        );
        assert!(parse_network_severity("invalid").is_err());
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
            assessment_type: openaudit_core::AssessmentType::LocalHostAssessment,
        };
        let html = render_html_report(&report);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<title>OpenAudit Report - Ubuntu Test</title>"));
        assert!(html.contains("Critical"));
    }

    #[test]
    fn test_render_markdown_perimeter_report() {
        let report = NetworkAssessmentReport {
            raw_target: "example.com".into(),
            canonical_host: "example.com".into(),
            pinned_ip: "93.184.216.34".into(),
            ip_classification: "Public".into(),
            ports_scanned: 1,
            open_ports_count: 1,
            endpoints: vec![DiscoveredEndpointService {
                port: 443,
                status: openaudit_network::PortStatus::Open,
                protocol: openaudit_network::IdentifiedProtocol::Https,
                service_name: "HTTPS".into(),
                confidence: openaudit_network::IdentificationConfidence::Confirmed,
                evidence: Some("TLS 1.3 handshake".into()),
                banner: None,
            }],
            tls_assessment: None,
            http_assessment: None,
            findings: vec![UnifiedNetworkFinding {
                id: "test.rule".into(),
                severity: NetworkFindingSeverity::High,
                confidence: "Confirmed".into(),
                category: "TLS".into(),
                title: "Test Rule".into(),
                endpoint: "https://example.com:443/".into(),
                evidence: "Test evidence".into(),
                recommendation: "Test remedy".into(),
                timestamp: chrono::Utc::now(),
            }],
            duration_ms: 120,
            completed_at: chrono::Utc::now(),
            architecture_disclaimer: "Architectural Boundary Notice: disclaimer here".into(),
        };

        let md = render_markdown_perimeter_report(&report);
        assert!(md.contains("# OpenAudit Network Perimeter Assessment Report"));
        assert!(md.contains("example.com"));
        assert!(md.contains("93.184.216.34"));
        assert!(md.contains("[High] Test Rule"));
        assert!(md.contains("Architectural Boundary Notice"));
    }
}
