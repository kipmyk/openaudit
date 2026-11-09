//! Report generation and export handlers (HTML, JSON, CSV).

use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::fmt::Write;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::store::models::{AssessmentFinding, AssessmentJob};

#[derive(Debug, Deserialize)]
pub struct ExportReportQuery {
    pub job_id: Uuid,
    pub format: Option<String>,
}

/// Safely sanitizes CSV field contents against CSV formula injection.
///
/// If a value begins with `=`, `+`, `-`, `@`, `\t`, or `\r`, prepends `'` to neutralize execution in spreadsheets.
#[must_use]
pub fn sanitize_csv_cell(cell: &str) -> String {
    let trimmed = cell.trim_start();
    let neutralized = if trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r')
    {
        format!("'{cell}")
    } else {
        cell.to_string()
    };

    // If cell contains commas, quotes, or newlines, quote the field
    if neutralized.contains(',')
        || neutralized.contains('"')
        || neutralized.contains('\n')
        || neutralized.contains('\r')
    {
        let escaped = neutralized.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        neutralized
    }
}

/// Safely escapes text for inclusion in HTML to prevent XSS.
#[must_use]
pub fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Generates a standalone, responsive, high-density Enterprise SaaS HTML report.
fn generate_html_report(job: &AssessmentJob, findings: &[AssessmentFinding]) -> String {
    let target = escape_html(&job.target);
    let job_id = job.id.to_string();
    let assessment_type = escape_html(&job.assessment_type);
    let profile = escape_html(&job.profile);
    let engine_version = escape_html(&job.engine_version);
    let status = escape_html(job.status.as_str());
    let created_at = escape_html(&job.created_at.to_rfc3339());
    let completed_at = job
        .completed_at
        .map_or_else(|| "N/A".to_string(), |c| escape_html(&c.to_rfc3339()));

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;

    for f in findings {
        match f.severity.to_lowercase().as_str() {
            "critical" => critical_count += 1,
            "high" => high_count += 1,
            "medium" => medium_count += 1,
            "low" => low_count += 1,
            _ => info_count += 1,
        }
    }

    let mut findings_html = String::new();
    if findings.is_empty() {
        findings_html.push_str(
            r#"<div class="empty-state">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                <div class="empty-title">Zero Security Findings Discovered</div>
                <div class="empty-desc">All evaluated security rules satisfied required posture controls.</div>
            </div>"#
        );
    } else {
        for f in findings {
            let sev = escape_html(&f.severity);
            let sev_lower = f.severity.to_lowercase();
            let sev_badge_class = match sev_lower.as_str() {
                "critical" => "badge-critical",
                "high" => "badge-high",
                "medium" => "badge-medium",
                "low" => "badge-low",
                _ => "badge-info",
            };
            let title = escape_html(&f.title);
            let rule_id = escape_html(&f.rule_id);
            let endpoint = escape_html(&f.endpoint);
            let confidence = escape_html(&f.confidence);
            let evidence = escape_html(&f.evidence);
            let recommendation = escape_html(&f.recommendation);
            let fp = f.fingerprint.as_deref().unwrap_or("N/A");

            let _ = write!(
                findings_html,
                r#"<div class="card finding-card">
                    <div class="finding-header">
                        <div class="finding-title-row">
                            <span class="badge {sev_badge_class}">{sev}</span>
                            <span class="finding-title">{title}</span>
                        </div>
                        <div class="finding-meta">
                            <span class="meta-item"><code>{rule_id}</code></span>
                            <span class="meta-item">Confidence: {confidence}</span>
                            <span class="meta-item">FP: <code>{fp}</code></span>
                        </div>
                    </div>
                    <div class="finding-body">
                        <div class="field-label">Target Endpoint</div>
                        <div class="field-val"><code>{endpoint}</code></div>

                        <div class="field-label">Technical Evidence</div>
                        <pre class="evidence-box"><code>{evidence}</code></pre>

                        <div class="field-label">Remediation Guidance</div>
                        <div class="remediation-val">{recommendation}</div>
                    </div>
                </div>"#
            );
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OpenAudit Security Assessment Report - {target}</title>
    <style>
        :root {{
            --bg: #09090b;
            --card: #18181b;
            --card-subtle: #121215;
            --border: #27272a;
            --text: #f4f4f5;
            --muted: #a1a1aa;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 13px;
            line-height: 1.5;
            padding: 32px 16px;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 24px;
        }}
        .brand {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--muted);
            margin-bottom: 4px;
        }}
        .title {{
            font-size: 20px;
            font-weight: 600;
            letter-spacing: -0.02em;
            color: var(--text);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 12px 16px;
        }}
        .stat-label {{
            font-size: 11px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 4px;
        }}
        .stat-value {{
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .grid-meta {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
        }}
        .card-title {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--muted);
            margin-bottom: 12px;
            font-weight: 600;
        }}
        .meta-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .meta-table td {{
            padding: 4px 0;
            font-size: 12px;
        }}
        .meta-table td:first-child {{
            color: var(--muted);
            width: 40%;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge-info {{ background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }}
        .finding-card {{
            margin-bottom: 16px;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 12px;
        }}
        .finding-title-row {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .finding-title {{
            font-size: 14px;
            font-weight: 600;
        }}
        .finding-meta {{
            display: flex;
            gap: 12px;
            color: var(--muted);
            font-size: 11px;
        }}
        .field-label {{
            font-size: 11px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 8px;
            margin-bottom: 2px;
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            background: rgba(255, 255, 255, 0.05);
            padding: 1px 4px;
            border-radius: 3px;
        }}
        pre.evidence-box {{
            background: var(--card-subtle);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px;
            overflow-x: auto;
            max-height: 180px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 11px;
            line-height: 1.4;
            color: #e4e4e7;
        }}
        .remediation-val {{
            color: #d4d4d8;
            font-size: 12px;
        }}
        .empty-state {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 48px;
            text-align: center;
            color: var(--muted);
        }}
        .empty-title {{
            font-size: 14px;
            font-weight: 600;
            color: var(--text);
            margin-top: 8px;
            margin-bottom: 4px;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            color: var(--muted);
            font-size: 11px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <div class="brand">OpenAudit Assessment Report</div>
                <div class="title">{target}</div>
            </div>
            <div>
                <span class="badge badge-info">{status}</span>
            </div>
        </header>

        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Critical</div>
                <div class="stat-value" style="color: var(--critical);">{critical_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High</div>
                <div class="stat-value" style="color: var(--high);">{high_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium</div>
                <div class="stat-value" style="color: var(--medium);">{medium_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Low</div>
                <div class="stat-value" style="color: var(--low);">{low_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Info</div>
                <div class="stat-value" style="color: var(--info);">{info_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{total_findings}</div>
            </div>
        </section>

        <section class="grid-meta">
            <div class="card">
                <div class="card-title">Assessment Execution</div>
                <table class="meta-table">
                    <tr><td>Job ID</td><td><code>{job_id}</code></td></tr>
                    <tr><td>Target</td><td><code>{target}</code></td></tr>
                    <tr><td>Assessment Type</td><td>{assessment_type}</td></tr>
                    <tr><td>Profile</td><td>{profile}</td></tr>
                </table>
            </div>
            <div class="card">
                <div class="card-title">Audit Metadata</div>
                <table class="meta-table">
                    <tr><td>Engine Version</td><td>{engine_version}</td></tr>
                    <tr><td>Created At</td><td>{created_at}</td></tr>
                    <tr><td>Completed At</td><td>{completed_at}</td></tr>
                    <tr><td>Rules Evaluated</td><td>{rules_evaluated_count}</td></tr>
                </table>
            </div>
        </section>

        <section>
            <div class="card-title" style="margin-bottom: 12px;">Discovered Security Findings ({total_findings})</div>
            {findings_html}
        </section>

        <footer class="footer">
            <div>OpenAudit v{engine_version} Control Plane</div>
            <div>Generated {generated_at} UTC</div>
        </footer>
    </div>
</body>
</html>"#,
        target = target,
        job_id = job_id,
        assessment_type = assessment_type,
        profile = profile,
        engine_version = engine_version,
        status = status,
        created_at = created_at,
        completed_at = completed_at,
        critical_count = critical_count,
        high_count = high_count,
        medium_count = medium_count,
        low_count = low_count,
        info_count = info_count,
        total_findings = findings.len(),
        rules_evaluated_count = job
            .rules_evaluated
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .map_or(0, |v| v.len()),
        findings_html = findings_html,
        generated_at = Utc::now().to_rfc3339()
    )
}

/// `GET /api/v1/reports/export` - Exports assessment reports as HTML, JSON, or CSV.
pub async fn export_report_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Query(query): Query<ExportReportQuery>,
) -> Response {
    let job = match state.store.get_job(auth.org_id, query.job_id).await {
        Ok(Some(j)) => j,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "message": format!("Job '{}' not found", query.job_id)
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": err.to_string()
                })),
            )
                .into_response();
        }
    };

    let findings = match state
        .store
        .list_findings(auth.org_id, Some(query.job_id), None)
        .await
    {
        Ok(f) => f,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": err.to_string()
                })),
            )
                .into_response();
        }
    };

    let format = query.format.as_deref().unwrap_or("json").to_lowercase();
    match format.as_str() {
        "csv" => {
            let mut csv_out = String::from(
                "finding_id,rule_id,severity,confidence,title,endpoint,evidence,recommendation,created_at\n",
            );
            for f in findings {
                let row = format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    sanitize_csv_cell(&f.id.to_string()),
                    sanitize_csv_cell(&f.rule_id),
                    sanitize_csv_cell(&f.severity),
                    sanitize_csv_cell(&f.confidence),
                    sanitize_csv_cell(&f.title),
                    sanitize_csv_cell(&f.endpoint),
                    sanitize_csv_cell(&f.evidence),
                    sanitize_csv_cell(&f.recommendation),
                    sanitize_csv_cell(&f.created_at.to_rfc3339()),
                );
                csv_out.push_str(&row);
            }

            let filename = format!("assessment-report-{}.csv", job.id);
            (
                StatusCode::OK,
                [
                    (CONTENT_TYPE, "text/csv; charset=utf-8"),
                    (
                        CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{filename}\""),
                    ),
                ],
                csv_out,
            )
                .into_response()
        }
        "html" => {
            let html_content = generate_html_report(&job, &findings);
            let filename = format!("assessment-report-{}.html", job.id);
            (
                StatusCode::OK,
                [
                    (CONTENT_TYPE, "text/html; charset=utf-8"),
                    (
                        CONTENT_DISPOSITION,
                        &format!("inline; filename=\"{filename}\""),
                    ),
                ],
                html_content,
            )
                .into_response()
        }
        _ => {
            // Default to JSON
            (
                StatusCode::OK,
                Json(json!({
                    "job": job,
                    "findings": findings,
                    "exported_at": Utc::now()
                })),
            )
                .into_response()
        }
    }
}
