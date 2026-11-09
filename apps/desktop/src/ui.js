// OpenAudit Desktop - Client State & Event Orchestrator
let currentReport = null;
let currentRules = [];
let systemInfo = null;
let systemPermissions = null;
let currentProfile = 'baseline';
let currentFilter = 'all';
let currentPlatformFilter = 'MacOS';
let selectedFindingRuleId = null;
let findingsSearchQuery = '';
let rulesSearchQuery = '';
let scanTimerInterval = null;
let scanStartTime = 0;

// Error reporter for native Cocoa debugging
window.onerror = function(msg, url, line, col, error) {
  const errStr = error && error.stack ? error.stack : `${msg} at line ${line}:${col}`;
  try {
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc) {
      window.webkit.messageHandlers.ipc.postMessage(JSON.stringify({ action: "js_error", msg: errStr, line }));
    }
  } catch (_) {}
  document.title = `ERR: ${errStr}`;
};

function sendIpc(action, data = {}) {
  const payload = JSON.stringify({ action, ...data });
  try {
    if (window.ipc && typeof window.ipc.postMessage === 'function') {
      window.ipc.postMessage(payload);
      return;
    }
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc) {
      window.webkit.messageHandlers.ipc.postMessage(payload);
      return;
    }
  } catch (err) {
    console.error("sendIpc error:", err);
  }

  // Fallback retry if handlers are still attaching
  let attempts = 0;
  const interval = setInterval(() => {
    attempts++;
    try {
      if (window.ipc && typeof window.ipc.postMessage === 'function') {
        clearInterval(interval);
        window.ipc.postMessage(payload);
      } else if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc) {
        clearInterval(interval);
        window.webkit.messageHandlers.ipc.postMessage(payload);
      } else if (attempts > 40) {
        clearInterval(interval);
      }
    } catch (_) {
      clearInterval(interval);
    }
  }, 40);
}

function safeGetStorage(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback;
  } catch (_) {
    return fallback;
  }
}

function safeSetStorage(key, val) {
  try {
    localStorage.setItem(key, val);
  } catch (_) {}
}

// Initialize Theme (Default Light Mode per mike-design-system standard)
function initTheme() {
  const saved = safeGetStorage('openaudit-theme', 'light');
  setTheme(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'light' ? 'dark' : 'light';
  setTheme(next);
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  safeSetStorage('openaudit-theme', theme);
  const icon = document.getElementById('theme-icon');
  if (icon) {
    if (theme === 'dark') {
      icon.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
    } else {
      icon.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
    }
  }
}

// Navigation Tab Switcher
function showTab(tabId) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(el => el.style.display = 'none');

  const navEl = document.getElementById(`nav-${tabId}`);
  if (navEl) navEl.classList.add('active');

  const paneEl = document.getElementById(`tab-${tabId}`);
  if (paneEl) paneEl.style.display = 'block';

  const titles = {
    overview: 'System Security Overview (Local Machine)',
    remote: 'Remote Server Network Assessment (Agentless)',
    enrolled: 'Enrolled Server Fleet Management',
    findings: 'Findings & Forensics Inspection',
    rules: 'Security Rule Catalog',
    report: 'Audit Report Preview',
    settings: 'Settings & macOS Permissions'
  };
  const titleEl = document.getElementById('page-title');
  if (titleEl && titles[tabId]) titleEl.textContent = titles[tabId];

  // Dynamically adapt primary action button in topbar based on active tab
  const topBtn = document.getElementById('btn-run-audit');
  if (topBtn) {
    if (tabId === 'remote') {
      topBtn.innerHTML = `
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="12 6 12 12 16 14"/>
        </svg>
        Validate Target Scope
      `;
      topBtn.onclick = startRemoteScan;
    } else {
      topBtn.innerHTML = `
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        Run Audit
      `;
      topBtn.onclick = runAudit;
    }
  }

  if (tabId === 'settings') {
    sendIpc('get_permissions');
  } else if (tabId === 'rules') {
    if (currentRules.length === 0) sendIpc('get_rules');
  } else if (tabId === 'report') {
    if (currentReport) renderReportPreview(currentReport);
  }
}

function onAuthCheckChange(checked) {
  const authBox = document.getElementById('remote-auth-box');
  if (authBox) {
    if (checked) {
      authBox.style.borderColor = 'var(--accent-blue)';
      authBox.style.backgroundColor = 'var(--bg-card)';
    } else {
      authBox.style.borderColor = 'var(--border-light)';
      authBox.style.backgroundColor = 'var(--bg-subtle)';
    }
  }
}

// Target Scope & Boundary Validation Action (M4 Perimeter Engine)
function startRemoteScan() {
  const targetInput = document.getElementById('remote-target-input');
  const portInput = document.getElementById('remote-port-input');
  const profileSelect = document.getElementById('remote-profile-select');
  const authCheck = document.getElementById('remote-auth-check');
  const authBox = document.getElementById('remote-auth-box');
  const outputContainer = document.getElementById('remote-scan-output-container');
  const consoleEl = document.getElementById('remote-scan-console');
  const titleEl = document.getElementById('remote-scan-target-title');
  const badgeEl = document.getElementById('remote-scan-status-badge');

  const target = (targetInput?.value || '192.0.2.10').trim();
  const ports = (portInput?.value || '80, 443, 8080, 8443, 22').trim();
  const profile = profileSelect?.value || 'network';

  if (!authCheck?.checked) {
    if (authBox) {
      authBox.style.borderColor = 'var(--accent-red)';
      authBox.style.backgroundColor = 'rgba(239, 68, 68, 0.08)';
    }
    showToast('Authorization required: Please check the certification box above');
    authCheck?.focus();
    return;
  }

  if (authBox) {
    authBox.style.borderColor = 'var(--border-light)';
    authBox.style.backgroundColor = 'var(--bg-subtle)';
  }

  if (outputContainer) outputContainer.style.display = 'block';
  if (titleEl) titleEl.textContent = `PERIMETER ASSESSMENT: ${target}`;
  if (badgeEl) {
    badgeEl.className = 'terminal-badge';
    badgeEl.innerHTML = `<svg class="spinner" viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> ASSESSING`;
  }

  showProgress(`Running perimeter assessment for ${target}...`, 40);

  let logs = `[*] OpenAudit M4 Network Perimeter Assessment\n`;
  logs += `[*] Target:             ${target}\n`;
  logs += `[*] Target Ports:       ${ports}\n`;
  logs += `[*] Profile:            ${profile}\n`;
  logs += `[*] Authorization:      Certified by operator\n`;
  logs += `[*] Executing target scope validation, TCP discovery, service identification, TLS, and HTTP assessment...\n`;
  if (consoleEl) consoleEl.textContent = logs;

  sendIpc('run_perimeter_assessment', {
    target: target,
    ports: ports,
    profile: profile,
    allow_loopback: true
  });
}

window.onPerimeterAssessmentCompleted = function(report) {
  hideProgress();
  const consoleEl = document.getElementById('remote-scan-console');
  const badgeEl = document.getElementById('remote-scan-status-badge');
  if (badgeEl) {
    badgeEl.className = 'terminal-badge';
    badgeEl.style.color = 'var(--accent-green)';
    badgeEl.innerHTML = `<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> COMPLETED (${report.duration_ms}ms)`;
  }

  let out = `[+] Perimeter Assessment Completed in ${report.duration_ms}ms\n`;
  out += `[*] Target:           ${report.raw_target} (${report.canonical_host})\n`;
  out += `[*] Pinned IP:        ${report.pinned_ip} [${report.ip_classification}]\n`;
  out += `[*] Ports Scanned:    ${report.ports_scanned} (${report.open_ports_count} Open)\n\n`;

  out += `--- DISCOVERED ENDPOINTS ---\n`;
  for (const ep of report.endpoints) {
    if (ep.status === 'open') {
      out += `  * Port ${ep.port}/tcp: [OPEN] Service: ${ep.service_name} (Confidence: ${ep.confidence})\n`;
      if (ep.evidence) out += `    Evidence: ${ep.evidence}\n`;
    }
  }

  if (report.tls_assessment) {
    const tls = report.tls_assessment;
    out += `\n--- TLS POSTURE (Port ${tls.target_port}) ---\n`;
    out += `  * Version:          ${tls.negotiated_version || 'None'}\n`;
    out += `  * Trust Status:     ${tls.trust_status}\n`;
    out += `  * Hostname Match:   ${tls.hostname_matched}\n`;
    if (tls.leaf_certificate) {
      out += `  * Common Name:      ${tls.leaf_certificate.common_name || 'N/A'}\n`;
      out += `  * Expiration:       ${tls.leaf_certificate.days_until_expiration} days remaining\n`;
    }
  }

  if (report.http_assessment) {
    const http = report.http_assessment;
    out += `\n--- HTTP POSTURE ---\n`;
    out += `  * HTTPS Available:  ${http.https_available}\n`;
    out += `  * HTTP->HTTPS Redir: ${http.http_to_https_redirect}\n`;
    out += `  * HSTS Enabled:     ${http.hsts_enabled}\n`;
    out += `  * CSP Present:      ${http.csp_present}\n`;
    out += `  * XCTO nosniff:     ${http.x_content_type_options_nosniff}\n`;
    if (http.server_header) out += `  * Server Banner:    ${http.server_header}\n`;
  }

  out += `\n--- SECURITY FINDINGS (${report.findings.length}) ---\n`;
  if (report.findings.length === 0) {
    out += `  [+] No perimeter vulnerabilities or insecure configurations detected.\n`;
  } else {
    for (const f of report.findings) {
      out += `  [${f.severity.toUpperCase()}] ${f.id} - ${f.title}\n`;
      out += `    Category: ${f.category}\n`;
      out += `    Endpoint: ${f.endpoint}\n`;
      out += `    Evidence: ${f.evidence}\n`;
      out += `    Action:   ${f.recommendation}\n\n`;
    }
  }

  out += `\n[!] ${report.architecture_disclaimer}\n`;
  if (consoleEl) consoleEl.textContent = out;
};

window.onPerimeterAssessmentFailed = function(data) {
  hideProgress();
  const consoleEl = document.getElementById('remote-scan-console');
  const badgeEl = document.getElementById('remote-scan-status-badge');
  if (badgeEl) {
    badgeEl.className = 'terminal-badge';
    badgeEl.style.color = 'var(--accent-red)';
    badgeEl.textContent = 'PROHIBITED / FAILED';
  }

  let out = `[!] PERIMETER ASSESSMENT REJECTED / FAILED\n`;
  out += `[*] Target: ${data.target}\n`;
  out += `[*] Reason: ${data.error}\n\n`;
  out += `[!] The target violates declared scope authorization, anti-SSRF protections, or network connectivity constraints.\n`;
  if (consoleEl) consoleEl.textContent = out;
};
}

function showRemoteScanNotice() {
  startRemoteScan();
}

// Segmented Profile Switcher
function setProfile(profile) {
  if (currentProfile === profile) return;
  currentProfile = profile;
  document.querySelectorAll('.segmented-group button[data-profile]').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.profile === profile);
  });
  runAudit();
}

// Progress Bar Controller
function showProgress(stageText, percent) {
  const container = document.getElementById('audit-progress-container');
  const stageEl = document.getElementById('progress-stage-text');
  const percentEl = document.getElementById('progress-percent-text');
  const fillEl = document.getElementById('progress-fill');

  if (container) container.style.display = 'block';
  if (stageEl) stageEl.textContent = stageText;
  if (percentEl) percentEl.textContent = `${percent}%`;
  if (fillEl) fillEl.style.width = `${percent}%`;
}

function hideProgress() {
  const container = document.getElementById('audit-progress-container');
  if (container) {
    container.style.opacity = '0';
    setTimeout(() => {
      container.style.display = 'none';
      container.style.opacity = '1';
    }, 300);
  }
}

// Trigger Audit Scan
function runAudit() {
  const btn = document.getElementById('btn-run-audit');
  const icon = document.getElementById('btn-run-icon');
  const text = document.getElementById('btn-run-text');
  const statusPill = document.getElementById('scan-status-pill');

  if (btn) btn.disabled = true;
  if (icon) {
    icon.innerHTML = `<path d="M21 12a9 9 0 1 1-6.219-8.56"/>`;
    icon.classList.add('spinner');
  }
  if (text) text.textContent = 'Scanning...';

  scanStartTime = Date.now();
  if (statusPill) {
    statusPill.innerHTML = `<span class="status-dot amber"></span> <span id="status-timer">Scanning (0ms)...</span>`;
  }

  showProgress('Initializing native in-process engine...', 15);

  if (scanTimerInterval) clearInterval(scanTimerInterval);
  scanTimerInterval = setInterval(() => {
    const elapsed = Date.now() - scanStartTime;
    const timerEl = document.getElementById('status-timer');
    if (timerEl) timerEl.textContent = `Scanning (${elapsed}ms)...`;

    if (elapsed > 40 && elapsed <= 100) {
      showProgress('Querying macOS telemetry (SIP, Firewall, Gatekeeper)...', 42);
    } else if (elapsed > 100 && elapsed <= 180) {
      showProgress('Evaluating 11 built-in macOS security rules...', 72);
    } else if (elapsed > 180) {
      showProgress('Synthesizing findings & verifying telemetry payloads...', 90);
    }
  }, 25);

  setTimeout(() => {
    sendIpc('run_audit', { profile: currentProfile });
  }, 40);
}

// IPC Callbacks called from Rust
window.onAuditComplete = function(report) {
  if (scanTimerInterval) {
    clearInterval(scanTimerInterval);
    scanTimerInterval = null;
  }

  currentReport = report;
  showProgress(`Audit complete (${report.duration_ms}ms) &bull; ${report.findings.length} findings`, 100);
  setTimeout(hideProgress, 950);

  const btn = document.getElementById('btn-run-audit');
  const icon = document.getElementById('btn-run-icon');
  const text = document.getElementById('btn-run-text');
  const statusPill = document.getElementById('scan-status-pill');

  if (btn) btn.disabled = false;
  if (icon) {
    icon.innerHTML = `<polygon points="5 3 19 12 5 21 5 3"/>`;
    icon.classList.remove('spinner');
  }
  if (text) text.textContent = 'Run Audit';

  if (statusPill) {
    const count = report.findings.length;
    const dotColor = count > 0 ? 'amber' : 'green';
    statusPill.innerHTML = `<span class="status-dot ${dotColor}"></span> Completed (${report.duration_ms}ms)`;
  }

  updateKpis(report);
  renderOverview(report);
  renderFindings(report);
  renderReportPreview(report);
};

window.onSystemInfoLoaded = function(info) {
  systemInfo = info;
  const osEl = document.getElementById('meta-os');
  if (osEl) osEl.textContent = `${info.pretty_name} (${info.arch})`;
  const diagEl = document.getElementById('diag-platform');
  if (diagEl) diagEl.textContent = `${info.pretty_name} (${info.arch})`;
};

function recheckPermissions() {
  const indicator = document.getElementById('perms-live-indicator');
  if (indicator) indicator.textContent = 'Checking...';
  sendIpc('get_permissions');
  showToast('Re-checking macOS system permissions & TCC state...');
}

window.onPermissionsLoaded = function(perms) {
  systemPermissions = perms;

  const fdaBadge = document.getElementById('fda-status-badge');
  const fdaBanner = document.getElementById('fda-warning-banner');
  if (fdaBadge) {
    if (perms.full_disk_access) {
      fdaBadge.textContent = 'GRANTED';
      fdaBadge.className = 'badge badge-pass';
      if (fdaBanner) fdaBanner.style.display = 'none';
    } else {
      fdaBadge.textContent = 'NOT GRANTED (TCC RESTRICTED)';
      fdaBadge.className = 'badge badge-high';
      if (fdaBanner) fdaBanner.style.display = 'flex';
    }
  }

  const sipBadge = document.getElementById('sip-status-badge');
  if (sipBadge) {
    if (perms.sip_active) {
      sipBadge.textContent = 'ACTIVE (KERNEL ENFORCED)';
      sipBadge.className = 'badge badge-pass';
    } else {
      sipBadge.textContent = 'DISABLED';
      sipBadge.className = 'badge badge-crit';
    }
  }

  const indicator = document.getElementById('perms-live-indicator');
  if (indicator) {
    indicator.textContent = '\u25cf Live Diagnostics';
    indicator.style.color = 'var(--accent-green)';
  }

  const privMeta = document.getElementById('meta-priv');
  if (privMeta) privMeta.textContent = perms.privilege;

  const privBadge = document.getElementById('settings-priv-badge');
  if (privBadge) {
    privBadge.textContent = perms.privilege.toUpperCase();
    privBadge.className = perms.is_root ? 'badge badge-pass' : 'badge badge-neutral';
  }

  const uidEl = document.getElementById('settings-uid');
  if (uidEl) uidEl.textContent = perms.uid;
  const userEl = document.getElementById('settings-user');
  if (userEl) userEl.textContent = perms.username;
  const effEl = document.getElementById('settings-effective');
  if (effEl) effEl.textContent = perms.privilege;
};

window.onRulesLoaded = function(rules) {
  currentRules = rules;
  renderRulesTable(rules);
  const countEl = document.getElementById('diag-rules-count');
  if (countEl) {
    const macRules = rules.filter(r => (r.target_platforms || []).includes('MacOS')).length;
    const linuxRules = rules.filter(r => (r.target_platforms || []).includes('Linux')).length;
    const winRules = rules.filter(r => (r.target_platforms || []).includes('Windows')).length;
    countEl.innerHTML = `
      <span class="tech-pill" style="color: var(--accent-green); background: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.2); font-weight: 600;">${macRules} macOS Controls (Active on this Mac)</span>
      <span class="tech-pill" style="color: var(--text-muted);">${linuxRules} Linux Server Rules</span>
      <span class="tech-pill" style="color: var(--text-muted);">${winRules} Windows Server Rules</span>
      <span style="font-size: 11px; color: var(--text-faint); margin-left: 4px;">(${rules.length} Total Isolated Rules)</span>
    `;
  }
};

window.onReportExported = function(path) {
  showToast(`Report exported to: ${path}`);
};

// Render KPI Cards (Linear/Stripe standard)
function updateKpis(report) {
  const totalEl = document.getElementById('kpi-total');
  if (totalEl) totalEl.textContent = report.findings.length;

  const critHigh = report.summary.critical + report.summary.high;
  const critHighEl = document.getElementById('kpi-crit-high');
  if (critHighEl) {
    critHighEl.textContent = critHigh;
    critHighEl.className = `kpi-stat-text ${critHigh > 0 ? 'high' : 'green'}`;
  }

  const privEl = document.getElementById('kpi-privilege');
  if (privEl) privEl.textContent = report.current_privilege;

  const durEl = document.getElementById('kpi-duration');
  if (durEl) durEl.textContent = `${report.duration_ms}ms`;

  const navBadge = document.getElementById('nav-findings-badge');
  if (navBadge) {
    if (report.findings.length > 0) {
      navBadge.textContent = report.findings.length;
      navBadge.style.display = 'inline-flex';
    } else {
      navBadge.style.display = 'none';
    }
  }
}

// Render Overview View
function renderOverview(report) {
  const container = document.getElementById('overview-findings-preview');
  if (!container) return;

  if (report.findings.length === 0) {
    container.innerHTML = `
      <div class="weight-row boost" style="cursor: default;">
        <div class="finding-title-group">
          <div class="finding-heading">No Policy Violations Detected</div>
          <div class="finding-subtext">All evaluated host controls satisfy ${currentProfile} security standards.</div>
        </div>
        <span class="badge badge-pass">CLEAN PASS</span>
      </div>
    `;
    return;
  }

  container.innerHTML = report.findings.map(item => {
    const f = item.finding;
    const sev = f.severity.toUpperCase();
    const penaltyClass = `penalty-${f.severity.toLowerCase()}`;
    const badgeClass = `badge-${f.severity.toLowerCase().slice(0, 4)}`;
    return `
      <div class="weight-row ${penaltyClass}" onclick="inspectFinding('${f.rule_id}')">
        <div class="finding-title-group" style="flex: 1; padding-right: 12px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 2px;">
            <span class="badge ${badgeClass}">${sev}</span>
            <span class="finding-heading">${escapeHtml(f.title)}</span>
          </div>
          <div class="finding-subtext">${escapeHtml(f.description)}</div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
            Target: <code class="tech-pill">${escapeHtml(item.target)}</code> &bull; Rule: <code class="tech-pill">${escapeHtml(f.rule_id)}</code>
          </div>
        </div>
        <button class="btn btn-sm" onclick="inspectFinding('${f.rule_id}'); event.stopPropagation();">
          Inspect Evidence
          <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
        </button>
      </div>
    `;
  }).join('');
}

// Render Master-Detail Findings View
function renderFindings(report) {
  const list = document.getElementById('findings-list');
  if (!list) return;

  const counts = {
    all: report.findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  report.findings.forEach(item => {
    const sev = item.finding.severity.toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  });

  const countAll = document.getElementById('count-all');
  if (countAll) countAll.textContent = counts.all;
  const countCrit = document.getElementById('count-crit');
  if (countCrit) countCrit.textContent = counts.critical;
  const countHigh = document.getElementById('count-high');
  if (countHigh) countHigh.textContent = counts.high;
  const countMed = document.getElementById('count-med');
  if (countMed) countMed.textContent = counts.medium;
  const countLow = document.getElementById('count-low');
  if (countLow) countLow.textContent = counts.low;

  const filtered = report.findings.filter(item => {
    const f = item.finding;
    const matchSev = currentFilter === 'all' || f.severity.toLowerCase() === currentFilter;
    const q = findingsSearchQuery.toLowerCase();
    const matchSearch = !q || f.title.toLowerCase().includes(q) || f.rule_id.toLowerCase().includes(q) || item.target.toLowerCase().includes(q);
    return matchSev && matchSearch;
  });

  if (filtered.length === 0) {
    list.innerHTML = `<div style="text-align:center; padding: 40px; color: var(--text-faint);">No findings match the current filter.</div>`;
    return;
  }

  list.innerHTML = filtered.map(item => {
    const f = item.finding;
    const sev = f.severity.toUpperCase();
    const penaltyClass = `penalty-${f.severity.toLowerCase()}`;
    const badgeClass = `badge-${f.severity.toLowerCase().slice(0, 4)}`;
    const isActive = selectedFindingRuleId === f.rule_id ? 'active' : '';

    return `
      <div class="weight-row ${penaltyClass} ${isActive}" data-rule-id="${escapeHtml(f.rule_id)}" onclick="selectFindingRow('${f.rule_id}')">
        <div style="flex: 1; padding-right: 8px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 2px;">
            <span class="badge ${badgeClass}">${sev}</span>
            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(f.rule_id)}</span>
          </div>
          <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 2px;">${escapeHtml(f.title)}</div>
          <div style="font-size: 11px; color: var(--text-secondary);">Target: <code class="tech-pill">${escapeHtml(item.target)}</code></div>
        </div>
      </div>
    `;
  }).join('');

  // Default selection
  if (filtered.length > 0) {
    const defaultRuleId = selectedFindingRuleId && filtered.some(i => i.finding.rule_id === selectedFindingRuleId)
      ? selectedFindingRuleId
      : filtered[0].finding.rule_id;
    selectFindingRow(defaultRuleId);
  }
}

function selectFindingRow(ruleId) {
  selectedFindingRuleId = ruleId;

  document.querySelectorAll('#findings-list .weight-row').forEach(row => {
    row.classList.toggle('active', row.dataset.ruleId === ruleId);
  });

  if (!currentReport) return;
  const item = currentReport.findings.find(f => f.finding.rule_id === ruleId);
  if (!item) return;

  const f = item.finding;
  const sev = f.severity.toUpperCase();
  const badgeClass = `badge-${f.severity.toLowerCase().slice(0, 4)}`;

  const badgeEl = document.getElementById('detail-sev-badge');
  if (badgeEl) {
    badgeEl.textContent = sev;
    badgeEl.className = `badge ${badgeClass}`;
  }

  const ruleIdEl = document.getElementById('detail-rule-id');
  if (ruleIdEl) ruleIdEl.textContent = f.rule_id;

  const titleEl = document.getElementById('detail-title');
  if (titleEl) titleEl.textContent = f.title;

  const targetEl = document.getElementById('detail-target');
  if (targetEl) targetEl.textContent = `Target: ${item.target}`;

  const descEl = document.getElementById('detail-desc');
  if (descEl) descEl.textContent = f.description;

  const remEl = document.getElementById('detail-rem');
  if (remEl) remEl.textContent = f.remediation;

  const remCmdEl = document.getElementById('detail-rem-cmd');
  if (remCmdEl) {
    if (f.rule_id === 'macos.firewall.disabled') {
      remCmdEl.textContent = 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on';
    } else if (f.rule_id === 'macos.remote.login-enabled') {
      remCmdEl.textContent = 'sudo systemsetup -setremotelogin off';
    } else if (f.rule_id.includes('launchd')) {
      remCmdEl.textContent = 'sudo chmod 644 /Library/LaunchDaemons/*.plist';
    } else {
      remCmdEl.textContent = `openaudit-cli remediate --rule ${f.rule_id}`;
    }
  }

  const payloadEl = document.getElementById('detail-payload');
  if (payloadEl) {
    let evidenceText = '';
    if (item.evidence && item.evidence.payload) {
      evidenceText = typeof item.evidence.payload.data === 'string'
        ? item.evidence.payload.data
        : JSON.stringify(item.evidence.payload.data, null, 2);
    } else {
      evidenceText = '// No raw evidence attached';
    }
    payloadEl.textContent = evidenceText;
  }
}

function inspectFinding(ruleId) {
  showTab('findings');
  selectFindingRow(ruleId);
}

function onSearchFindings() {
  const input = document.getElementById('findings-search');
  findingsSearchQuery = input ? input.value : '';
  if (currentReport) renderFindings(currentReport);
}

function copyRemediationCmd() {
  const cmd = document.getElementById('detail-rem-cmd');
  if (cmd) {
    navigator.clipboard.writeText(cmd.textContent);
    showToast('Copied remediation command to clipboard');
  }
}

// Render Rule Catalog Table (Strictly isolated by OS platform)
function renderRulesTable(rules) {
  const tbody = document.getElementById('rules-tbody');
  const footerLabel = document.getElementById('rules-count-label');
  const scopeTitle = document.getElementById('platform-scope-title');
  const scopeDesc = document.getElementById('platform-scope-desc');
  const scopeBanner = document.getElementById('platform-scope-banner');
  if (!tbody) return;

  const q = rulesSearchQuery.toLowerCase();
  const filtered = rules.filter(r => {
    const plats = r.target_platforms || r.platforms || [];
    const matchPlat = currentPlatformFilter === 'all' || plats.includes(currentPlatformFilter);
    const matchSearch = !q || r.id.toLowerCase().includes(q) || r.title.toLowerCase().includes(q);
    return matchPlat && matchSearch;
  });

  // Update scope banner metadata per platform
  if (scopeTitle && scopeDesc) {
    if (currentPlatformFilter === 'MacOS') {
      scopeTitle.textContent = 'macOS Native Security Controls (11 Rules \u2022 Active Host Posture)';
      scopeDesc.textContent = 'Evaluated locally against this macOS workstation via direct in-process telemetry (SIP, FileVault, Gatekeeper, Application Firewall, LaunchDaemons, TCC).';
      if (scopeBanner) scopeBanner.className = 'weight-row boost';
    } else if (currentPlatformFilter === 'Linux') {
      scopeTitle.textContent = 'Linux Server Hardening Controls (20 Rules \u2022 Dedicated Server Scope)';
      scopeDesc.textContent = 'Evaluated on Linux enterprise servers via headless openaudit-cli or enrolled agent (SSH daemon hardening, root privilege boundaries, sudoers, sysctl).';
      if (scopeBanner) scopeBanner.className = 'weight-row';
    } else if (currentPlatformFilter === 'Windows') {
      scopeTitle.textContent = 'Windows Server Hardening Controls (12 Rules \u2022 Dedicated Server Scope)';
      scopeDesc.textContent = 'Evaluated on Windows enterprise servers via headless openaudit-cli or enrolled agent (Microsoft Defender, Windows Firewall, LSA Protection, Registry hardening).';
      if (scopeBanner) scopeBanner.className = 'weight-row';
    } else {
      scopeTitle.textContent = 'Built-in Security Rule Registry (43 Rules Partitioned by OS)';
      scopeDesc.textContent = 'Strictly partitioned by operating system: 11 macOS host rules, 20 Linux server rules, and 12 Windows server rules. Rules are isolated and never run on incompatible platforms.';
      if (scopeBanner) scopeBanner.className = 'weight-row';
    }
  }

  if (footerLabel) {
    footerLabel.textContent = `Showing ${filtered.length} of ${rules.length} total rules`;
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 24px; color: var(--text-faint);">No rules match the current filter.</td></tr>`;
    return;
  }

  const renderRuleRow = (r) => {
    const plats = r.target_platforms || r.platforms || [];
    const isMac = plats.includes('MacOS');
    const isLinux = plats.includes('Linux');
    const isWin = plats.includes('Windows');

    let platBadge = '';
    if (isMac) {
      platBadge = '<span class="badge badge-pass">macOS Native &bull; Active</span>';
    } else if (isLinux) {
      platBadge = '<span class="badge badge-low">Linux Server &bull; Remote/CLI</span>';
    } else if (isWin) {
      platBadge = '<span class="badge badge-med">Windows Server &bull; Remote/CLI</span>';
    } else {
      platBadge = `<span class="badge badge-neutral">${plats.join(', ')}</span>`;
    }

    const sev = r.severity.toUpperCase();
    const sevClass = `badge-${r.severity.toLowerCase().slice(0, 4)}`;
    return `
      <tr>
        <td><code class="tech-pill">${escapeHtml(r.id)}</code></td>
        <td><strong>${escapeHtml(r.title)}</strong></td>
        <td><span class="badge ${sevClass}">${sev}</span></td>
        <td><span class="tech-pill">${r.privilege}</span></td>
        <td><span class="tech-pill">${r.profile}</span></td>
        <td>${platBadge}</td>
      </tr>
    `;
  };

  if (currentPlatformFilter === 'all') {
    // Partition rules by OS platform with clear section headers
    const macRules = filtered.filter(r => (r.target_platforms || []).includes('MacOS'));
    const linuxRules = filtered.filter(r => (r.target_platforms || []).includes('Linux'));
    const winRules = filtered.filter(r => (r.target_platforms || []).includes('Windows'));

    let html = '';
    if (macRules.length > 0) {
      html += `<tr style="background: var(--bg-subtle);"><td colspan="6" style="padding: 10px 14px; font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-green); border-bottom: 1px solid var(--border-light);"><span class="badge badge-pass" style="margin-right: 8px;">macOS Native Scope</span> 11 Active Host Controls (Evaluated on this Workstation)</td></tr>`;
      html += macRules.map(renderRuleRow).join('');
    }
    if (linuxRules.length > 0) {
      html += `<tr style="background: var(--bg-subtle);"><td colspan="6" style="padding: 10px 14px; font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-blue); border-bottom: 1px solid var(--border-light);"><span class="badge badge-low" style="margin-right: 8px;">Linux Server Scope</span> 20 Server Hardening Rules (Evaluated via Headless CLI / Remote Agent)</td></tr>`;
      html += linuxRules.map(renderRuleRow).join('');
    }
    if (winRules.length > 0) {
      html += `<tr style="background: var(--bg-subtle);"><td colspan="6" style="padding: 10px 14px; font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-amber); border-bottom: 1px solid var(--border-light);"><span class="badge badge-med" style="margin-right: 8px;">Windows Server Scope</span> 12 Server Hardening Rules (Evaluated via Headless CLI / Remote Agent)</td></tr>`;
      html += winRules.map(renderRuleRow).join('');
    }
    tbody.innerHTML = html;
  } else {
    tbody.innerHTML = filtered.map(renderRuleRow).join('');
  }
}

function onSearchRules() {
  const input = document.getElementById('rules-search');
  rulesSearchQuery = input ? input.value : '';
  renderRulesTable(currentRules);
}

function filterRulesPlatform(platform) {
  currentPlatformFilter = platform;
  document.querySelectorAll('.rule-plat-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.platform === platform);
  });
  renderRulesTable(currentRules);
}

// Render HTML Report Preview
function renderReportPreview(report) {
  const frame = document.getElementById('report-iframe');
  if (!frame) return;
  sendIpc('get_html_report', { report: report });
}

window.onHtmlReportReady = function(html) {
  const frame = document.getElementById('report-iframe');
  if (frame) {
    frame.srcdoc = html;
  }
};

function exportReport() {
  if (currentReport) {
    sendIpc('export_html', { report: currentReport });
  }
}

function openExportedReport() {
  sendIpc('open_report_file', { report: currentReport });
}

function openSystemSettings(pane) {
  sendIpc('open_system_settings', { pane: pane });
}

function filterFindings(sev) {
  currentFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.severity === sev);
  });
  if (currentReport) renderFindings(currentReport);
}

function showToast(msg) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> ${escapeHtml(msg)}`;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 200);
  }, 3500);
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function clearInput(id) {
  const el = document.getElementById(id);
  if (el) {
    el.value = '';
    el.focus();
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

function pasteToTarget(id) {
  const el = document.getElementById(id);
  if (el) {
    el.focus();
    sendIpc('clipboard_paste');
  }
}

window.onNativeClipboardPaste = function(text) {
  if (typeof text !== 'string') return;
  const el = document.activeElement;
  if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
    const start = el.selectionStart !== undefined ? el.selectionStart : el.value.length;
    const end = el.selectionEnd !== undefined ? el.selectionEnd : el.value.length;
    const before = el.value.substring(0, start);
    const after = el.value.substring(end);
    el.value = before + text + after;
    el.selectionStart = el.selectionEnd = start + text.length;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
};

// Keyboard Shortcuts for Accessibility & Navigation (Capture Phase for WebView)
document.addEventListener('keydown', (e) => {
  const isInput = document.activeElement && (
    document.activeElement.tagName === 'INPUT' ||
    document.activeElement.tagName === 'TEXTAREA' ||
    document.activeElement.isContentEditable
  );

  const isCmdOrCtrl = e.metaKey || e.ctrlKey;
  const isBackspace = e.key === 'Backspace' || e.code === 'Backspace';
  const isDelete = e.key === 'Delete' || e.code === 'Delete';

  // 1. Backspace and Delete handling for inputs (including range selection and Cmd/Alt modifiers)
  if (isInput && (isBackspace || isDelete)) {
    const el = document.activeElement;
    if (el && el.selectionStart !== undefined) {
      const start = el.selectionStart;
      const end = el.selectionEnd;

      if (start !== end) {
        // Range selected (e.g. Cmd+A): delete the selected range
        e.preventDefault();
        e.stopPropagation();
        el.value = el.value.substring(0, start) + el.value.substring(end);
        el.selectionStart = el.selectionEnd = start;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        return;
      } else if (isBackspace) {
        if (isCmdOrCtrl) {
          // Cmd+Backspace: delete from start of input to cursor
          e.preventDefault();
          e.stopPropagation();
          el.value = el.value.substring(start);
          el.selectionStart = el.selectionEnd = 0;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          return;
        } else if (e.altKey) {
          // Alt+Backspace: delete word backward
          e.preventDefault();
          e.stopPropagation();
          const before = el.value.substring(0, start);
          const trimmedBefore = before.replace(/\s+$/, '');
          const lastSpace = trimmedBefore.lastIndexOf(' ');
          const cutIdx = lastSpace === -1 ? 0 : lastSpace + 1;
          el.value = el.value.substring(0, cutIdx) + el.value.substring(start);
          el.selectionStart = el.selectionEnd = cutIdx;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          return;
        } else if (start > 0) {
          // Single character backspace
          e.preventDefault();
          e.stopPropagation();
          el.value = el.value.substring(0, start - 1) + el.value.substring(start);
          el.selectionStart = el.selectionEnd = start - 1;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          return;
        }
      } else if (isDelete) {
        if (start < el.value.length) {
          // Forward delete
          e.preventDefault();
          e.stopPropagation();
          el.value = el.value.substring(0, start) + el.value.substring(start + 1);
          el.selectionStart = el.selectionEnd = start;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          return;
        }
      }
    }
  }

  // 2. Universal Edit Shortcuts (Select All, Copy, Cut, Paste) in WebView
  if (isCmdOrCtrl) {
    const isA = e.key === 'a' || e.key === 'A' || e.code === 'KeyA';
    const isC = e.key === 'c' || e.key === 'C' || e.code === 'KeyC';
    const isX = e.key === 'x' || e.key === 'X' || e.code === 'KeyX';
    const isV = e.key === 'v' || e.key === 'V' || e.code === 'KeyV';

    if (isA && isInput) {
      e.preventDefault();
      e.stopPropagation();
      const el = document.activeElement;
      if (typeof el.select === 'function') {
        el.select();
      } else if (typeof el.setSelectionRange === 'function') {
        el.setSelectionRange(0, el.value.length);
      }
      return;
    } else if (isC) {
      let sel = '';
      if (isInput && document.activeElement && document.activeElement.selectionStart !== undefined) {
        const el = document.activeElement;
        sel = el.value ? el.value.substring(el.selectionStart, el.selectionEnd) : '';
      }
      if (!sel) {
        sel = window.getSelection() ? window.getSelection().toString() : '';
      }
      if (sel) {
        sendIpc('clipboard_copy', { text: sel });
        try { navigator.clipboard.writeText(sel); } catch (_) {}
      }
      return;
    } else if (isX && isInput) {
      const el = document.activeElement;
      if (el && el.selectionStart !== undefined && el.selectionStart !== el.selectionEnd) {
        const start = el.selectionStart;
        const end = el.selectionEnd;
        const sel = el.value.substring(start, end);
        sendIpc('clipboard_copy', { text: sel });
        try { navigator.clipboard.writeText(sel); } catch (_) {}
        el.value = el.value.substring(0, start) + el.value.substring(end);
        el.selectionStart = el.selectionEnd = start;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        e.preventDefault();
        e.stopPropagation();
      }
      return;
    } else if (isV && isInput) {
      e.preventDefault();
      e.stopPropagation();
      if (navigator.clipboard && navigator.clipboard.readText) {
        navigator.clipboard.readText().then(text => {
          if (text) {
            window.onNativeClipboardPaste(text);
          } else {
            sendIpc('clipboard_paste');
          }
        }).catch(() => {
          sendIpc('clipboard_paste');
        });
      } else {
        sendIpc('clipboard_paste');
      }
      return;
    }

    // Navigation Shortcuts (Disabled while typing in inputs)
    if (!isInput) {
      if (e.key === '1') { e.preventDefault(); showTab('overview'); }
      else if (e.key === '2') { e.preventDefault(); showTab('remote'); }
      else if (e.key === '3') { e.preventDefault(); showTab('enrolled'); }
      else if (e.key === '4') { e.preventDefault(); showTab('findings'); }
      else if (e.key === '5') { e.preventDefault(); showTab('rules'); }
      else if (e.key === '6') { e.preventDefault(); showTab('report'); }
      else if (e.key === '7') { e.preventDefault(); showTab('settings'); }
      else if (e.key.toLowerCase() === 'r') { e.preventDefault(); runAudit(); }
    }
  } else if (e.altKey && !isInput) {
    if (e.key === '1') { e.preventDefault(); filterRulesPlatform('MacOS'); }
    else if (e.key === '2') { e.preventDefault(); filterRulesPlatform('Linux'); }
    else if (e.key === '3') { e.preventDefault(); filterRulesPlatform('Windows'); }
    else if (e.key === '4') { e.preventDefault(); filterRulesPlatform('all'); }
  }
}, true);

// Initial Bootstrapping
function bootstrap() {
  try {
    initTheme();
    setTimeout(() => {
      try {
        sendIpc('get_system_info');
        sendIpc('get_permissions');
        sendIpc('get_rules');
        runAudit();
      } catch (err) {
        document.title = `ERR_TIMEOUT: ${err}`;
      }
    }, 100);
  } catch (e) {
    document.title = `ERR_BOOTSTRAP: ${e}`;
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootstrap);
} else {
  bootstrap();
}
