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

  if (tabId === 'settings') {
    sendIpc('get_permissions');
  } else if (tabId === 'rules') {
    if (currentRules.length === 0) sendIpc('get_rules');
  } else if (tabId === 'report') {
    if (currentReport) renderReportPreview(currentReport);
  }
}

function showRemoteScanNotice() {
  const target = (document.getElementById('remote-target-input')?.value || '192.0.2.10').trim();
  const auth = document.getElementById('remote-auth-check')?.checked;
  if (!auth) {
    alert('Explicit Authorization Required: You must certify that you are authorized to assess target ' + target + ' prior to scanning.');
    return;
  }
  alert('Milestone 4 Roadmap Boundary:\n\nTarget ' + target + ' is queued for Agentless Remote Network Assessment.\n\nPerimeter scanning (DNS, TLS, HTTP security headers, and SSRF defenses) is scheduled for Milestone 4.\n\nImportant Security Boundary: An IP address alone cannot perform an operating system audit. Internal accounts, packages, permissions, and kernel settings require local host execution or enrolled OpenAudit agents.');
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
    countEl.textContent = `${macRules} macOS Native Controls (Active) \u2022 ${linuxRules} Linux Server Rules \u2022 ${winRules} Windows Server Rules (${rules.length} Total)`;
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
      scopeTitle.textContent = 'macOS Native Security Controls (Active on this Host)';
      scopeDesc.textContent = '11 native host posture checks evaluated directly via Apple Silicon telemetry (SIP, FileVault, Gatekeeper, Firewall, LaunchDaemons).';
      if (scopeBanner) scopeBanner.className = 'weight-row boost';
    } else if (currentPlatformFilter === 'Linux') {
      scopeTitle.textContent = 'Linux Server Security Controls (Clean Isolation)';
      scopeDesc.textContent = '20 native rules evaluating SSH daemon hardening, sudoers, world-writable sysctl, and user boundaries (Executed via openaudit-cli on Linux servers or remote agent).';
      if (scopeBanner) scopeBanner.className = 'weight-row';
    } else if (currentPlatformFilter === 'Windows') {
      scopeTitle.textContent = 'Windows Server Security Controls (Clean Isolation)';
      scopeDesc.textContent = '12 native rules evaluating Windows Defender, Advanced Firewall, LSA Protection, and Registry hardening (Executed via openaudit-cli on Windows or remote agent).';
      if (scopeBanner) scopeBanner.className = 'weight-row';
    } else {
      scopeTitle.textContent = 'Complete Built-in Security Rule Registry (All Platforms)';
      scopeDesc.textContent = '43 total security rules strictly scoped across macOS host (11), Linux servers (20), and Windows servers (12). Rules never cross platform boundaries.';
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

  tbody.innerHTML = filtered.map(r => {
    const plats = r.target_platforms || r.platforms || [];
    const isMac = plats.includes('MacOS');
    const isLinux = plats.includes('Linux');
    const isWin = plats.includes('Windows');

    let platBadge = '';
    if (isMac) {
      platBadge = '<span class="badge badge-pass">macOS &bull; Active</span>';
    } else if (isLinux) {
      platBadge = '<span class="badge badge-low">Linux Server</span>';
    } else if (isWin) {
      platBadge = '<span class="badge badge-med">Windows Server</span>';
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
  }).join('');
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
