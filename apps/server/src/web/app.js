/**
 * OpenAudit Operator Web Application
 * Self-hosted Control Plane Frontend (Milestone 8)
 * Linear / Stripe / Vercel monochrome design system
 */

(function () {
  'use strict';

  // State Management
  const state = {
    token: localStorage.getItem('openaudit_token') || null,
    user: null,
    currentView: 'posture',
    pollInterval: null,
    selectedFindingId: null,
    cachedJobs: [],
    cachedAssets: [],
  };

  // DOM Elements Cache
  const el = {
    authContainer: document.getElementById('auth-container'),
    appShell: document.getElementById('app-shell'),
    viewBootstrap: document.getElementById('view-bootstrap'),
    viewLogin: document.getElementById('view-login'),
    headerTenantName: document.getElementById('header-tenant-name'),
    headerUserEmail: document.getElementById('header-user-email'),
    headerUserRole: document.getElementById('header-user-role'),
    navItemUsersWrapper: document.getElementById('nav-item-users-wrapper'),
    toastContainer: document.getElementById('toast-container'),
  };

  // Toast System
  function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.2s';
      setTimeout(() => toast.remove(), 250);
    }, 3500);
  }

  // Safe HTML Escaping
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // API Fetch Utility
  async function apiFetch(endpoint, options = {}) {
    const headers = options.headers || {};
    if (state.token) {
      headers['Authorization'] = `Bearer ${state.token}`;
    }
    if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.body);
    }
    options.headers = headers;

    const res = await fetch(endpoint, options);
    if (res.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/bootstrap')) {
      handleUnauthorized();
      throw new Error('Session expired or unauthorized');
    }
    return res;
  }

  function handleUnauthorized() {
    state.token = null;
    state.user = null;
    localStorage.removeItem('openaudit_token');
    showAuthView('login');
  }

  // Authentication Flow
  async function checkSession() {
    if (!state.token) {
      showAuthView(window.location.hash === '#setup' ? 'setup' : 'login');
      return;
    }

    try {
      const res = await apiFetch('/api/v1/auth/me');
      if (res.ok) {
        const data = await res.json();
        state.user = data.user;
        setupAuthenticatedShell(data);
      } else {
        handleUnauthorized();
      }
    } catch (e) {
      handleUnauthorized();
    }
  }

  function showAuthView(viewName) {
    if (state.pollInterval) clearInterval(state.pollInterval);
    el.appShell.style.display = 'none';
    el.authContainer.style.display = 'flex';

    if (viewName === 'setup') {
      el.viewBootstrap.style.display = 'block';
      el.viewLogin.style.display = 'none';
      window.location.hash = '#setup';
    } else {
      el.viewBootstrap.style.display = 'none';
      el.viewLogin.style.display = 'block';
      window.location.hash = '#login';
    }
  }

  function setupAuthenticatedShell(userData) {
    el.authContainer.style.display = 'none';
    el.appShell.style.display = 'flex';

    const user = userData.user;
    el.headerUserEmail.textContent = user.email;
    el.headerUserRole.textContent = user.role.toUpperCase();
    el.headerUserRole.className = `badge ${user.role === 'admin' ? 'badge-critical' : user.role === 'auditor' ? 'badge-blue' : 'badge-subtle'}`;
    el.headerTenantName.textContent = `Tenant: ${userData.org_slug || 'Default'}`;

    if (user.role !== 'admin') {
      el.navItemUsersWrapper.style.display = 'none';
    } else {
      el.navItemUsersWrapper.style.display = 'block';
    }

    // Determine initial view from hash
    const initialView = window.location.hash.replace('#', '') || 'posture';
    if (['posture', 'assets', 'assessments', 'findings', 'compare', 'agents', 'users'].includes(initialView)) {
      switchView(initialView);
    } else {
      switchView('posture');
    }

    // Start background poller for active scans
    startBackgroundPoller();
  }

  // View Navigation Switcher
  function switchView(viewName) {
    state.currentView = viewName;
    window.location.hash = `#${viewName}`;

    // Update Sidebar Active Class
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.dataset.view === viewName) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Update Panels
    document.querySelectorAll('.view-panel').forEach(panel => {
      if (panel.id === `view-${viewName}`) {
        panel.classList.add('active');
      } else {
        panel.classList.remove('active');
      }
    });

    // Load Data for Selected View
    loadViewData(viewName);
  }

  function loadViewData(viewName) {
    switch (viewName) {
      case 'posture':
        loadPostureOverview();
        break;
      case 'assets':
        loadAssets();
        break;
      case 'assessments':
        loadAssessments();
        break;
      case 'findings':
        loadFindings();
        break;
      case 'compare':
        setupCompareSelectors();
        break;
      case 'agents':
        loadAgents();
        break;
      case 'users':
        if (state.user && state.user.role === 'admin') {
          loadUsers();
        }
        break;
    }
  }

  // 1. Posture Overview
  async function loadPostureOverview() {
    try {
      const res = await apiFetch('/api/v1/posture/summary');
      if (!res.ok) return;
      const data = await res.json();

      // Top KPI Cards
      document.getElementById('kpi-total-findings').textContent = data.total_active_findings;
      document.getElementById('kpi-verified-remediations').textContent = data.verified_remediations_count;
      document.getElementById('kpi-asset-coverage').textContent = `${data.assessed_assets} / ${data.total_assets}`;
      const coveragePct = data.total_assets > 0 ? Math.round((data.assessed_assets / data.total_assets) * 100) : 0;
      document.getElementById('kpi-asset-percent').textContent = `${coveragePct}% assessed`;
      document.getElementById('kpi-stale-assets').textContent = data.stale_assets_count;

      // Severity Breakdown
      const sev = data.by_severity;
      document.getElementById('kpi-crit').textContent = `${sev.critical} Crit`;
      document.getElementById('kpi-high').textContent = `${sev.high} High`;
      document.getElementById('kpi-med').textContent = `${sev.medium} Med`;
      document.getElementById('kpi-low').textContent = `${sev.low} Low`;

      // Status Table
      const st = data.by_status;
      document.getElementById('stat-count-open').textContent = st.open;
      document.getElementById('stat-count-ack').textContent = st.acknowledged;
      document.getElementById('stat-count-inprog').textContent = st.in_progress;
      document.getElementById('stat-count-res').textContent = st.resolved;
      document.getElementById('stat-count-accepted').textContent = st.accepted_risk;
      document.getElementById('stat-count-reopened').textContent = st.reopened;

      // Engine Stats
      document.getElementById('stat-jobs-completed').textContent = data.completed_assessments_count;
      document.getElementById('stat-jobs-failed').textContent = data.failed_assessments_count;
      document.getElementById('stat-manual-resolutions').textContent = data.manual_resolutions_count;
    } catch (e) {
      showToast('Failed to load posture summary', 'error');
    }
  }

  // 2. Asset Inventory
  async function loadAssets() {
    const tbody = document.getElementById('tbody-assets');
    try {
      const res = await apiFetch('/api/v1/assets');
      if (!res.ok) return;
      const data = await res.json();
      const assets = data.assets || [];
      state.cachedAssets = assets;

      if (assets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="table-empty">Zero assets registered. Click "Register Asset" above to add your first target.</td></tr>`;
        return;
      }

      tbody.innerHTML = assets.map(a => {
        const critBadge = a.criticality === 'critical' ? 'badge-critical' : a.criticality === 'high' ? 'badge-high' : 'badge-subtle';
        const dateStr = a.created_at ? new Date(a.created_at).toLocaleString() : 'N/A';
        return `
          <tr>
            <td><strong>${escapeHtml(a.name)}</strong></td>
            <td><span class="badge badge-subtle">${escapeHtml(a.asset_type)}</span></td>
            <td><code>${escapeHtml(a.target)}</code></td>
            <td><span class="badge ${critBadge}">${escapeHtml(a.criticality)}</span></td>
            <td>${escapeHtml(dateStr)}</td>
            <td class="text-right">
              <button class="btn btn-sm btn-outline" onclick="window.OpenAuditApp.launchScanForAsset('${a.id}', '${escapeHtml(a.target)}')">Scan</button>
              <button class="btn btn-sm btn-subtle text-red" onclick="window.OpenAuditApp.deleteAsset('${a.id}')">Delete</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" class="table-empty text-red">Failed to load assets: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  // 3. Assessments & Scans
  async function loadAssessments() {
    const tbody = document.getElementById('tbody-assessments');
    try {
      const res = await apiFetch('/api/v1/assessments?limit=50');
      if (!res.ok) return;
      const data = await res.json();
      const jobs = data.jobs || [];
      state.cachedJobs = jobs;

      if (jobs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="table-empty">Zero assessments executed yet. Click "Launch Assessment" to run your first audit.</td></tr>`;
        return;
      }

      tbody.innerHTML = jobs.map(j => {
        let statusBadge = 'badge-subtle';
        let statusExtra = '';
        if (j.status === 'completed') statusBadge = 'badge-green';
        else if (j.status === 'running') {
          statusBadge = 'badge-blue';
          statusExtra = '<span class="pulse-dot"></span>';
        } else if (j.status === 'failed') statusBadge = 'badge-critical';
        else if (j.status === 'pending') statusBadge = 'badge-amber';

        const createdStr = j.created_at ? new Date(j.created_at).toLocaleTimeString() : 'N/A';
        const completedStr = j.completed_at ? new Date(j.completed_at).toLocaleTimeString() : '--';

        return `
          <tr>
            <td><code>${escapeHtml(j.target)}</code></td>
            <td><span class="badge badge-subtle">${escapeHtml(j.assessment_type)}</span></td>
            <td>${escapeHtml(j.profile)}</td>
            <td><span class="badge ${statusBadge}">${statusExtra} ${escapeHtml(j.status)}</span></td>
            <td>${escapeHtml(createdStr)}</td>
            <td>${escapeHtml(completedStr)}</td>
            <td><strong>${j.findings_count}</strong></td>
            <td class="text-right">
              ${j.status === 'running' || j.status === 'pending' ?
                `<button class="btn btn-sm btn-danger" onclick="window.OpenAuditApp.cancelJob('${j.id}')">Cancel</button>` :
                `<a class="btn btn-sm btn-outline" href="/api/v1/reports/export?job_id=${j.id}&format=html" target="_blank">Report</a>
                 <a class="btn btn-sm btn-subtle" href="/api/v1/reports/export?job_id=${j.id}&format=csv">CSV</a>`
              }
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="8" class="table-empty text-red">Failed to load assessments: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  // 4. Findings & Lifecycle
  async function loadFindings() {
    const tbody = document.getElementById('tbody-findings');
    const sevFilter = document.getElementById('filter-finding-severity').value;
    const statusFilter = document.getElementById('filter-finding-status').value;

    let url = '/api/v1/findings?limit=100';
    if (sevFilter) url += `&severity=${encodeURIComponent(sevFilter)}`;
    if (statusFilter) url += `&status=${encodeURIComponent(statusFilter)}`;

    try {
      const res = await apiFetch(url);
      if (!res.ok) return;
      const data = await res.json();
      const findings = data.findings || [];

      if (findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="table-empty">Zero findings match the selected filters.</td></tr>`;
        return;
      }

      tbody.innerHTML = findings.map(f => {
        const sevLower = f.severity.toLowerCase();
        const sevBadge = sevLower === 'critical' ? 'badge-critical' : sevLower === 'high' ? 'badge-high' : sevLower === 'medium' ? 'badge-medium' : 'badge-low';

        let stBadge = 'badge-subtle';
        if (f.status === 'open') stBadge = 'badge-critical';
        else if (f.status === 'resolved') stBadge = 'badge-green';
        else if (f.status === 'in_progress') stBadge = 'badge-blue';
        else if (f.status === 'acknowledged') stBadge = 'badge-amber';
        else if (f.status === 'reopened') stBadge = 'badge-high';

        return `
          <tr>
            <td><span class="badge ${sevBadge}">${escapeHtml(f.severity)}</span></td>
            <td>
              <div><strong>${escapeHtml(f.title)}</strong></div>
              <code class="text-faint" style="font-size: 0.725rem;">${escapeHtml(f.rule_id)}</code>
            </td>
            <td><code>${escapeHtml(f.endpoint)}</code></td>
            <td><span class="badge ${stBadge}">${escapeHtml(f.status)}</span></td>
            <td>${f.occurrence_count}</td>
            <td>${escapeHtml(f.assigned_owner || 'Unassigned')}</td>
            <td class="text-right">
              <button class="btn btn-sm btn-outline" onclick="window.OpenAuditApp.inspectFinding('${f.id}')">Inspect</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="table-empty text-red">Failed to load findings: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  // Inspect Finding in Drawer
  async function inspectFinding(id) {
    state.selectedFindingId = id;
    const drawer = document.getElementById('drawer-finding-detail');
    drawer.style.display = 'flex';

    try {
      const res = await apiFetch(`/api/v1/findings/${id}`);
      if (!res.ok) return;
      const f = await res.json();

      document.getElementById('drawer-finding-title').textContent = f.title;
      document.getElementById('drawer-finding-rule').textContent = f.rule_id;
      document.getElementById('drawer-finding-endpoint').textContent = f.endpoint;
      document.getElementById('drawer-finding-fp').textContent = f.fingerprint;
      document.getElementById('drawer-finding-occurrences').textContent = `Observed ${f.occurrence_count} time${f.occurrence_count === 1 ? '' : 's'}`;

      const sevEl = document.getElementById('drawer-finding-severity');
      sevEl.textContent = f.severity;
      sevEl.className = `badge ${f.severity.toLowerCase() === 'critical' ? 'badge-critical' : f.severity.toLowerCase() === 'high' ? 'badge-high' : 'badge-medium'}`;

      const stEl = document.getElementById('drawer-finding-status');
      stEl.textContent = f.status.toUpperCase();
      stEl.className = `badge ${f.status === 'resolved' ? 'badge-green' : f.status === 'open' ? 'badge-critical' : 'badge-blue'}`;

      // Forms
      document.getElementById('finding-status-id').value = f.id;
      document.getElementById('select-new-status').value = f.status.toLowerCase();
      document.getElementById('finding-assign-id').value = f.id;
      document.getElementById('assign-owner-name').value = f.assigned_owner || '';
      document.getElementById('assign-due-date').value = f.due_date ? f.due_date.substring(0, 10) : '';
      document.getElementById('assign-notes').value = f.remediation_notes || '';

      // Load History Timeline
      loadFindingHistory(id);
    } catch (e) {
      showToast('Failed to load finding details', 'error');
    }
  }

  async function loadFindingHistory(id) {
    const timeline = document.getElementById('drawer-history-timeline');
    try {
      const res = await apiFetch(`/api/v1/findings/${id}/history`);
      if (!res.ok) return;
      const history = await res.json();

      if (history.length === 0) {
        timeline.innerHTML = `<div class="empty-text">No lifecycle status transitions recorded yet.</div>`;
        return;
      }

      timeline.innerHTML = history.map(h => {
        const timeStr = new Date(h.created_at).toLocaleString();
        return `
          <div class="timeline-item">
            <div class="timeline-header">
              <span><strong>${escapeHtml(h.old_status)}</strong> &rarr; <strong>${escapeHtml(h.new_status)}</strong></span>
              <span>${escapeHtml(timeStr)}</span>
            </div>
            ${h.resolution_type ? `<span class="badge badge-subtle">${escapeHtml(h.resolution_type)}</span>` : ''}
            ${h.comment ? `<div style="margin-top: 4px; color: var(--text-secondary);">${escapeHtml(h.comment)}</div>` : ''}
          </div>
        `;
      }).join('');
    } catch (e) {
      timeline.innerHTML = `<div class="empty-text text-red">Failed to load history audit log.</div>`;
    }
  }

  // 5. Coverage Comparison
  async function setupCompareSelectors() {
    const baseSel = document.getElementById('compare-base-job');
    const targetSel = document.getElementById('compare-target-job');

    try {
      const res = await apiFetch('/api/v1/assessments?limit=100');
      if (!res.ok) return;
      const data = await res.json();
      const completedJobs = (data.jobs || []).filter(j => j.status === 'completed');

      if (completedJobs.length < 2) {
        baseSel.innerHTML = `<option value="">Requires at least two completed assessments</option>`;
        targetSel.innerHTML = `<option value="">Requires at least two completed assessments</option>`;
        return;
      }

      const options = completedJobs.map(j => {
        const dateStr = new Date(j.created_at).toLocaleString();
        return `<option value="${j.id}">${escapeHtml(j.target)} (${escapeHtml(j.assessment_type)} - ${dateStr})</option>`;
      }).join('');

      baseSel.innerHTML = options;
      targetSel.innerHTML = options;
      if (completedJobs.length >= 2) {
        targetSel.selectedIndex = 1;
      }
    } catch (e) {
      showToast('Failed to load assessments for comparison', 'error');
    }
  }

  async function executeComparison(baseId, targetId) {
    const container = document.getElementById('compare-results-container');
    container.style.display = 'block';

    try {
      const res = await apiFetch(`/api/v1/assessments/compare?base_job_id=${baseId}&target_job_id=${targetId}`);
      if (!res.ok) {
        const err = await res.json();
        showToast(err.error || 'Comparison failed', 'error');
        return;
      }
      const comp = await res.json();

      // Coverage Bar
      const pct = Math.round(comp.coverage_ratio * 100);
      document.getElementById('compare-coverage-title').textContent = `Coverage Ratio: ${pct}%`;
      document.getElementById('compare-coverage-notes').textContent = comp.coverage_notes;
      document.getElementById('compare-progress-fill').style.width = `${pct}%`;
      document.getElementById('compare-progress-fill').style.background = pct >= 100 ? 'var(--accent-green)' : 'var(--accent-amber)';

      // Counts
      document.getElementById('count-comp-resolved').textContent = comp.resolved_findings.length;
      document.getElementById('count-comp-omitted').textContent = comp.unverified_omissions.length;
      document.getElementById('count-comp-new').textContent = comp.new_findings.length;
      document.getElementById('count-comp-persistent').textContent = comp.persistent_findings.length;

      // Lists
      renderComparisonList('list-comp-resolved', comp.resolved_findings, 'Verified Remediated', 'badge-green');
      renderComparisonList('list-comp-omitted', comp.unverified_omissions, 'Rule Omitted (Unverified)', 'badge-amber');
      renderComparisonList('list-comp-new', comp.new_findings, 'New Exposure', 'badge-critical');
      renderComparisonList('list-comp-persistent', comp.persistent_findings, 'Persistent Exposure', 'badge-subtle');
    } catch (e) {
      showToast('Comparison request failed', 'error');
    }
  }

  function renderComparisonList(elementId, items, label, badgeClass) {
    const el = document.getElementById(elementId);
    if (!items || items.length === 0) {
      el.innerHTML = `<div class="empty-text">Zero findings in this category.</div>`;
      return;
    }
    el.innerHTML = items.map(f => `
      <div style="padding: 8px 0; border-bottom: 1px solid var(--border-subtle);">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="badge ${badgeClass}">${label}</span>
          <code>${escapeHtml(f.endpoint || 'N/A')}</code>
        </div>
        <div style="font-weight: 500; font-size: 0.85rem; margin-top: 4px;">${escapeHtml(f.title)}</div>
        <code class="text-faint" style="font-size: 0.725rem;">${escapeHtml(f.rule_id)}</code>
      </div>
    `).join('');
  }

  // 6. Agents Management
  async function loadAgents() {
    const tbody = document.getElementById('tbody-agents');
    try {
      const res = await apiFetch('/api/v1/agents');
      if (!res.ok) return;
      const data = await res.json();
      const agents = data.agents || [];

      if (agents.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="table-empty">Zero agent daemons enrolled. Click "Issue Enrollment Token" to connect distributed workers.</td></tr>`;
        return;
      }

      tbody.innerHTML = agents.map(a => {
        let stBadge = a.status === 'active' ? 'badge-green' : a.status === 'pending' ? 'badge-amber' : 'badge-subtle';
        let lastSeenStr = 'Never';
        if (a.last_seen_at) {
          const diffSec = Math.floor((new Date() - new Date(a.last_seen_at)) / 1000);
          lastSeenStr = diffSec < 60 ? 'Just now' : `${Math.floor(diffSec / 60)}m ago`;
        }

        return `
          <tr>
            <td><code>${escapeHtml(a.machine_id)}</code></td>
            <td>${escapeHtml(a.hostname)}</td>
            <td><span class="badge badge-subtle">v${escapeHtml(a.agent_version)}</span></td>
            <td><span class="badge ${stBadge}">${escapeHtml(a.status)}</span></td>
            <td>${escapeHtml(lastSeenStr)}</td>
            <td class="text-right">
              ${a.status === 'pending' ? `<button class="btn btn-sm btn-primary" onclick="window.OpenAuditApp.approveAgent('${a.id}')">Approve</button>` : ''}
              <button class="btn btn-sm btn-danger" onclick="window.OpenAuditApp.revokeAgent('${a.id}')">Revoke</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" class="table-empty text-red">Failed to load agents: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  // 7. Users Management
  async function loadUsers() {
    const tbody = document.getElementById('tbody-users');
    try {
      const res = await apiFetch('/api/v1/users');
      if (!res.ok) return;
      const data = await res.json();
      const users = data.users || [];

      tbody.innerHTML = users.map(u => {
        const roleBadge = u.role === 'admin' ? 'badge-critical' : u.role === 'auditor' ? 'badge-blue' : 'badge-subtle';
        const dateStr = new Date(u.created_at).toLocaleDateString();
        return `
          <tr>
            <td><strong>${escapeHtml(u.name)}</strong></td>
            <td><code>${escapeHtml(u.email)}</code></td>
            <td><span class="badge ${roleBadge}">${escapeHtml(u.role.toUpperCase())}</span></td>
            <td>${escapeHtml(dateStr)}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="4" class="table-empty text-red">Failed to load users: ${escapeHtml(e.message)}</td></tr>`;
    }
  }

  // Background Auto-Poller
  function startBackgroundPoller() {
    if (state.pollInterval) clearInterval(state.pollInterval);
    state.pollInterval = setInterval(async () => {
      if (!state.token) return;
      if (state.currentView === 'assessments') {
        const hasRunning = state.cachedJobs.some(j => j.status === 'running' || j.status === 'pending');
        if (hasRunning) {
          loadAssessments();
        }
      }
    }, 3500);
  }

  // Global Event Listeners & Setup
  function initEventHandlers() {
    // Bootstrap Form
    document.getElementById('form-bootstrap').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-submit-bootstrap');
      btn.disabled = true;

      const payload = {
        org_name: document.getElementById('bootstrap-org-name').value.trim(),
        org_slug: document.getElementById('bootstrap-org-slug').value.trim(),
        admin_name: document.getElementById('bootstrap-admin-name').value.trim(),
        admin_email: document.getElementById('bootstrap-admin-email').value.trim(),
        admin_password: document.getElementById('bootstrap-admin-password').value,
      };

      try {
        const res = await fetch('/api/v1/auth/bootstrap', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (res.ok) {
          const data = await res.json();
          state.token = data.token;
          localStorage.setItem('openaudit_token', data.token);
          showToast('Control plane initialized successfully');
          checkSession();
        } else {
          const err = await res.json();
          showToast(err.error || 'Bootstrap failed', 'error');
        }
      } catch (err) {
        showToast('Connection error during initialization', 'error');
      } finally {
        btn.disabled = false;
      }
    });

    // Login Form
    document.getElementById('form-login').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-submit-login');
      btn.disabled = true;

      const payload = {
        email: document.getElementById('login-email').value.trim(),
        password: document.getElementById('login-password').value,
      };

      try {
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (res.ok) {
          const data = await res.json();
          state.token = data.token;
          localStorage.setItem('openaudit_token', data.token);
          showToast('Welcome back');
          checkSession();
        } else {
          const err = await res.json();
          showToast(err.error || 'Authentication rejected', 'error');
        }
      } catch (err) {
        showToast('Network error during login', 'error');
      } finally {
        btn.disabled = false;
      }
    });

    // Logout
    document.getElementById('btn-logout').addEventListener('click', async () => {
      try {
        await apiFetch('/api/v1/auth/logout', { method: 'POST' });
      } catch (e) {}
      handleUnauthorized();
      showToast('Signed out');
    });

    // Auth View Switchers
    document.getElementById('link-goto-login').addEventListener('click', (e) => {
      e.preventDefault();
      showAuthView('login');
    });
    document.getElementById('link-goto-setup').addEventListener('click', (e) => {
      e.preventDefault();
      showAuthView('setup');
    });

    // Sidebar Navigation Click
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const view = item.dataset.view;
        if (view) switchView(view);
      });
    });

    // Refresh Posture Button
    document.getElementById('btn-refresh-posture').addEventListener('click', () => {
      loadPostureOverview();
      showToast('Posture metrics updated');
    });

    // Theme Toggle
    document.getElementById('btn-toggle-theme').addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('openaudit_theme', next);
    });

    // Finding Filters
    document.getElementById('filter-finding-severity').addEventListener('change', loadFindings);
    document.getElementById('filter-finding-status').addEventListener('change', loadFindings);

    // Finding Detail Drawer Close
    document.getElementById('btn-close-drawer').addEventListener('click', () => {
      document.getElementById('drawer-finding-detail').style.display = 'none';
      state.selectedFindingId = null;
    });

    // Resolution Type Toggle
    document.getElementById('select-new-status').addEventListener('change', (e) => {
      const isResolved = e.target.value === 'resolved';
      document.getElementById('group-resolution-type').style.display = isResolved ? 'block' : 'none';
    });

    // Status Update Submit
    document.getElementById('form-update-status').addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = document.getElementById('finding-status-id').value;
      const status = document.getElementById('select-new-status').value;
      const resolutionType = status === 'resolved' ? document.getElementById('select-resolution-type').value : null;
      const comment = document.getElementById('status-transition-comment').value.trim();

      try {
        const res = await apiFetch(`/api/v1/findings/${id}/status`, {
          method: 'POST',
          body: {
            status,
            resolution_type: resolutionType,
            comment: comment || null,
          },
        });

        if (res.ok) {
          showToast('Finding lifecycle status updated');
          inspectFinding(id);
          loadFindings();
          loadPostureOverview();
        } else {
          const err = await res.json();
          showToast(err.error || 'Failed to update status', 'error');
        }
      } catch (e) {
        showToast('Error updating status', 'error');
      }
    });

    // Assignment Submit
    document.getElementById('form-assign-owner').addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = document.getElementById('finding-assign-id').value;
      const assigned_owner = document.getElementById('assign-owner-name').value.trim();
      const rawDue = document.getElementById('assign-due-date').value;
      const due_date = rawDue ? `${rawDue}T23:59:59Z` : null;
      const remediation_notes = document.getElementById('assign-notes').value.trim();

      try {
        const res = await apiFetch(`/api/v1/findings/${id}/assign`, {
          method: 'POST',
          body: {
            assigned_owner: assigned_owner || null,
            due_date,
            remediation_notes: remediation_notes || null,
          },
        });

        if (res.ok) {
          showToast('Remediation assignment saved');
          loadFindings();
        } else {
          const err = await res.json();
          showToast(err.error || 'Failed to save assignment', 'error');
        }
      } catch (e) {
        showToast('Error saving assignment', 'error');
      }
    });

    // Compare Assessments Form
    document.getElementById('form-compare').addEventListener('submit', (e) => {
      e.preventDefault();
      const baseId = document.getElementById('compare-base-job').value;
      const targetId = document.getElementById('compare-target-job').value;
      if (!baseId || !targetId) {
        showToast('Please select both baseline and follow-up assessments', 'error');
        return;
      }
      executeComparison(baseId, targetId);
    });

    // Modal Triggers
    document.getElementById('btn-open-create-asset-modal').addEventListener('click', () => {
      document.getElementById('modal-create-asset').style.display = 'flex';
    });

    document.getElementById('btn-open-launch-assessment-modal').addEventListener('click', () => {
      openLaunchAssessmentModal();
    });
    document.getElementById('btn-header-quick-scan').addEventListener('click', () => {
      openLaunchAssessmentModal();
    });

    document.getElementById('btn-open-issue-token-modal').addEventListener('click', () => {
      document.getElementById('token-form-container').style.display = 'block';
      document.getElementById('token-result-container').style.display = 'none';
      document.getElementById('modal-issue-token').style.display = 'flex';
    });

    document.getElementById('btn-open-create-user-modal').addEventListener('click', () => {
      document.getElementById('modal-create-user').style.display = 'flex';
    });

    // Generic Modal Close
    document.querySelectorAll('[data-close]').forEach(btn => {
      btn.addEventListener('click', () => {
        const modalId = btn.dataset.close;
        const modal = document.getElementById(modalId);
        if (modal) modal.style.display = 'none';
      });
    });

    // Register Asset Submit
    document.getElementById('form-create-asset').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('asset-name').value.trim(),
        asset_type: document.getElementById('asset-type').value,
        target: document.getElementById('asset-target').value.trim(),
        criticality: document.getElementById('asset-criticality').value,
      };

      try {
        const res = await apiFetch('/api/v1/assets', {
          method: 'POST',
          body: payload,
        });

        if (res.ok) {
          showToast('Asset registered successfully');
          document.getElementById('modal-create-asset').style.display = 'none';
          document.getElementById('form-create-asset').reset();
          loadAssets();
          loadPostureOverview();
        } else {
          const err = await res.json();
          showToast(err.error || 'Failed to create asset', 'error');
        }
      } catch (e) {
        showToast('Error registering asset', 'error');
      }
    });

    // Launch Assessment Submit
    document.getElementById('form-launch-assessment').addEventListener('submit', async (e) => {
      e.preventDefault();
      const assetSelect = document.getElementById('scan-asset-select').value;
      const payload = {
        asset_id: assetSelect || null,
        target: document.getElementById('scan-target').value.trim(),
        assessment_type: document.getElementById('scan-type').value,
        profile: document.getElementById('scan-profile').value,
      };

      try {
        const res = await apiFetch('/api/v1/assessments', {
          method: 'POST',
          body: payload,
        });

        if (res.ok) {
          showToast('Assessment dispatched');
          document.getElementById('modal-launch-assessment').style.display = 'none';
          switchView('assessments');
        } else {
          const err = await res.json();
          showToast(err.error || 'Failed to start assessment', 'error');
        }
      } catch (e) {
        showToast('Error starting assessment', 'error');
      }
    });

    // Issue Token Submit
    document.getElementById('form-issue-token').addEventListener('submit', async (e) => {
      e.preventDefault();
      const machineId = document.getElementById('token-machine-id').value.trim();
      const lifetime = parseInt(document.getElementById('token-lifetime').value, 10);

      try {
        const res = await apiFetch('/api/v1/agents/tokens', {
          method: 'POST',
          body: {
            machine_id: machineId || null,
            lifetime_secs: lifetime,
          },
        });

        if (res.ok) {
          const data = await res.json();
          document.getElementById('token-form-container').style.display = 'none';
          document.getElementById('token-result-container').style.display = 'block';

          const cmd = `openaudit-agent enroll \\\n  --server "${window.location.origin}" \\\n  --token-id "${data.token_id}" \\\n  --secret "${data.token_secret}" \\\n  --nonce "${data.challenge_nonce}"`;
          document.getElementById('token-snippet-code').textContent = cmd;
        } else {
          const err = await res.json();
          showToast(err.error || 'Failed to issue token', 'error');
        }
      } catch (e) {
        showToast('Error generating token', 'error');
      }
    });

    // Create User Submit
    document.getElementById('form-create-user').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('user-full-name').value.trim(),
        email: document.getElementById('user-email').value.trim(),
        password: document.getElementById('user-password').value,
        role: document.getElementById('user-role').value,
      };

      try {
        const res = await apiFetch('/api/v1/users', {
          method: 'POST',
          body: payload,
        });

        if (res.ok) {
          showToast('User invited successfully');
          document.getElementById('modal-create-user').style.display = 'none';
          document.getElementById('form-create-user').reset();
          loadUsers();
        } else {
          const err = await res.json();
          showToast(err.error || 'Failed to create user', 'error');
        }
      } catch (e) {
        showToast('Error inviting user', 'error');
      }
    });
  }

  function openLaunchAssessmentModal() {
    const sel = document.getElementById('scan-asset-select');
    sel.innerHTML = '<option value="">-- Custom Target (No registered asset) --</option>' +
      state.cachedAssets.map(a => `<option value="${a.id}" data-target="${escapeHtml(a.target)}">${escapeHtml(a.name)} (${escapeHtml(a.target)})</option>`).join('');

    sel.onchange = () => {
      const opt = sel.options[sel.selectedIndex];
      if (opt && opt.dataset.target) {
        document.getElementById('scan-target').value = opt.dataset.target;
      }
    };

    document.getElementById('modal-launch-assessment').style.display = 'flex';
  }

  // Public Global Actions
  window.OpenAuditApp = {
    launchScanForAsset: (assetId, target) => {
      openLaunchAssessmentModal();
      document.getElementById('scan-asset-select').value = assetId;
      document.getElementById('scan-target').value = target;
    },
    deleteAsset: async (id) => {
      if (!confirm('Are you sure you want to delete this asset?')) return;
      try {
        const res = await apiFetch(`/api/v1/assets/${id}`, { method: 'DELETE' });
        if (res.ok) {
          showToast('Asset deleted');
          loadAssets();
          loadPostureOverview();
        }
      } catch (e) {
        showToast('Failed to delete asset', 'error');
      }
    },
    cancelJob: async (id) => {
      try {
        const res = await apiFetch(`/api/v1/assessments/${id}/cancel`, { method: 'POST' });
        if (res.ok) {
          showToast('Assessment cancelled');
          loadAssessments();
        }
      } catch (e) {
        showToast('Failed to cancel assessment', 'error');
      }
    },
    inspectFinding: (id) => {
      inspectFinding(id);
    },
    approveAgent: async (id) => {
      try {
        const res = await apiFetch(`/api/v1/agents/${id}/status`, {
          method: 'POST',
          body: { status: 'active' },
        });
        if (res.ok) {
          showToast('Agent approved and active');
          loadAgents();
        }
      } catch (e) {
        showToast('Failed to approve agent', 'error');
      }
    },
    revokeAgent: async (id) => {
      if (!confirm('Revoke this agent node permanently?')) return;
      try {
        const res = await apiFetch(`/api/v1/agents/${id}`, { method: 'DELETE' });
        if (res.ok) {
          showToast('Agent revoked');
          loadAgents();
        }
      } catch (e) {
        showToast('Failed to revoke agent', 'error');
      }
    },
  };

  // Initialization
  document.addEventListener('DOMContentLoaded', () => {
    // Restore Saved Theme
    const savedTheme = localStorage.getItem('openaudit_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    initEventHandlers();
    checkSession();
  });
})();

