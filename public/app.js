/**
 * WAF Management Dashboard JavaScript
 */

const API_BASE = '/api';

// State
let currentPage = 'dashboard';
let charts = {};
let refreshInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  initLogin();
  initNavigation();
  initEventListeners();
  // Try existing session, then fall back to login.
  const ok = await checkAuth();
  if (ok) startAutoRefresh();
});

function initLogin() {
  const form = document.getElementById('login-form');
  if (!form) return;
  form.addEventListener('submit', handleLoginSubmit);
}

// Theme handling
function initTheme() {
  const saved = localStorage.getItem('kavach-theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = saved || (prefersDark ? 'dark' : 'light');
  setTheme(theme);

  const btn = document.getElementById('theme-toggle-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      setTheme(current === 'dark' ? 'light' : 'dark');
    });
  }
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('kavach-theme', theme);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) {
    const icon = btn.querySelector('i');
    if (icon) icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
  }
  // Update chart colors if charts exist
  updateChartTheme(theme);
}

function updateChartTheme(theme) {
  const textColor = theme === 'dark' ? '#f1f5f9' : '#111827';
  const gridColor = theme === 'dark' ? '#334155' : '#e5e7eb';
  Object.values(charts).forEach(chart => {
    if (!chart || !chart.options) return;
    if (chart.options.scales && chart.options.scales.x) {
      chart.options.scales.x.ticks = { color: textColor };
      chart.options.scales.x.grid = { color: gridColor };
    }
    if (chart.options.scales && chart.options.scales.y) {
      chart.options.scales.y.ticks = { color: textColor };
      chart.options.scales.y.grid = { color: gridColor };
    }
    if (chart.options.plugins && chart.options.plugins.legend) {
      chart.options.plugins.legend.labels = { color: textColor };
    }
    chart.update();
  });
}

// WebSocket for real-time updates
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch {
    return;
  }
  ws.onopen = () => console.log('WebSocket connected');
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'threat' && currentPage === 'dashboard') {
        loadDashboardData();
      }
      if (data.type === 'memory' && currentPage === 'dashboard') {
        updateMemoryBar(data);
      }
    } catch {}
  };
  ws.onclose = () => {
    // Reconnect after 5 seconds
    setTimeout(initWebSocket, 5000);
  };
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errorEl = document.getElementById('login-error');
  const btn = document.getElementById('login-submit-btn');

  errorEl.hidden = true;
  btn.disabled = true;
  const origText = btn.innerHTML;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in...';

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const msg = res.status === 429
        ? 'Account locked. Try again later.'
        : (body.error || `Login failed (${res.status})`);
      errorEl.textContent = msg;
      errorEl.hidden = false;
      return;
    }
    const data = await res.json();
    showApp(data.user);
  } catch (err) {
    errorEl.textContent = 'Network error: ' + err.message;
    errorEl.hidden = false;
  } finally {
    btn.disabled = false;
    btn.innerHTML = origText;
  }
}

async function checkAuth() {
  try {
    const res = await fetch(`${API_BASE}/auth/me`, { credentials: 'same-origin' });
    if (res.ok) {
      const data = await res.json();
      showApp(data.user);
      return true;
    }
  } catch {
    // fall through to login
  }
  showLogin();
  return false;
}

function showApp(user) {
  document.getElementById('login-page')?.classList.remove('active');
  document.getElementById('login-page')?.setAttribute('hidden', '');
  const shell = document.getElementById('app-shell');
  if (shell) shell.removeAttribute('hidden');

  // Hide login page entirely after login
  const lp = document.getElementById('login-page');
  if (lp) lp.style.display = 'none';

  if (user) {
    const nameEl = document.getElementById('user-display-name');
    const roleEl = document.getElementById('user-role');
    if (nameEl) nameEl.textContent = user.displayName || user.username;
    if (roleEl) roleEl.textContent = user.role || '';
    // Show admin-only items
    document.querySelectorAll('.admin-only').forEach((el) => {
      const show = user.role === 'admin';
      el.hidden = !show;
    });
  }

  // Kick off the dashboard
  loadDashboardData();
  if (!refreshInterval) startAutoRefresh();
}

function showLogin() {
  const shell = document.getElementById('app-shell');
  if (shell) shell.setAttribute('hidden', '');
  const lp = document.getElementById('login-page');
  if (lp) {
    lp.style.display = '';
    lp.classList.add('active');
  }
}

async function logout() {
  try {
    await fetch(`${API_BASE}/auth/logout`, { method: 'POST', credentials: 'same-origin' });
  } catch {}
  // Clear any state
  if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
  showLogin();
  document.getElementById('login-password').value = '';
  document.getElementById('login-username').focus();
}

// Navigation
function initNavigation() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const page = item.dataset.page;
      navigateTo(page);
    });
  });
}

function navigateTo(page) {
  // Update nav
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === page);
  });
  
  // Update page
  document.querySelectorAll('.page').forEach(p => {
    p.classList.toggle('active', p.id === `${page}-page`);
  });
  
  // Update title
  const titles = {
    dashboard: 'Dashboard',
    rules: 'Security Rules',
    logs: 'Request Logs',
    blocked: 'IP Management',
    bots: 'Bot Detection',
    geo: 'Geo Blocking',
    webhooks: 'Webhooks',
    test: 'Test Rules',
    settings: 'Settings'
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  
  currentPage = page;
  
  // Load page data
  switch(page) {
    case 'dashboard':
      loadDashboardData();
      break;
    case 'rules':
      loadRules();
      break;
    case 'logs':
      loadLogs();
      break;
    case 'blocked':
      loadIPLists();
      break;
    case 'bots':
      loadBotSettings();
      break;
    case 'geo':
      loadGeoSettings();
      break;
    case 'webhooks':
      loadWebhooks();
      break;
    case 'test':
      // Test page doesn't need initial load
      break;
    case 'settings':
      loadSettings();
      break;
    case 'users':
      loadUsers();
      break;
    case 'audit':
      loadAuditLog();
      break;
  }
}

// Event Listeners
function initEventListeners() {
  // Refresh button
  document.getElementById('refresh-btn').addEventListener('click', () => {
    refreshCurrentPage();
  });
  
  // Time range selector
  document.getElementById('time-range').addEventListener('change', () => {
    loadDashboardData();
  });
  
  // Add rule button
  document.getElementById('add-rule-btn').addEventListener('click', () => {
    openRuleModal();
  });
  
  // Rule form
  document.getElementById('rule-form').addEventListener('submit', handleRuleSubmit);
  
  // Modal close buttons
  document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
    btn.addEventListener('click', closeModals);
  });
  
  // IP management
  document.getElementById('block-ip-btn').addEventListener('click', () => {
    openIPModal('block');
  });
  
  document.getElementById('whitelist-ip-btn').addEventListener('click', () => {
    openIPModal('whitelist');
  });
  
  document.getElementById('ip-form').addEventListener('submit', handleIPSubmit);
  
  // Log filter
  document.getElementById('log-filter').addEventListener('change', () => {
    loadLogs();
  });
  
  // Clear logs
  document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);
  
  // Test form
  document.getElementById('test-form').addEventListener('submit', handleTestSubmit);
  
  // Attack examples
  document.querySelectorAll('.attack-card').forEach(card => {
    card.addEventListener('click', () => {
      const attack = card.dataset.attack;
      fillAttackExample(attack);
    });
  });
  
  // Settings buttons
  document.getElementById('reset-stats-btn').addEventListener('click', resetStats);
  document.getElementById('clear-all-logs-btn').addEventListener('click', clearLogs);
  
  // Bot detection toggle
  document.getElementById('bot-detection-toggle')?.addEventListener('change', async (e) => {
    try {
      await apiPut('/config', { enableBotDetection: e.target.checked });
      showToast('success', `Bot detection ${e.target.checked ? 'enabled' : 'disabled'}`);
    } catch (err) {
      console.error('Failed to update bot detection:', err);
    }
  });
  
  // Geo blocking toggle
  document.getElementById('geo-blocking-toggle')?.addEventListener('change', async (e) => {
    try {
      await apiPut('/config', { enableGeoBlocking: e.target.checked });
      showToast('success', `Geo blocking ${e.target.checked ? 'enabled' : 'disabled'}`);
    } catch (err) {
      console.error('Failed to update geo blocking:', err);
    }
  });
  
  // Country management
  document.getElementById('block-country-btn')?.addEventListener('click', async () => {
    const code = document.getElementById('block-country-input').value.toUpperCase();
    if (!code) return;
    try {
      await apiPost('/countries/block', { country: code });
      showToast('success', `Country ${code} blocked`);
      loadGeoSettings();
    } catch (err) {
      console.error('Failed to block country:', err);
    }
  });
  
  document.getElementById('allow-country-btn')?.addEventListener('click', async () => {
    const code = document.getElementById('allow-country-input').value.toUpperCase();
    if (!code) return;
    try {
      await apiPost('/countries/allow', { country: code });
      showToast('success', `Country ${code} added to allowed list`);
      loadGeoSettings();
    } catch (err) {
      console.error('Failed to allow country:', err);
    }
  });
  
  // Webhooks
  document.getElementById('add-webhook-btn')?.addEventListener('click', openWebhookModal);
  document.getElementById('webhook-form')?.addEventListener('submit', handleWebhookSubmit);
  
  // Import/Export
  document.getElementById('export-config-btn')?.addEventListener('click', exportConfig);
  document.getElementById('import-config-btn')?.addEventListener('click', () => {
    document.getElementById('import-file').click();
  });
  document.getElementById('import-file')?.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      importConfig(e.target.files[0]);
    }
  });

  // Logout
  document.getElementById('logout-btn')?.addEventListener('click', logout);

  // User management (admin)
  document.getElementById('add-user-btn')?.addEventListener('click', () => openUserModal());
  document.getElementById('user-form')?.addEventListener('submit', handleUserSubmit);

  // Password change
  document.getElementById('change-password-btn')?.addEventListener('click', () => {
    document.getElementById('password-modal').classList.add('active');
  });
  document.getElementById('password-form')?.addEventListener('submit', handlePasswordChange);

  // Audit log
  document.getElementById('audit-refresh-btn')?.addEventListener('click', loadAuditLog);
  document.getElementById('audit-user-filter')?.addEventListener('change', loadAuditLog);
  document.getElementById('audit-action-filter')?.addEventListener('change', loadAuditLog);
}

// API Functions
async function apiGet(endpoint) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, { credentials: 'same-origin' });
    if (response.status === 401) {
      handleUnauthorized();
      throw new Error('Unauthorized');
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      showToast('error', `API Error: ${err.message}`);
    }
    throw err;
  }
}

async function apiPost(endpoint, data) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (response.status === 401) {
      handleUnauthorized();
      throw new Error('Unauthorized');
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      showToast('error', `API Error: ${err.message}`);
    }
    throw err;
  }
}

async function apiPut(endpoint, data) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (response.status === 401) {
      handleUnauthorized();
      throw new Error('Unauthorized');
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      showToast('error', `API Error: ${err.message}`);
    }
    throw err;
  }
}

async function apiDelete(endpoint) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'DELETE',
      credentials: 'same-origin'
    });
    if (response.status === 401) {
      handleUnauthorized();
      throw new Error('Unauthorized');
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    if (err.message !== 'Unauthorized') {
      showToast('error', `API Error: ${err.message}`);
    }
    throw err;
  }
}

function handleUnauthorized() {
  // If we're already on the login page, don't loop.
  if (document.getElementById('login-page')?.classList.contains('active')) return;
  showLogin();
  showToast('error', 'Session expired. Please log in again.');
}

// Dashboard
async function loadDashboardData() {
  try {
    const timeRange = document.getElementById('time-range').value;
    const data = await apiGet(`/stats?range=${timeRange}`);
    
    // Update stats
    document.getElementById('total-requests').textContent = formatNumber(data.engine.totalRequests);
    document.getElementById('blocked-requests').textContent = formatNumber(data.engine.blockedRequests);
    document.getElementById('threats-detected').textContent = formatNumber(data.engine.threatsDetected);
    document.getElementById('active-rules').textContent = data.engine.rulesCount;
    
    // Update charts
    updateTrafficChart(data.logs.hourlyData);
    updateThreatsChart(data.logs.threatsByType);
    
    // Update recent logs
    updateRecentLogs(data.logs.blockedRequests > 0 ? await apiGet('/logs/blocked?limit=5') : { logs: [] });
    
  } catch (err) {
    console.error('Failed to load dashboard:', err);
  }
}

function updateTrafficChart(hourlyData) {
  const ctx = document.getElementById('traffic-chart').getContext('2d');
  
  if (charts.traffic) {
    charts.traffic.destroy();
  }
  
  const labels = hourlyData.map(d => {
    const date = new Date(d.time + ':00:00');
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  });
  
  charts.traffic = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Total Requests',
        data: hourlyData.map(d => d.total),
        borderColor: '#4f46e5',
        backgroundColor: 'rgba(79, 70, 229, 0.1)',
        fill: true,
        tension: 0.4
      }, {
        label: 'Blocked',
        data: hourlyData.map(d => d.blocked),
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        fill: true,
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom'
        }
      },
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

function updateThreatsChart(threatsByType) {
  const ctx = document.getElementById('threats-chart').getContext('2d');
  
  if (charts.threats) {
    charts.threats.destroy();
  }
  
  const labels = Object.keys(threatsByType).map(type => 
    type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
  );
  const data = Object.values(threatsByType);
  
  const colors = ['#4f46e5', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'];
  
  charts.threats = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: colors.slice(0, labels.length)
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom'
        }
      }
    }
  });
}

function updateRecentLogs(logsData) {
  const tbody = document.getElementById('recent-logs');
  const logs = logsData.logs || [];
  
  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center">No blocked requests yet</td></tr>';
    return;
  }
  
  tbody.innerHTML = logs.map(log => `
    <tr>
      <td>${formatTime(log.timestamp)}</td>
      <td>${log.ip}</td>
      <td><span class="badge badge-info">${log.method}</span></td>
      <td>${log.path}</td>
      <td>${log.violations?.map(v => v.type).join(', ') || 'N/A'}</td>
      <td><span class="badge badge-danger">Blocked</span></td>
    </tr>
  `).join('');
}

// Rules
async function loadRules() {
  try {
    const data = await apiGet('/rules');
    const tbody = document.getElementById('rules-table');
    
    tbody.innerHTML = data.rules.map(rule => `
      <tr>
        <td>
          <label class="toggle">
            <input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="toggleRule('${rule.id}')">
            <span class="toggle-slider"></span>
          </label>
        </td>
        <td><strong>${rule.name}</strong></td>
        <td>${rule.type.replace(/_/g, ' ')}</td>
        <td class="severity-${rule.severity}">${rule.severity}</td>
        <td><span class="badge ${rule.action === 'block' ? 'badge-danger' : 'badge-warning'}">${rule.action}</span></td>
        <td>
          <button class="btn btn-sm btn-secondary" onclick="editRule('${rule.id}')">
            <i class="fas fa-edit"></i>
          </button>
          <button class="btn btn-sm btn-danger" onclick="deleteRule('${rule.id}')">
            <i class="fas fa-trash"></i>
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load rules:', err);
  }
}

function openRuleModal(rule = null) {
  const modal = document.getElementById('rule-modal');
  const title = document.getElementById('modal-title');
  const form = document.getElementById('rule-form');
  
  if (rule) {
    title.textContent = 'Edit Rule';
    document.getElementById('rule-id').value = rule.id;
    document.getElementById('rule-name').value = rule.name;
    document.getElementById('rule-type').value = rule.type;
    document.getElementById('rule-severity').value = rule.severity;
    document.getElementById('rule-pattern').value = rule.pattern.toString().slice(1, -2); // Remove / and /i
    document.getElementById('rule-description').value = rule.description || '';
    document.getElementById('rule-action').value = rule.action;
    document.getElementById('rule-enabled').checked = rule.enabled;
  } else {
    title.textContent = 'Add Rule';
    form.reset();
    document.getElementById('rule-id').value = '';
  }
  
  modal.classList.add('active');
}

async function handleRuleSubmit(e) {
  e.preventDefault();
  
  const id = document.getElementById('rule-id').value;
  const rule = {
    name: document.getElementById('rule-name').value,
    type: document.getElementById('rule-type').value,
    severity: document.getElementById('rule-severity').value,
    pattern: document.getElementById('rule-pattern').value,
    description: document.getElementById('rule-description').value,
    action: document.getElementById('rule-action').value,
    enabled: document.getElementById('rule-enabled').checked
  };
  
  try {
    if (id) {
      await apiPut(`/rules/${id}`, rule);
      showToast('success', 'Rule updated successfully');
    } else {
      await apiPost('/rules', rule);
      showToast('success', 'Rule created successfully');
    }
    
    closeModals();
    loadRules();
  } catch (err) {
    console.error('Failed to save rule:', err);
  }
}

async function editRule(id) {
  try {
    const rule = await apiGet(`/rules/${id}`);
    openRuleModal(rule);
  } catch (err) {
    console.error('Failed to load rule:', err);
  }
}

async function toggleRule(id) {
  try {
    await apiPost(`/rules/${id}/toggle`);
    showToast('success', 'Rule status updated');
    loadRules();
  } catch (err) {
    console.error('Failed to toggle rule:', err);
  }
}

async function deleteRule(id) {
  if (!confirm('Are you sure you want to delete this rule?')) return;
  
  try {
    await apiDelete(`/rules/${id}`);
    showToast('success', 'Rule deleted');
    loadRules();
  } catch (err) {
    console.error('Failed to delete rule:', err);
  }
}

// Logs
async function loadLogs() {
  try {
    const filter = document.getElementById('log-filter').value;
    const endpoint = filter === 'blocked' ? '/logs/blocked?limit=100' : '/logs?limit=100';
    const data = await apiGet(endpoint);
    
    const tbody = document.getElementById('logs-table');
    
    if (data.logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center">No logs found</td></tr>';
      return;
    }
    
    tbody.innerHTML = data.logs.map(log => `
      <tr>
        <td>${formatTime(log.timestamp)}</td>
        <td>${log.ip}</td>
        <td><span class="badge badge-info">${log.method}</span></td>
        <td>${log.path}</td>
        <td>
          <span class="badge ${log.allowed ? 'badge-success' : 'badge-danger'}">
            ${log.allowed ? 'Allowed' : 'Blocked'}
          </span>
        </td>
        <td>
          ${log.violations?.length > 0 
            ? log.violations.map(v => `<span class="badge badge-warning">${v.type}</span>`).join(' ')
            : '<span class="text-muted">-</span>'
          }
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load logs:', err);
  }
}

async function clearLogs() {
  if (!confirm('Are you sure you want to clear all logs? This cannot be undone.')) return;
  
  try {
    await apiDelete('/logs');
    showToast('success', 'Logs cleared');
    loadLogs();
  } catch (err) {
    console.error('Failed to clear logs:', err);
  }
}

// IP Management
async function loadIPLists() {
  try {
    const [blocked, whitelisted] = await Promise.all([
      apiGet('/ips/blocked'),
      apiGet('/ips/whitelisted')
    ]);
    
    // Blocked IPs
    const blockedTbody = document.getElementById('blocked-ips-table');
    if (blocked.ips.length === 0) {
      blockedTbody.innerHTML = '<tr><td colspan="2" class="text-center">No blocked IPs</td></tr>';
    } else {
      blockedTbody.innerHTML = blocked.ips.map(ip => `
        <tr>
          <td><code>${ip}</code></td>
          <td>
            <button class="btn btn-sm btn-success" onclick="unblockIP('${ip}')">
              <i class="fas fa-check"></i> Unblock
            </button>
          </td>
        </tr>
      `).join('');
    }
    
    // Whitelisted IPs
    const whitelistedTbody = document.getElementById('whitelisted-ips-table');
    if (whitelisted.ips.length === 0) {
      whitelistedTbody.innerHTML = '<tr><td colspan="2" class="text-center">No whitelisted IPs</td></tr>';
    } else {
      whitelistedTbody.innerHTML = whitelisted.ips.map(ip => `
        <tr>
          <td><code>${ip}</code></td>
          <td>
            <button class="btn btn-sm btn-danger" onclick="unwhitelistIP('${ip}')">
              <i class="fas fa-times"></i> Remove
            </button>
          </td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load IP lists:', err);
  }
}

function openIPModal(action) {
  const modal = document.getElementById('ip-modal');
  const title = document.getElementById('ip-modal-title');
  
  title.textContent = action === 'block' ? 'Block IP Address' : 'Whitelist IP Address';
  document.getElementById('ip-action').value = action;
  document.getElementById('ip-address').value = '';
  
  modal.classList.add('active');
}

async function handleIPSubmit(e) {
  e.preventDefault();
  
  const action = document.getElementById('ip-action').value;
  const ip = document.getElementById('ip-address').value;
  
  try {
    if (action === 'block') {
      await apiPost('/ips/block', { ip });
      showToast('success', `IP ${ip} blocked`);
    } else {
      await apiPost('/ips/whitelist', { ip });
      showToast('success', `IP ${ip} whitelisted`);
    }
    
    closeModals();
    loadIPLists();
  } catch (err) {
    console.error('Failed to manage IP:', err);
  }
}

async function unblockIP(ip) {
  try {
    await apiPost('/ips/unblock', { ip });
    showToast('success', `IP ${ip} unblocked`);
    loadIPLists();
  } catch (err) {
    console.error('Failed to unblock IP:', err);
  }
}

async function unwhitelistIP(ip) {
  try {
    await apiPost('/ips/unwhitelist', { ip });
    showToast('success', `IP ${ip} removed from whitelist`);
    loadIPLists();
  } catch (err) {
    console.error('Failed to unwhitelist IP:', err);
  }
}

// Test Rules
async function handleTestSubmit(e) {
  e.preventDefault();
  
  const form = e.target;
  const data = {
    method: form.method.value,
    url: form.url.value,
    query: JSON.parse(form.query.value || '{}'),
    body: JSON.parse(form.body.value || '{}'),
    headers: JSON.parse(form.headers.value || '{}')
  };
  
  try {
    const result = await apiPost('/test', data);
    showTestResult(result);
  } catch (err) {
    console.error('Test failed:', err);
  }
}

function showTestResult(result) {
  const container = document.getElementById('test-result');
  const status = document.getElementById('test-status');
  const details = document.getElementById('test-details');
  
  container.classList.remove('hidden');
  
  if (result.result.allowed) {
    status.className = 'result-status allowed';
    status.innerHTML = '<i class="fas fa-check-circle"></i> Request Allowed';
  } else {
    status.className = 'result-status blocked';
    status.innerHTML = '<i class="fas fa-ban"></i> Request Blocked';
  }
  
  details.innerHTML = `
    <h5>Violations Detected:</h5>
    ${result.result.violations.length > 0 
      ? `<ul>${result.result.violations.map(v => `
        <li><strong>${v.type}</strong> (${v.severity}): ${v.reason}</li>
      `).join('')}</ul>`
      : '<p class="text-muted">No violations detected</p>'
    }
    <h5>Request Details:</h5>
    <pre>${JSON.stringify(result.request, null, 2)}</pre>
  `;
}

function fillAttackExample(type) {
  const examples = {
    sql: { url: "/api/search?q=' OR '1'='1", query: {"q": "' OR '1'='1"} },
    xss: { url: "/api/comment", body: {"comment": "<script>alert('xss')</script>"} },
    path: { url: "/api/file?file=../../../etc/passwd", query: {"file": "../../../etc/passwd"} },
    command: { url: "/api/ping?host=127.0.0.1;cat /etc/passwd", query: {"host": "127.0.0.1;cat /etc/passwd"} }
  };
  
  const ex = examples[type];
  if (ex) {
    document.querySelector('[name="url"]').value = ex.url;
    if (ex.query) document.querySelector('[name="query"]').value = JSON.stringify(ex.query, null, 2);
    if (ex.body) document.querySelector('[name="body"]').value = JSON.stringify(ex.body, null, 2);
  }
}

// Settings
async function resetStats() {
  if (!confirm('Are you sure you want to reset all statistics?')) return;
  
  try {
    await apiPost('/reset-stats');
    showToast('success', 'Statistics reset');
    loadDashboardData();
  } catch (err) {
    console.error('Failed to reset stats:', err);
  }
}

// Utilities
function closeModals() {
  document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
}

function showToast(type, message) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  const icons = {
    success: 'check-circle',
    error: 'exclamation-circle',
    info: 'info-circle'
  };
  
  toast.innerHTML = `
    <i class="fas fa-${icons[type]}"></i>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function formatNumber(num) {
  return num.toLocaleString();
}

function formatTime(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleString();
}

function refreshCurrentPage() {
  switch(currentPage) {
    case 'dashboard':
      loadDashboardData();
      break;
    case 'rules':
      loadRules();
      break;
    case 'logs':
      loadLogs();
      break;
    case 'blocked':
      loadIPLists();
      break;
    case 'bots':
      loadBotSettings();
      break;
    case 'geo':
      loadGeoSettings();
      break;
    case 'webhooks':
      loadWebhooks();
      break;
    case 'settings':
      loadSettings();
      break;
  }
}

function startAutoRefresh() {
  // Refresh every 10 seconds
  refreshInterval = setInterval(() => {
    if (currentPage === 'dashboard') {
      loadDashboardData();
    }
    
    // Update memory stats every 5 seconds
    if (currentPage === 'dashboard') {
      loadMemoryStats();
    }
  }, 10000);
}

// Memory Management
async function loadMemoryStats() {
  if (currentPage !== 'dashboard') return;
  try {
    const data = await apiGet('/memory');
    
    if (data.formatted) {
      document.getElementById('heap-usage').textContent = data.formatted.heapUsed;
      document.getElementById('memory-rss').textContent = data.formatted.rss;
    }
    
    document.getElementById('gc-runs').textContent = data.gcRuns;
    
    // Update memory bar
    const usagePercent = (data.usagePercent * 100).toFixed(1);
    document.getElementById('memory-usage-text').textContent = usagePercent + '%';
    
    const barFill = document.getElementById('memory-bar-fill');
    barFill.style.width = Math.min(usagePercent, 100) + '%';
    
    // Update bar color based on health
    barFill.classList.remove('warning', 'critical');
    const statusEl = document.getElementById('memory-status');
    
    if (usagePercent >= 95) {
      barFill.classList.add('critical');
      statusEl.className = 'badge badge-danger';
      statusEl.textContent = 'Critical';
    } else if (usagePercent >= 80) {
      barFill.classList.add('warning');
      statusEl.className = 'badge badge-warning';
      statusEl.textContent = 'Warning';
    } else {
      statusEl.className = 'badge badge-success';
      statusEl.textContent = 'Healthy';
    }
  } catch (err) {
    // Memory stats might not be available yet
  }
}

async function manualMemoryCleanup() {
  try {
    const result = await apiPost('/memory/cleanup', {});
    if (result.success) {
      showToast('success', 'Memory cleanup completed');
      loadMemoryStats();
    }
  } catch (err) {
    console.error('Memory cleanup failed:', err);
    showToast('error', 'Memory cleanup failed');
  }
}

// Bot Detection
async function loadBotSettings() {
  try {
    const data = await apiGet('/bots');
    
    document.getElementById('bot-detection-toggle').checked = data.enabled;
    
    const blockedTable = document.getElementById('blocked-bots-table');
    if (data.blockedBots.length === 0) {
      blockedTable.innerHTML = '<tr><td colspan="2" class="text-center">No blocked bots</td></tr>';
    } else {
      blockedTable.innerHTML = data.blockedBots.map(bot => `
        <tr>
          <td>${bot}</td>
          <td>
            <button class="btn btn-sm btn-success" onclick="unblockBot('${bot}')">
              <i class="fas fa-check"></i> Allow
            </button>
          </td>
        </tr>
      `).join('');
    }
    
    const allowedTable = document.getElementById('allowed-bots-table');
    if (data.allowedBots.length === 0) {
      allowedTable.innerHTML = '<tr><td colspan="2" class="text-center">No specifically allowed bots</td></tr>';
    } else {
      allowedTable.innerHTML = data.allowedBots.map(bot => `
        <tr>
          <td>${bot}</td>
          <td>
            <button class="btn btn-sm btn-danger" onclick="unallowBot('${bot}')">
              <i class="fas fa-ban"></i> Remove
            </button>
          </td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load bot settings:', err);
  }
}

async function unblockBot(name) {
  try {
    await apiPost('/bots/allow', { name });
    showToast('success', `Bot ${name} allowed`);
    loadBotSettings();
  } catch (err) {
    console.error('Failed to unblock bot:', err);
  }
}

async function unallowBot(name) {
  try {
    await apiPost('/bots/block', { name });
    showToast('success', `Bot ${name} blocked`);
    loadBotSettings();
  } catch (err) {
    console.error('Failed to block bot:', err);
  }
}

// Geo Blocking
async function loadGeoSettings() {
  try {
    const [blocked, allowed] = await Promise.all([
      apiGet('/countries/blocked'),
      apiGet('/countries/allowed')
    ]);
    
    const blockedTable = document.getElementById('blocked-countries-table');
    if (blocked.countries.length === 0) {
      blockedTable.innerHTML = '<tr><td colspan="3" class="text-center">No blocked countries</td></tr>';
    } else {
      blockedTable.innerHTML = blocked.countries.map(c => `
        <tr>
          <td><code>${c.code}</code></td>
          <td>${c.name}</td>
          <td>
            <button class="btn btn-sm btn-success" onclick="unblockCountry('${c.code}')">
              <i class="fas fa-check"></i> Unblock
            </button>
          </td>
        </tr>
      `).join('');
    }
    
    const allowedTable = document.getElementById('allowed-countries-table');
    if (allowed.countries.length === 0) {
      allowedTable.innerHTML = '<tr><td colspan="3" class="text-center">All countries allowed</td></tr>';
    } else {
      allowedTable.innerHTML = allowed.countries.map(c => `
        <tr>
          <td><code>${c.code}</code></td>
          <td>${c.name}</td>
          <td>
            <button class="btn btn-sm btn-danger" onclick="removeAllowedCountry('${c.code}')">
              <i class="fas fa-times"></i> Remove
            </button>
          </td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load geo settings:', err);
  }
}

async function unblockCountry(code) {
  try {
    await apiPost('/countries/unblock', { country: code });
    showToast('success', `Country ${code} unblocked`);
    loadGeoSettings();
  } catch (err) {
    console.error('Failed to unblock country:', err);
  }
}

async function removeAllowedCountry(code) {
  try {
    await apiPost('/countries/unallow', { country: code });
    showToast('success', `Country ${code} removed from allowed list`);
    loadGeoSettings();
  } catch (err) {
    console.error('Failed to remove allowed country:', err);
  }
}

// Webhooks
async function loadWebhooks() {
  try {
    const data = await apiGet('/webhooks');
    
    const table = document.getElementById('webhooks-table');
    if (data.webhooks.length === 0) {
      table.innerHTML = '<tr><td colspan="5" class="text-center">No webhooks configured</td></tr>';
    } else {
      table.innerHTML = data.webhooks.map(w => `
        <tr>
          <td>${w.url.substring(0, 50)}...</td>
          <td>${w.events.join(', ')}</td>
          <td>${w.minSeverity}</td>
          <td>
            <label class="toggle">
              <input type="checkbox" ${w.enabled ? 'checked' : ''} onchange="toggleWebhook('${w.id}', ${!w.enabled})">
              <span class="toggle-slider"></span>
            </label>
          </td>
          <td>
            <button class="btn btn-sm btn-secondary" onclick="testWebhook('${w.id}')">
              <i class="fas fa-play"></i> Test
            </button>
            <button class="btn btn-sm btn-danger" onclick="deleteWebhook('${w.id}')">
              <i class="fas fa-trash"></i>
            </button>
          </td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load webhooks:', err);
  }
}

function openWebhookModal() {
  document.getElementById('webhook-modal').classList.add('active');
  document.getElementById('webhook-form').reset();
}

async function handleWebhookSubmit(e) {
  e.preventDefault();
  
  const data = {
    url: document.getElementById('webhook-url').value,
    events: Array.from(document.getElementById('webhook-events').selectedOptions).map(o => o.value),
    minSeverity: document.getElementById('webhook-severity').value,
    method: document.getElementById('webhook-method').value,
    headers: JSON.parse(document.getElementById('webhook-headers').value || '{}'),
    enabled: document.getElementById('webhook-enabled').checked
  };
  
  try {
    await apiPost('/webhooks', data);
    showToast('success', 'Webhook added');
    closeModals();
    loadWebhooks();
  } catch (err) {
    console.error('Failed to add webhook:', err);
  }
}

async function toggleWebhook(id, enabled) {
  try {
    await apiPut(`/webhooks/${id}`, { enabled });
    showToast('success', `Webhook ${enabled ? 'enabled' : 'disabled'}`);
    loadWebhooks();
  } catch (err) {
    console.error('Failed to toggle webhook:', err);
  }
}

async function testWebhook(id) {
  try {
    const result = await apiPost(`/webhooks/${id}/test`);
    if (result.success) {
      showToast('success', 'Webhook test sent successfully');
    } else {
      showToast('error', `Webhook test failed: ${result.error}`);
    }
  } catch (err) {
    console.error('Failed to test webhook:', err);
  }
}

async function deleteWebhook(id) {
  if (!confirm('Are you sure you want to delete this webhook?')) return;
  
  try {
    await apiDelete(`/webhooks/${id}`);
    showToast('success', 'Webhook deleted');
    loadWebhooks();
  } catch (err) {
    console.error('Failed to delete webhook:', err);
  }
}

// Settings - Import/Export
async function loadSettings() {
  try {
    const data = await apiGet('/config');
    
    // Update toggles
    document.getElementById('bot-detection-toggle').checked = data.features.botDetection;
    document.getElementById('geo-blocking-toggle').checked = data.features.geoBlocking;
  } catch (err) {
    console.error('Failed to load settings:', err);
  }
}

async function exportConfig() {
  try {
    const response = await fetch(`${API_BASE}/export`, { credentials: 'same-origin' });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `waf-config-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    showToast('success', 'Configuration exported');
  } catch (err) {
    console.error('Failed to export config:', err);
    showToast('error', 'Export failed');
  }
}

async function importConfig(file) {
  try {
    const text = await file.text();
    const config = JSON.parse(text);
    
    await apiPost('/import', config);
    showToast('success', 'Configuration imported successfully');
    location.reload();
  } catch (err) {
    console.error('Failed to import config:', err);
    showToast('error', 'Import failed: ' + err.message);
  }
}

// Expose functions to global scope for onclick handlers
window.toggleRule = toggleRule;
window.editRule = editRule;
window.deleteRule = deleteRule;
window.unblockIP = unblockIP;
window.unwhitelistIP = unwhitelistIP;
window.unblockBot = unblockBot;
window.unallowBot = unallowBot;
window.unblockCountry = unblockCountry;
window.removeAllowedCountry = removeAllowedCountry;
window.toggleWebhook = toggleWebhook;
window.testWebhook = testWebhook;
window.deleteWebhook = deleteWebhook;
window.manualMemoryCleanup = manualMemoryCleanup;
window.editUser = editUser;
window.deleteUser = deleteUser;
window.resetUserPassword = resetUserPassword;

// ============================================================
// User management (admin)
// ============================================================

async function loadUsers() {
  try {
    const data = await apiGet('/users');
    const tbody = document.getElementById('users-table');
    if (!tbody) return;
    if (!data.users.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center">No users</td></tr>';
      return;
    }
    tbody.innerHTML = data.users.map(u => `
      <tr>
        <td><code>${escapeHtml(u.username)}</code></td>
        <td>${escapeHtml(u.displayName || '')}</td>
        <td><span class="badge badge-${u.role === 'admin' ? 'danger' : u.role === 'operator' ? 'warning' : 'info'}">${u.role}</span></td>
        <td>${u.createdAt ? new Date(u.createdAt).toLocaleDateString() : ''}</td>
        <td>${u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : '<span class="text-muted">never</span>'}</td>
        <td>
          <button class="btn btn-sm btn-secondary" onclick="editUser('${u.id}')" title="Edit">
            <i class="fas fa-edit"></i>
          </button>
          <button class="btn btn-sm btn-warning" onclick="resetUserPassword('${u.id}', '${escapeHtml(u.username)}')" title="Reset password">
            <i class="fas fa-key"></i>
          </button>
          <button class="btn btn-sm btn-danger" onclick="deleteUser('${u.id}', '${escapeHtml(u.username)}')" title="Delete">
            <i class="fas fa-trash"></i>
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    // 401 handled in apiGet
  }
}

function openUserModal(user) {
  const modal = document.getElementById('user-modal');
  const title = document.getElementById('user-modal-title');
  const pwGroup = document.getElementById('user-password-group');
  const pwInput = document.getElementById('user-password');
  const editId = document.getElementById('user-edit-id');
  if (user) {
    title.textContent = 'Edit User';
    editId.value = user.id;
    document.getElementById('user-username').value = user.username;
    document.getElementById('user-username').disabled = true;
    document.getElementById('user-displayname').value = user.displayName || '';
    document.getElementById('user-role-select').value = user.role || 'viewer';
    pwGroup.style.display = 'none';
    pwInput.required = false;
  } else {
    title.textContent = 'Add User';
    editId.value = '';
    document.getElementById('user-username').disabled = false;
    document.getElementById('user-form').reset();
    pwGroup.style.display = '';
    pwInput.required = true;
  }
  modal.classList.add('active');
}

async function editUser(id) {
  try {
    const data = await apiGet('/users');
    const user = (data.users || []).find(u => u.id === id);
    if (user) openUserModal(user);
  } catch {}
}

async function handleUserSubmit(e) {
  e.preventDefault();
  const id = document.getElementById('user-edit-id').value;
  const payload = {
    username: document.getElementById('user-username').value.trim(),
    displayName: document.getElementById('user-displayname').value.trim() || undefined,
    role: document.getElementById('user-role-select').value
  };
  if (!id) payload.password = document.getElementById('user-password').value;

  try {
    if (id) {
      await apiPut('/users/' + encodeURIComponent(id), payload);
      showToast('success', 'User updated');
    } else {
      await apiPost('/users', payload);
      showToast('success', 'User created');
    }
    closeModals();
    loadUsers();
  } catch (err) {
    // toast already shown
  }
}

async function deleteUser(id, username) {
  if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  try {
    await apiDelete('/users/' + encodeURIComponent(id));
    showToast('success', 'User deleted');
    loadUsers();
  } catch {}
}

async function resetUserPassword(id, username) {
  if (!confirm(`Reset password for "${username}"? A new random password will be generated and shown once.`)) return;
  try {
    const res = await apiPost('/users/' + encodeURIComponent(id) + '/reset-password', {});
    if (res.password) {
      prompt('New password for ' + username + ' (copy it now):', res.password);
    }
  } catch {}
}

// ============================================================
// Change own password
// ============================================================

async function handlePasswordChange(e) {
  e.preventDefault();
  const oldPassword = document.getElementById('pw-current').value;
  const newPassword = document.getElementById('pw-new').value;
  try {
    await apiPost('/auth/change-password', { oldPassword, newPassword });
    showToast('success', 'Password changed');
    document.getElementById('password-form').reset();
    closeModals();
  } catch {}
}

// ============================================================
// Audit log
// ============================================================

async function loadAuditLog() {
  const userFilter = document.getElementById('audit-user-filter')?.value.trim();
  const actionFilter = document.getElementById('audit-action-filter')?.value.trim();
  const qs = new URLSearchParams();
  if (userFilter) qs.set('user', userFilter);
  if (actionFilter) qs.set('action', actionFilter);
  qs.set('limit', '200');
  try {
    const data = await apiGet('/audit?' + qs.toString());
    const tbody = document.getElementById('audit-table');
    if (!tbody) return;
    if (!data.entries.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center">No audit entries</td></tr>';
      return;
    }
    tbody.innerHTML = data.entries.map(e => `
      <tr>
        <td>${new Date(e.timestamp).toLocaleString()}</td>
        <td><code>${escapeHtml(e.user || 'system')}</code></td>
        <td>${escapeHtml(e.action)}</td>
        <td>${escapeHtml(e.ip || '')}</td>
        <td><span class="badge badge-${e.success ? 'success' : 'danger'}">${e.success ? 'ok' : 'fail'}</span></td>
        <td><code class="text-muted">${escapeHtml(JSON.stringify(e.details || {}))}</code></td>
      </tr>
    `).join('');
  } catch {}
}

// ============================================================
// HTML escape utility (used in dynamic content)
// ============================================================
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
