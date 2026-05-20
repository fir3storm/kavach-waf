/**
 * WAF Management Dashboard JavaScript
 */

const API_BASE = '/api';

// State
let currentPage = 'dashboard';
let charts = {};
let refreshInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initEventListeners();
  loadDashboardData();
  startAutoRefresh();
});

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
}

// API Functions
async function apiGet(endpoint) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    showToast('error', `API Error: ${err.message}`);
    throw err;
  }
}

async function apiPost(endpoint, data) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    showToast('error', `API Error: ${err.message}`);
    throw err;
  }
}

async function apiPut(endpoint, data) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    showToast('error', `API Error: ${err.message}`);
    throw err;
  }
}

async function apiDelete(endpoint) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'DELETE'
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    showToast('error', `API Error: ${err.message}`);
    throw err;
  }
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
  }, 10000);
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
    const response = await fetch(`${API_BASE}/export`);
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
