/**
 * WAF Server - Main entry point
 * Runs the WAF management API and serves the web UI
 */

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { WAFMiddleware } = require('./middleware');
const { createAPIRouter } = require('./api');

const app = express();
const PORT = process.env.PORT || 3000;
const WAF_UI_PORT = process.env.WAF_UI_PORT || 3001;

// Create WAF middleware instance
const waf = new WAFMiddleware({
  logAllRequests: true
});

// ===== WAF MANAGEMENT SERVER (Port 3001) =====
const managementApp = express();

managementApp.use(bodyParser.json());
managementApp.use(bodyParser.urlencoded({ extended: true }));

// API routes
managementApp.use('/api', createAPIRouter(waf));

// Serve static files for web UI
managementApp.use(express.static(path.join(__dirname, '..', 'public')));

// Serve the main management UI
managementApp.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Health check
managementApp.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start management server
managementApp.listen(WAF_UI_PORT, () => {
  console.log(`🛡️  WAF Management UI running on http://localhost:${WAF_UI_PORT}`);
  console.log(`📊 Dashboard: http://localhost:${WAF_UI_PORT}`);
  console.log(`🔌 API: http://localhost:${WAF_UI_PORT}/api`);
});

// ===== PROTECTED APP SERVER (Port 3000) =====
// This demonstrates how to protect an application with the WAF

// Apply WAF middleware BEFORE other routes
app.use(waf.middleware());

// Body parsing for protected app
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Protected routes - these will be filtered by WAF
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the protected application!',
    timestamp: new Date().toISOString(),
    status: 'secure'
  });
});

app.get('/api/users', (req, res) => {
  res.json([
    { id: 1, name: 'Alice', role: 'admin' },
    { id: 2, name: 'Bob', role: 'user' },
    { id: 3, name: 'Charlie', role: 'user' }
  ]);
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  res.json({
    message: 'Login endpoint (protected by WAF)',
    received: { username, password: password ? '***' : null }
  });
});

app.get('/api/search', (req, res) => {
  const { q } = req.query;
  res.json({
    message: 'Search endpoint (protected by WAF)',
    query: q,
    results: []
  });
});

// Simulate vulnerable endpoints for testing
app.post('/api/comment', (req, res) => {
  res.json({
    message: 'Comment submitted',
    comment: req.body.comment
  });
});

app.get('/api/file', (req, res) => {
  res.json({
    message: 'File endpoint',
    file: req.query.file
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start protected app server
app.listen(PORT, () => {
  console.log(`\n🔒 Protected Application running on http://localhost:${PORT}`);
  console.log(`   All requests to this server are filtered by WAF\n`);
  console.log('Test endpoints:');
  console.log(`  GET  http://localhost:${PORT}/api/users`);
  console.log(`  POST http://localhost:${PORT}/api/login`);
  console.log(`  GET  http://localhost:${PORT}/api/search?q=test`);
  console.log(`\nTry these attacks (they will be blocked):`);
  console.log(`  GET  http://localhost:${PORT}/api/search?q=' OR '1'='1`);
  console.log(`  POST http://localhost:${PORT}/api/comment with body: {"comment": "<script>alert('xss')</script>"}`);
  console.log(`  GET  http://localhost:${PORT}/api/file?file=../../../etc/passwd`);
});

module.exports = { app, managementApp, waf };
