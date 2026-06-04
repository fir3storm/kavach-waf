/**
 * Kavach WAF Server - Main entry point
 * Runs the WAF management API and serves the web UI
 */

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { WAFMiddleware } = require('./middleware');
const { createAPIRouter } = require('./api');
const { MemoryManager } = require('./memory-manager');
const { WorkerQueue } = require('./worker-queue');
const { UserManager } = require('./user-manager');
const { SessionManager } = require('./session');
const { RedisClient } = require('./cache/redis-client');
const { CSRFProtection } = require('./csrf-protection');
const { HealthCheck } = require('./health/health-check');
const { PrometheusMetrics } = require('./metrics/prometheus');
const { JWTValidator } = require('./jwt-validator');
const { IPReputationService } = require('./ip-reputation');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;
const WAF_UI_PORT = process.env.WAF_UI_PORT || 3001;

// Initialize User Manager
const userManager = new UserManager({
  dataDir: path.join(__dirname, '..', 'data'),
  logger: console
});

// Bootstrap default admin on first run
const bootstrapResult = userManager.bootstrap();
if (bootstrapResult.created) {
  console.log('\n🔐 Default admin user created.');
  console.log(`   Username: ${bootstrapResult.username}`);
  console.log(`   Password: ${bootstrapResult.password}`);
  console.log('   ⚠️  Please log in and change this password immediately.\n');
} else {
  console.log(`🔐 ${userManager.listUsers().length} user(s) loaded`);
}

// Initialize Session Manager
const sessionManager = new SessionManager({
  dataDir: path.join(__dirname, '..', 'data'),
  ttlMs: 8 * 60 * 60 * 1000,
  isProduction: process.env.NODE_ENV === 'production',
  logger: console
});

// Parse allowed origins for CORS (comma-separated env var)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

// Initialize Memory Manager
const memoryManager = new MemoryManager({
  maxHeapSize: 512 * 1024 * 1024,
  gcThreshold: 0.8,
  criticalThreshold: 0.95,
  checkInterval: 30000,
  maxLogsInMemory: 1000,
  maxRateLimitEntries: 10000,
  logger: console
});

// Initialize Redis Client (for distributed caching + rate limiting)
const redisClient = new RedisClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD,
  keyPrefix: 'kavach:',
  ttlSeconds: 3600
});

// Initialize IP Reputation Service
const ipReputation = new IPReputationService({
  cache: redisClient,
  cacheTTL: 3600
});

// Initialize Prometheus Metrics
const prometheusMetrics = new PrometheusMetrics({ prefix: 'kavach_' });

// Initialize Health Checks
const healthCheck = new HealthCheck({
  dataDir: path.join(__dirname, '..', 'data'),
  minUptimeMs: 5000
});

// Initialize CSRF Protection
const csrfProtection = new CSRFProtection({
  secret: sessionManager.secret,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  excludedPaths: ['/api/auth/login', '/api/auth/logout', '/api/webhooks']
});

// Initialize JWT Validator
const jwtValidator = new JWTValidator({
  secret: process.env.JWT_SECRET,
  issuer: process.env.JWT_ISSUER,
  audience: process.env.JWT_AUDIENCE,
  jwksUri: process.env.JWKS_URI
});

// Initialize Worker Queue (graceful fallback if Redis unavailable)
let workerQueue = null;
async function initializeWorkerQueue() {
  try {
    workerQueue = new WorkerQueue({
      logger: console,
      redisHost: process.env.REDIS_HOST || 'localhost',
      redisPort: process.env.REDIS_PORT || 6379,
      redisPassword: process.env.REDIS_PASSWORD
    });
    await workerQueue.initialize();
    if (workerQueue.initialized) {
      console.log('✅ Worker Queue initialized');
    }
  } catch (err) {
    console.warn('⚠️  Redis not available, running without worker queue:', err.message);
    workerQueue = null;
  }
}

// Metrics callback for WAF engine
function metricsCallback(method, blocked, reason, severity) {
  prometheusMetrics.recordRequest(method, blocked, reason, severity);
  if (blocked && reason) {
    prometheusMetrics.recordThreat(reason);
  }
}

// Create WAF middleware instance
const waf = new WAFMiddleware({
  logAllRequests: true,
  enableWorkerQueue: true,
  workerQueue: () => workerQueue,
  redisClient,
  ipReputation,
  metricsCallback
});

// Start monitoring
memoryManager.start();

// Make globals available for cleanup
const engine = waf.getEngine();
global.wafEngine = engine;
global.wafLogger = waf.getLogger();
global.wafRateLimiter = engine.rateLimiter;

// Register memory manager cleanup references
memoryManager.registerReference('redis-fallback', redisClient, {
  cleanup: () => redisClient.cleanup()
});

// ===== WAF MANAGEMENT SERVER (Port 3001) =====
const managementApp = express();

// Expose userManager to the API router via app.locals (session middleware reads it)
managementApp.locals.userManager = userManager;

// CSRF cookie middleware (sets double-submit cookie before body parsing)
managementApp.use(csrfProtection.middleware());

managementApp.use(bodyParser.json());
managementApp.use(bodyParser.urlencoded({ extended: true }));

// Health check middleware
managementApp.use(healthCheck.middleware({ redisClient, workerQueue, memoryManager }));

// Prometheus metrics middleware
managementApp.use(prometheusMetrics.middleware());

// API routes (now passes userManager, sessionManager, allowedOrigins, jwtValidator, ipReputation)
managementApp.use('/api', createAPIRouter({
  wafMiddleware: waf,
  userManager,
  sessionManager,
  allowedOrigins,
  jwtValidator,
  ipReputation,
  csrfProtection
}));

// JWT validation endpoints (mounted directly for flexibility)
managementApp.post('/api/jwt/validate', async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token required' });
  const result = await jwtValidator.validate(token);
  res.json(result);
});

managementApp.post('/api/jwt/decode', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token required' });
  res.json({ decoded: jwtValidator.decode(token) });
});

// Serve static files for web UI
managementApp.use(express.static(path.join(__dirname, '..', 'public')));

// Serve the main management UI
managementApp.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Start management server
const managementServer = managementApp.listen(WAF_UI_PORT, async () => {
  console.log(`🛡️  Kavach WAF Management UI running on http://localhost:${WAF_UI_PORT}`);
  console.log(`📊 Dashboard: http://localhost:${WAF_UI_PORT}`);
  console.log(`🔌 API: http://localhost:${WAF_UI_PORT}/api`);
  console.log(`💾 Memory Manager active`);
  console.log(`📈 Prometheus metrics at /metrics`);
  console.log(`🏥 Health checks at /health, /health/live, /health/ready`);
  
  // Initialize worker queue (non-blocking)
  initializeWorkerQueue().catch(err => {
    console.warn('Worker Queue initialization skipped:', err.message);
  });
});

// WebSocket server for real-time dashboard updates
const wss = new WebSocket.Server({ server: managementServer, path: '/ws' });
const wsClients = new Set();

wss.on('connection', (ws) => {
  wsClients.add(ws);
  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

function broadcastToDashboard(data) {
  const msg = JSON.stringify(data);
  wsClients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  });
}

// Expose broadcast for engine/webhook use
global.broadcastToDashboard = broadcastToDashboard;

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

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  memoryManager.stop();
  if (workerQueue) {
    await workerQueue.close();
  }
  if (redisClient) {
    await redisClient.close();
  }
  wss.close();
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  memoryManager.stop();
});

module.exports = { app, managementApp, waf, memoryManager, workerQueue, userManager, sessionManager, redisClient, prometheusMetrics, healthCheck };
