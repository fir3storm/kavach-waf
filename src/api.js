/**
 * REST API for WAF Management
 *
 * All routes are mounted under /api and require authentication.
 * Auth flow:
 *   - Public: POST /api/auth/login
 *   - Authenticated: everything else (with role checks for mutating routes)
 *
 * Role policy:
 *   - viewer   : GET-only
 *   - operator : + POST/PUT/DELETE on rules, IPs, countries, webhooks, /test
 *   - admin    : + /api/config, /api/users/*, /api/audit
 */

const express = require('express');
const { ROLES } = require('./user-manager');

function createAPIRouter({ wafMiddleware, userManager, sessionManager, allowedOrigins = [], jwtValidator, ipReputation, csrfProtection }) {
  const router = express.Router();
  const engine = wafMiddleware.getEngine();
  const logger = wafMiddleware.getLogger();
  const sm = sessionManager;

  // ---- CORS (configurable, default same-origin only) ----
  router.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Vary', 'Origin');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  // ---- Helper: get the full user record (for passwordVersion on change-password) ----

  // ===========================================================
  // PUBLIC: AUTH
  // ===========================================================
  router.post('/auth/login', (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password required' });
    }
    const result = userManager.verifyLogin(username, password);
    const ip = req.ip || req.headers['x-forwarded-for'] || null;
    if (!result.success) {
      userManager.logAudit({ user: username, action: 'login_failed', ip, success: false, details: { reason: result.reason } });
      if (result.reason === 'locked_out') {
        return res.status(429).json({ error: 'Account locked. Try again later.', lockedUntil: result.lockedUntil });
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    userManager.logAudit({ user: result.user.username, action: 'login_success', ip, success: true });

    // Re-fetch the full record to get passwordVersion for the session.
    const full = userManager.users.get(result.user.id);
    const token = sm.createToken(full);
    sm.setCookie(res, token);
    res.json({ user: result.user });
  });

  router.post('/auth/logout', (req, res) => {
    const u = req.user?.username;
    if (u) userManager.logAudit({ user: u, action: 'logout', ip: req.ip, success: true });
    sm.clearCookie(res);
    res.json({ success: true });
  });

  // Authenticated routes below this point
  router.use(sm.middleware());
  router.use((req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    next();
  });

  router.get('/auth/me', (req, res) => {
    const full = userManager.users.get(req.user.id);
    res.json({ user: { id: full.id, username: full.username, role: full.role, displayName: full.displayName } });
  });

  router.post('/auth/change-password', (req, res) => {
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'oldPassword and newPassword required' });
    }
    const full = userManager.users.get(req.user.id);
    if (!full || !userManager.verifyPassword(oldPassword, full.password)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    try {
      userManager.changePassword(req.user.id, newPassword);
      userManager.logAudit({ user: req.user.username, action: 'password_changed', ip: req.ip, success: true });
      // Issue a new session cookie so the user isn't kicked out.
      const fresh = userManager.users.get(req.user.id);
      const token = sm.createToken(fresh);
      sm.setCookie(res, token);
      res.json({ success: true });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // ===========================================================
  // ADMIN: USERS
  // ===========================================================
  const usersRouter = express.Router();
  usersRouter.use(sm.requireAuth('admin'));

  usersRouter.get('/', (req, res) => {
    res.json({ users: userManager.listUsers(), count: userManager.listUsers().length });
  });

  usersRouter.post('/', (req, res) => {
    const { username, password, role, displayName } = req.body || {};
    try {
      const created = userManager.createUser({ username, password, role, displayName });
      userManager.logAudit({ user: req.user.username, action: 'user_created', ip: req.ip, success: true, details: { newUser: created.username, role } });
      res.status(201).json(created);
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  usersRouter.put('/:id', (req, res) => {
    const { username, role, displayName } = req.body || {};
    try {
      const updated = userManager.updateUser(req.params.id, { username, role, displayName });
      if (!updated) return res.status(404).json({ error: 'User not found' });
      userManager.logAudit({ user: req.user.username, action: 'user_updated', ip: req.ip, success: true, details: { id: req.params.id } });
      res.json(updated);
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  usersRouter.delete('/:id', (req, res) => {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    try {
      const ok = userManager.deleteUser(req.params.id);
      if (!ok) return res.status(404).json({ error: 'User not found' });
      userManager.logAudit({ user: req.user.username, action: 'user_deleted', ip: req.ip, success: true, details: { id: req.params.id } });
      res.json({ success: true });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  usersRouter.post('/:id/reset-password', (req, res) => {
    try {
      const newPw = userManager.resetPassword(req.params.id);
      if (!newPw) return res.status(404).json({ error: 'User not found' });
      userManager.logAudit({ user: req.user.username, action: 'password_reset', ip: req.ip, success: true, details: { id: req.params.id } });
      res.json({ success: true, password: newPw });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  router.use('/users', usersRouter);

  // ===========================================================
  // ADMIN: AUDIT
  // ===========================================================
  const auditRouter = express.Router();
  auditRouter.use(sm.requireAuth('admin'));

  auditRouter.get('/', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
    const entries = userManager.readAudit({
      user: req.query.user,
      action: req.query.action,
      limit
    });
    res.json({ entries, count: entries.length });
  });

  router.use('/audit', auditRouter);

  // ===========================================================
  // READ: any authenticated user
  // ===========================================================
  const readRouter = express.Router();
  readRouter.use(sm.requireAuth('viewer', 'operator', 'admin'));

  readRouter.get('/stats', (req, res) => {
    const engineStats = engine.getStats();
    const logStats = logger.getStats(req.query.range || '24h');
    res.json({ engine: engineStats, logs: logStats });
  });

  readRouter.get('/stats/realtime', (req, res) => {
    res.json({
      timestamp: Date.now(),
      ...engine.getStats(),
      recentLogs: logger.getLogs({ limit: 10 })
    });
  });

  readRouter.get('/rules', (req, res) => {
    res.json({ rules: engine.getRules(), count: engine.getRules().length });
  });

  readRouter.get('/rules/:id', (req, res) => {
    const rule = engine.getRule(req.params.id);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    res.json(rule);
  });

  readRouter.get('/ips/blocked', (req, res) => {
    res.json({ ips: engine.getBlockedIPs(), count: engine.getBlockedIPs().length });
  });
  readRouter.get('/ips/whitelisted', (req, res) => {
    res.json({ ips: engine.getWhitelistedIPs(), count: engine.getWhitelistedIPs().length });
  });
  readRouter.get('/countries/blocked', (req, res) => {
    res.json({ countries: engine.getBlockedCountries(), count: engine.getBlockedCountries().length });
  });
  readRouter.get('/countries/allowed', (req, res) => {
    res.json({ countries: engine.getAllowedCountries(), count: engine.getAllowedCountries().length });
  });
  readRouter.get('/webhooks', (req, res) => {
    res.json({ webhooks: engine.webhook.getWebhooks(), enabled: engine.webhook.enabled });
  });
  readRouter.get('/bots', (req, res) => {
    res.json({
      enabled: engine.config.enableBotDetection,
      blockedBots: engine.botDetector.getBlockedBots(),
      allowedBots: engine.botDetector.getAllowedBots()
    });
  });

  // CSRF token endpoint
  router.get('/csrf-token', (req, res) => {
    const token = req.csrfToken ? req.csrfToken() : (csrfProtection ? csrfProtection.generateToken() : null);
    res.json({ token });
  });

  // IP Reputation lookup
  readRouter.get('/ip-reputation/:ip', async (req, res) => {
    if (!ipReputation) return res.status(503).json({ error: 'IP reputation service not configured' });
    const result = await ipReputation.checkIP(req.params.ip);
    res.json(result);
  });

  readRouter.get('/config', (req, res) => {
    res.json({
      config: engine.config,
      features: {
        botDetection: engine.config.enableBotDetection,
        geoBlocking: engine.config.enableGeoBlocking,
        sanitization: engine.config.enableSanitization,
        webhooks: engine.config.enableWebhooks
      }
    });
  });
  readRouter.get('/logs', (req, res) => {
    const options = {
      limit: parseInt(req.query.limit) || 100,
      type: req.query.type,
      since: req.query.since
    };
    res.json({ logs: logger.getLogs(options), count: logger.getLogs(options).length });
  });
  readRouter.get('/logs/blocked', (req, res) => {
    const options = { limit: parseInt(req.query.limit) || 100, type: 'blocked' };
    res.json({ logs: logger.getLogs(options), count: logger.getLogs(options).length });
  });

  router.use(readRouter);

  // ===========================================================
  // OPERATOR: rules / IPs / countries / webhooks / bots / test
  // ===========================================================
  const opRouter = express.Router();
  opRouter.use(sm.requireAuth('operator', 'admin'));

  // Rules
  opRouter.post('/rules', (req, res) => {
    try {
      const rule = req.body;
      if (!rule.name || !rule.type || !rule.pattern) {
        return res.status(400).json({ error: 'Missing required fields: name, type, pattern' });
      }
      if (typeof rule.pattern === 'string') {
        try { rule.pattern = new RegExp(rule.pattern, 'i'); }
        catch (e) { return res.status(400).json({ error: 'Invalid regex pattern' }); }
      }
      const created = engine.addRule(rule);
      logger.logEvent('rule_created', { ruleId: created.id, user: req.user.username });
      res.status(201).json(created);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  opRouter.put('/rules/:id', (req, res) => {
    try {
      const updates = req.body;
      if (updates.pattern && typeof updates.pattern === 'string') {
        try { updates.pattern = new RegExp(updates.pattern, 'i'); }
        catch (e) { return res.status(400).json({ error: 'Invalid regex pattern' }); }
      }
      const updated = engine.updateRule(req.params.id, updates);
      if (!updated) return res.status(404).json({ error: 'Rule not found' });
      logger.logEvent('rule_updated', { ruleId: req.params.id, updates, user: req.user.username });
      res.json(updated);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  opRouter.delete('/rules/:id', (req, res) => {
    const deleted = engine.deleteRule(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Rule not found' });
    logger.logEvent('rule_deleted', { ruleId: req.params.id, user: req.user.username });
    res.json({ success: true });
  });

  opRouter.post('/rules/:id/toggle', (req, res) => {
    const rule = engine.getRule(req.params.id);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    const updated = engine.updateRule(req.params.id, { enabled: !rule.enabled });
    logger.logEvent('rule_toggled', { ruleId: req.params.id, enabled: updated.enabled, user: req.user.username });
    res.json(updated);
  });

  // IPs
  opRouter.post('/ips/block', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP address required' });
    engine.blockIP(ip);
    logger.logEvent('ip_blocked', { ip, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/ips/unblock', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP address required' });
    engine.unblockIP(ip);
    logger.logEvent('ip_unblocked', { ip, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/ips/whitelist', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP address required' });
    engine.whitelistIP(ip);
    logger.logEvent('ip_whitelisted', { ip, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/ips/unwhitelist', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP address required' });
    engine.unwhitelistIP(ip);
    logger.logEvent('ip_unwhitelisted', { ip, user: req.user.username });
    res.json({ success: true });
  });

  // Countries
  opRouter.post('/countries/block', (req, res) => {
    const { country } = req.body || {};
    if (!country) return res.status(400).json({ error: 'Country code required' });
    engine.blockCountry(country);
    logger.logEvent('country_blocked', { country, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/countries/unblock', (req, res) => {
    const { country } = req.body || {};
    if (!country) return res.status(400).json({ error: 'Country code required' });
    engine.unblockCountry(country);
    logger.logEvent('country_unblocked', { country, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/countries/allow', (req, res) => {
    const { country } = req.body || {};
    if (!country) return res.status(400).json({ error: 'Country code required' });
    engine.allowCountry(country);
    logger.logEvent('country_allowed', { country, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/countries/unallow', (req, res) => {
    const { country } = req.body || {};
    if (!country) return res.status(400).json({ error: 'Country code required' });
    engine.removeAllowedCountry(country);
    logger.logEvent('country_unallowed', { country, user: req.user.username });
    res.json({ success: true });
  });

  // Webhooks
  opRouter.post('/webhooks', (req, res) => {
    const webhook = engine.webhook.addWebhook(req.body);
    logger.logEvent('webhook_added', { webhookId: webhook.id, user: req.user.username });
    res.status(201).json(webhook);
  });
  opRouter.put('/webhooks/:id', (req, res) => {
    const webhook = engine.webhook.updateWebhook(req.params.id, req.body);
    if (!webhook) return res.status(404).json({ error: 'Webhook not found' });
    logger.logEvent('webhook_updated', { webhookId: req.params.id, user: req.user.username });
    res.json(webhook);
  });
  opRouter.delete('/webhooks/:id', (req, res) => {
    const deleted = engine.webhook.removeWebhook(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Webhook not found' });
    logger.logEvent('webhook_deleted', { webhookId: req.params.id, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/webhooks/:id/test', async (req, res) => {
    const result = await engine.webhook.testWebhook(req.params.id);
    res.json(result);
  });

  // Bots
  opRouter.post('/bots/block', (req, res) => {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Bot name required' });
    engine.botDetector.blockBot(name);
    res.json({ success: true });
  });
  opRouter.post('/bots/allow', (req, res) => {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Bot name required' });
    engine.botDetector.allowBot(name);
    res.json({ success: true });
  });

  // IP Reputation management
  opRouter.post('/ip-reputation/blacklist', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP address required' });
    if (ipReputation) ipReputation.addToBlacklist(ip);
    engine.blockIP(ip);
    logger.logEvent('ip_blacklisted_reputation', { ip, user: req.user.username });
    res.json({ success: true });
  });
  opRouter.post('/ip-reputation/whitelist', (req, res) => {
    const { ip } = req.body || {};
    if (!ip) return res.status(400).json({ error: 'IP address required' });
    if (ipReputation) ipReputation.addToWhitelist(ip);
    engine.whitelistIP(ip);
    logger.logEvent('ip_whitelisted_reputation', { ip, user: req.user.username });
    res.json({ success: true });
  });

  // Test
  opRouter.post('/test', async (req, res) => {
    const { url, method, headers, body, query } = req.body || {};
    const mockReq = {
      url: url || '/',
      path: url ? url.split('?')[0] : '/',
      method: method || 'GET',
      headers: headers || {},
      body: body || {},
      query: query || {}
    };
    const result = await engine.analyzeRequest(mockReq);
    res.json({
      request: mockReq,
      result: { allowed: result.allowed, violations: result.violations, action: result.action }
    });
  });

  // Reset stats
  opRouter.post('/reset-stats', (req, res) => {
    engine.resetStats();
    logger.logEvent('stats_reset', { user: req.user.username });
    res.json({ success: true });
  });

  // Export (operator can export for backup)
  opRouter.get('/export', (req, res) => {
    const config = engine.exportConfig();
    res.setHeader('Content-Disposition', 'attachment; filename=waf-config.json');
    res.json(config);
  });

  // Import (operator)
  opRouter.post('/import', (req, res) => {
    const config = req.body;
    const result = engine.importConfig(config);
    if (result.success) {
      logger.logEvent('config_imported', { user: req.user.username });
      res.json({ success: true });
    } else {
      res.status(400).json({ success: false, error: result.error });
    }
  });

  // Logs clear (operator)
  opRouter.delete('/logs', (req, res) => {
    logger.clearLogs();
    res.json({ success: true });
  });

  router.use(opRouter);

  // ===========================================================
  // ADMIN: config
  // ===========================================================
  const adminRouter = express.Router();
  adminRouter.use(sm.requireAuth('admin'));

  adminRouter.put('/config', (req, res) => {
    engine.config = { ...engine.config, ...req.body };
    logger.logEvent('config_updated', { config: engine.config, user: req.user.username });
    res.json({ success: true, config: engine.config });
  });

  router.use(adminRouter);

  return router;
}

module.exports = { createAPIRouter };
