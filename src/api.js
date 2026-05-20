/**
 * REST API for WAF Management
 */

const express = require('express');

function createAPIRouter(wafMiddleware) {
  const router = express.Router();
  const engine = wafMiddleware.getEngine();
  const logger = wafMiddleware.getLogger();

  // CORS middleware for API
  router.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    next();
  });

  // ===== STATISTICS =====
  
  // Get WAF statistics
  router.get('/stats', (req, res) => {
    const engineStats = engine.getStats();
    const logStats = logger.getStats(req.query.range || '24h');
    
    res.json({
      engine: engineStats,
      logs: logStats
    });
  });

  // Get real-time stats (for dashboard)
  router.get('/stats/realtime', (req, res) => {
    res.json({
      timestamp: Date.now(),
      ...engine.getStats(),
      recentLogs: logger.getLogs({ limit: 10 })
    });
  });

  // ===== RULES MANAGEMENT =====

  // Get all rules
  router.get('/rules', (req, res) => {
    res.json({
      rules: engine.getRules(),
      count: engine.getRules().length
    });
  });

  // Get single rule
  router.get('/rules/:id', (req, res) => {
    const rule = engine.getRule(req.params.id);
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    res.json(rule);
  });

  // Create new rule
  router.post('/rules', (req, res) => {
    try {
      const rule = req.body;
      
      // Validate rule
      if (!rule.name || !rule.type || !rule.pattern) {
        return res.status(400).json({ 
          error: 'Missing required fields: name, type, pattern' 
        });
      }

      // Convert pattern string to RegExp if needed
      if (typeof rule.pattern === 'string') {
        try {
          rule.pattern = new RegExp(rule.pattern, 'i');
        } catch (e) {
          return res.status(400).json({ error: 'Invalid regex pattern' });
        }
      }

      const created = engine.addRule(rule);
      logger.logEvent('rule_created', { ruleId: created.id, rule: created });
      
      res.status(201).json(created);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Update rule
  router.put('/rules/:id', (req, res) => {
    try {
      const updates = req.body;
      
      // Convert pattern string to RegExp if needed
      if (updates.pattern && typeof updates.pattern === 'string') {
        try {
          updates.pattern = new RegExp(updates.pattern, 'i');
        } catch (e) {
          return res.status(400).json({ error: 'Invalid regex pattern' });
        }
      }

      const updated = engine.updateRule(req.params.id, updates);
      if (!updated) {
        return res.status(404).json({ error: 'Rule not found' });
      }
      
      logger.logEvent('rule_updated', { ruleId: req.params.id, updates });
      res.json(updated);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Delete rule
  router.delete('/rules/:id', (req, res) => {
    const deleted = engine.deleteRule(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    
    logger.logEvent('rule_deleted', { ruleId: req.params.id });
    res.json({ success: true, message: 'Rule deleted' });
  });

  // Toggle rule enabled status
  router.post('/rules/:id/toggle', (req, res) => {
    const rule = engine.getRule(req.params.id);
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    
    const updated = engine.updateRule(req.params.id, { enabled: !rule.enabled });
    logger.logEvent('rule_toggled', { ruleId: req.params.id, enabled: updated.enabled });
    
    res.json(updated);
  });

  // ===== IP MANAGEMENT =====

  // Get blocked IPs
  router.get('/ips/blocked', (req, res) => {
    res.json({
      ips: engine.getBlockedIPs(),
      count: engine.getBlockedIPs().length
    });
  });

  // Get whitelisted IPs
  router.get('/ips/whitelisted', (req, res) => {
    res.json({
      ips: engine.getWhitelistedIPs(),
      count: engine.getWhitelistedIPs().length
    });
  });

  // Block an IP
  router.post('/ips/block', (req, res) => {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP address required' });
    }
    
    engine.blockIP(ip);
    logger.logEvent('ip_blocked', { ip });
    
    res.json({ success: true, message: `IP ${ip} blocked` });
  });

  // Unblock an IP
  router.post('/ips/unblock', (req, res) => {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP address required' });
    }
    
    engine.unblockIP(ip);
    logger.logEvent('ip_unblocked', { ip });
    
    res.json({ success: true, message: `IP ${ip} unblocked` });
  });

  // Whitelist an IP
  router.post('/ips/whitelist', (req, res) => {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP address required' });
    }
    
    engine.whitelistIP(ip);
    logger.logEvent('ip_whitelisted', { ip });
    
    res.json({ success: true, message: `IP ${ip} whitelisted` });
  });

  // Remove IP from whitelist
  router.post('/ips/unwhitelist', (req, res) => {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'IP address required' });
    }
    
    engine.unwhitelistIP(ip);
    logger.logEvent('ip_unwhitelisted', { ip });
    
    res.json({ success: true, message: `IP ${ip} removed from whitelist` });
  });

  // ===== LOGS =====

  // Get logs
  router.get('/logs', (req, res) => {
    const options = {
      limit: parseInt(req.query.limit) || 100,
      type: req.query.type,
      since: req.query.since
    };
    
    res.json({
      logs: logger.getLogs(options),
      count: logger.getLogs(options).length
    });
  });

  // Get blocked requests
  router.get('/logs/blocked', (req, res) => {
    const options = {
      limit: parseInt(req.query.limit) || 100,
      type: 'blocked'
    };
    
    res.json({
      logs: logger.getLogs(options),
      count: logger.getLogs(options).length
    });
  });

  // Clear logs
  router.delete('/logs', (req, res) => {
    logger.clearLogs();
    res.json({ success: true, message: 'Logs cleared' });
  });

  // ===== TEST =====

  // Test a request against rules
  router.post('/test', async (req, res) => {
    const { url, method, headers, body, query } = req.body;
    
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
      result: {
        allowed: result.allowed,
        violations: result.violations,
        action: result.action
      }
    });
  });

  // Reset statistics
  router.post('/reset-stats', (req, res) => {
    engine.resetStats();
    logger.logEvent('stats_reset', {});
    res.json({ success: true, message: 'Statistics reset' });
  });

  // ===== IMPORT/EXPORT =====

  // Export configuration
  router.get('/export', (req, res) => {
    const config = engine.exportConfig();
    res.setHeader('Content-Disposition', 'attachment; filename=waf-config.json');
    res.json(config);
  });

  // Import configuration
  router.post('/import', (req, res) => {
    const config = req.body;
    const result = engine.importConfig(config);
    
    if (result.success) {
      logger.logEvent('config_imported', {});
      res.json({ success: true, message: 'Configuration imported successfully' });
    } else {
      res.status(400).json({ success: false, error: result.error });
    }
  });

  // ===== GEO-BLOCKING =====

  // Get blocked countries
  router.get('/countries/blocked', (req, res) => {
    res.json({
      countries: engine.getBlockedCountries(),
      count: engine.getBlockedCountries().length
    });
  });

  // Get allowed countries
  router.get('/countries/allowed', (req, res) => {
    res.json({
      countries: engine.getAllowedCountries(),
      count: engine.getAllowedCountries().length
    });
  });

  // Block country
  router.post('/countries/block', (req, res) => {
    const { country } = req.body;
    if (!country) {
      return res.status(400).json({ error: 'Country code required' });
    }
    
    engine.blockCountry(country);
    logger.logEvent('country_blocked', { country });
    res.json({ success: true, message: `Country ${country} blocked` });
  });

  // Unblock country
  router.post('/countries/unblock', (req, res) => {
    const { country } = req.body;
    if (!country) {
      return res.status(400).json({ error: 'Country code required' });
    }
    
    engine.unblockCountry(country);
    logger.logEvent('country_unblocked', { country });
    res.json({ success: true, message: `Country ${country} unblocked` });
  });

  // Allow country (whitelist)
  router.post('/countries/allow', (req, res) => {
    const { country } = req.body;
    if (!country) {
      return res.status(400).json({ error: 'Country code required' });
    }
    
    engine.allowCountry(country);
    logger.logEvent('country_allowed', { country });
    res.json({ success: true, message: `Country ${country} added to allowed list` });
  });

  // Remove country from allowed list
  router.post('/countries/unallow', (req, res) => {
    const { country } = req.body;
    if (!country) {
      return res.status(400).json({ error: 'Country code required' });
    }
    
    engine.removeAllowedCountry(country);
    logger.logEvent('country_unallowed', { country });
    res.json({ success: true, message: `Country ${country} removed from allowed list` });
  });

  // ===== WEBHOOKS =====

  // Get webhooks
  router.get('/webhooks', (req, res) => {
    res.json({
      webhooks: engine.webhook.getWebhooks(),
      enabled: engine.webhook.enabled
    });
  });

  // Add webhook
  router.post('/webhooks', (req, res) => {
    const webhook = engine.webhook.addWebhook(req.body);
    logger.logEvent('webhook_added', { webhookId: webhook.id });
    res.status(201).json(webhook);
  });

  // Update webhook
  router.put('/webhooks/:id', (req, res) => {
    const webhook = engine.webhook.updateWebhook(req.params.id, req.body);
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }
    logger.logEvent('webhook_updated', { webhookId: req.params.id });
    res.json(webhook);
  });

  // Delete webhook
  router.delete('/webhooks/:id', (req, res) => {
    const deleted = engine.webhook.removeWebhook(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: 'Webhook not found' });
    }
    logger.logEvent('webhook_deleted', { webhookId: req.params.id });
    res.json({ success: true, message: 'Webhook deleted' });
  });

  // Test webhook
  router.post('/webhooks/:id/test', async (req, res) => {
    const result = await engine.webhook.testWebhook(req.params.id);
    res.json(result);
  });

  // ===== BOT DETECTION =====

  // Get bot detection status
  router.get('/bots', (req, res) => {
    res.json({
      enabled: engine.config.enableBotDetection,
      blockedBots: engine.botDetector.getBlockedBots(),
      allowedBots: engine.botDetector.getAllowedBots()
    });
  });

  // Block bot
  router.post('/bots/block', (req, res) => {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Bot name required' });
    }
    
    engine.botDetector.blockBot(name);
    res.json({ success: true, message: `Bot ${name} blocked` });
  });

  // Allow bot
  router.post('/bots/allow', (req, res) => {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Bot name required' });
    }
    
    engine.botDetector.allowBot(name);
    res.json({ success: true, message: `Bot ${name} allowed` });
  });

  // ===== CONFIGURATION =====

  // Get configuration
  router.get('/config', (req, res) => {
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

  // Update configuration
  router.put('/config', (req, res) => {
    engine.config = { ...engine.config, ...req.body };
    logger.logEvent('config_updated', { config: engine.config });
    res.json({ success: true, config: engine.config });
  });

  return router;
}

module.exports = { createAPIRouter };
