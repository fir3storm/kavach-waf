/**
 * WAF Core Engine
 * Handles rule matching, request analysis, and threat detection
 */

const crypto = require('crypto');
const { BotDetector } = require('./bot-detector');
const { GeoBlocker } = require('./geo-blocker');
const { WebhookNotifier } = require('./webhook');
const { RequestSanitizer } = require('./sanitizer');
const { RedisClient } = require('./cache/redis-client');
const { IPReputationService } = require('./ip-reputation');

// Default security rules
const DEFAULT_RULES = [
  {
    id: 'sql-injection-1',
    name: 'SQL Injection Detection',
    type: 'sql_injection',
    pattern: /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|into|table|database)\b)|(--|;--|;|\/\*|\*\/|\bOR\b.*=|\bAND\b.*=)/i,
    description: 'Detects common SQL injection patterns',
    severity: 'high',
    enabled: true,
    action: 'block'
  },
  {
    id: 'xss-1',
    name: 'Cross-Site Scripting (XSS)',
    type: 'xss',
    pattern: /(<script|javascript:|on\w+\s*=|alert\s*\(|confirm\s*\(|prompt\s*\()/i,
    description: 'Detects XSS attack patterns',
    severity: 'high',
    enabled: true,
    action: 'block'
  },
  {
    id: 'path-traversal-1',
    name: 'Path Traversal',
    type: 'path_traversal',
    pattern: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|.%2f|%2e\.)/i,
    description: 'Detects directory traversal attempts',
    severity: 'medium',
    enabled: true,
    action: 'block'
  },
  {
    id: 'command-injection-1',
    name: 'Command Injection',
    type: 'command_injection',
    pattern: /(\||;|\$\(|`|<\(|>\)|\$\{|`).*\b(cat|ls|pwd|whoami|id|uname|nc|netcat|wget|curl|bash|sh|cmd|powershell)\b/i,
    description: 'Detects command injection attempts',
    severity: 'critical',
    enabled: true,
    action: 'block'
  },
  {
    id: 'lfi-1',
    name: 'Local File Inclusion',
    type: 'lfi',
    pattern: /(file:\/\/|php:\/\/|data:\/\/|expect:\/\/|input:\/\/|filter:\/\/)/i,
    description: 'Detects LFI/RFI attempts',
    severity: 'high',
    enabled: true,
    action: 'block'
  },
  {
    id: 'nosql-injection-1',
    name: 'NoSQL Injection',
    type: 'nosql_injection',
    pattern: /(\$eq|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$regex|\$where|\$expr)/i,
    description: 'Detects NoSQL injection patterns',
    severity: 'high',
    enabled: true,
    action: 'block'
  },
  {
    id: 'xxe-1',
    name: 'XML External Entity',
    type: 'xxe',
    pattern: /(<!ENTITY\s+.*\s+SYSTEM|<!DOCTYPE.*\[.*<!ENTITY)/i,
    description: 'Detects XXE attacks',
    severity: 'critical',
    enabled: true,
    action: 'block'
  },
  {
    id: 'ssti-1',
    name: 'Server-Side Template Injection',
    type: 'ssti',
    pattern: /(\{\{.*\}\}|\$\{.*\}|<%=.*%>|\[\[.*\]\]|\{\%.*\%\})/i,
    description: 'Detects template injection patterns',
    severity: 'high',
    enabled: true,
    action: 'block'
  }
];

class WAFEngine {
  constructor(options = {}) {
    this.rules = [...DEFAULT_RULES];
    this.blockedIPs = new Set();
    this.whitelist = new Set();
    this.blockedCountries = new Set();
    this.allowedCountries = new Set();
    this.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      threatsDetected: 0,
      startTime: Date.now()
    };
    
    // Initialize new modules
    this.botDetector = new BotDetector(options.botDetection);
    this.geoBlocker = new GeoBlocker(options.geoBlocking);
    this.webhook = new WebhookNotifier(options.webhooks);
    this.sanitizer = new RequestSanitizer(options.sanitization);
    this.workerQueue = options.workerQueue || null;
    
    // Redis-backed rate limiting
    this.redisClient = options.redisClient || null;
    this.rateLimiter = new Map();
    this.endpointRateLimiters = new Map();
    
    // IP Reputation
    this.ipReputation = options.ipReputation || null;
    
    // Prometheus metrics callback
    this.metricsCallback = options.metricsCallback || null;
    
    // Configuration
    this.config = {
      maxRequestSize: options.maxRequestSize || 10 * 1024 * 1024, // 10MB
      enableBotDetection: options.enableBotDetection !== false,
      enableGeoBlocking: options.enableGeoBlocking || false,
      enableSanitization: options.enableSanitization !== false,
      enableWebhooks: options.enableWebhooks !== false,
      enableWorkerQueue: options.enableWorkerQueue || false,
      enableIPReputation: options.enableIPReputation !== false,
      ...options
    };
  }

  /**
   * Analyze a request for threats
   */
  async analyzeRequest(req) {
    const violations = [];
    const clientIP = this.getClientIP(req);
    const extraInfo = {};

    // Check whitelist
    if (this.whitelist.has(clientIP)) {
      return { allowed: true, violations: [], clientIP };
    }

    // Check blacklist
    if (this.blockedIPs.has(clientIP)) {
      const result = { 
        allowed: false, 
        violations: [{ rule: 'ip-blacklist', type: 'ip_blacklist', severity: 'high', reason: 'IP is blacklisted', action: 'block' }],
        action: 'block',
        clientIP
      };
      this.notifyWebhook('block', req, result, extraInfo);
      this.recordMetrics(req.method, true, 'ip_blacklist', 'high');
      return result;
    }

    // Check request size
    const contentLength = parseInt(req.headers['content-length']) || 0;
    if (contentLength > this.config.maxRequestSize) {
      violations.push({
        rule: 'request-size',
        type: 'request_size',
        severity: 'medium',
        reason: `Request size ${contentLength} exceeds limit ${this.config.maxRequestSize}`,
        action: 'block'
      });
    }

    // Geo-blocking check
    if (this.config.enableGeoBlocking) {
      const geoCheck = await this.geoBlocker.checkIP(clientIP);
      if (geoCheck.blocked) {
        violations.push({
          rule: 'geo-block',
          type: 'geo_block',
          severity: 'medium',
          reason: geoCheck.reason,
          action: 'block'
        });
        extraInfo.country = geoCheck.country;
      }
    }

    // Bot detection
    if (this.config.enableBotDetection) {
      const botCheck = this.botDetector.analyze(req);
      if (botCheck.isBadBot) {
        violations.push({
          rule: 'bot-detection',
          type: 'bot_detected',
          severity: 'medium',
          reason: botCheck.reason || 'Bad bot detected',
          action: 'block'
        });
        extraInfo.isBot = true;
      }
    }

    // IP Reputation check
    if (this.config.enableIPReputation && this.ipReputation) {
      try {
        const rep = await this.ipReputation.checkIP(clientIP);
        if (rep.risk === 'high' || rep.risk === 'critical') {
          violations.push({
            rule: 'ip-reputation',
            type: 'ip_reputation',
            severity: rep.risk === 'critical' ? 'critical' : 'high',
            reason: `IP reputation: ${rep.risk} (${rep.score}) - ${rep.reason}`,
            action: 'block'
          });
          extraInfo.ipReputation = rep;
        } else if (rep.risk === 'medium') {
          extraInfo.ipReputation = rep;
        }
      } catch {
        // IP reputation failures should not block
      }
    }

    // Check rate limiting
    const rateLimitCheck = await this.checkRateLimit(clientIP);
    if (!rateLimitCheck.allowed) {
      violations.push({
        rule: 'rate-limit',
        type: 'rate_limit',
        severity: 'medium',
        reason: 'Rate limit exceeded',
        action: 'block'
      });
    }

    // Check endpoint-specific rate limiting
    const endpointLimit = await this.checkEndpointRateLimit(clientIP, req.path, req.method);
    if (!endpointLimit.allowed) {
      violations.push({
        rule: 'endpoint-rate-limit',
        type: 'endpoint_rate_limit',
        severity: 'medium',
        reason: `Rate limit exceeded for ${req.method} ${req.path}`,
        action: 'block'
      });
    }

    // Analyze request components
    const requestData = this.extractRequestData(req);
    
    // Check each enabled rule
    for (const rule of this.rules) {
      if (!rule.enabled) continue;

      const match = this.checkRule(rule, requestData);
      if (match.found) {
        violations.push({
          rule: rule.id,
          type: rule.type,
          severity: rule.severity,
          reason: `${rule.name}: ${match.location}`,
          pattern: match.value,
          action: rule.action
        });
      }
    }

    this.stats.totalRequests++;
    
    if (violations.length > 0) {
      this.stats.threatsDetected += violations.length;
      this.stats.blockedRequests++;
    }

    const blocked = violations.some(v => v.action === 'block');
    const result = {
      allowed: !blocked,
      violations,
      action: blocked ? 'block' : 'log',
      clientIP
    };

    // Record prometheus metrics
    const topThreat = violations.find(v => v.action === 'block');
    this.recordMetrics(req.method, blocked, topThreat?.type, topThreat?.severity);

    // Send webhook notification if blocked
    if (blocked && this.config.enableWebhooks) {
      this.notifyWebhook('block', req, result, extraInfo);
    }

    // Dispatch to worker queue for background analysis
    if (this.config.enableWorkerQueue && this.workerQueue) {
      this.dispatchToWorkerQueue(req, result);
    }
    
    return result;
  }

  recordMetrics(method, blocked, reason, severity) {
    if (this.metricsCallback) {
      try {
        this.metricsCallback(method, blocked, reason, severity);
      } catch {
        // metrics failures are non-critical
      }
    }
  }

  /**
   * Dispatch request to worker queue for background analysis
   */
  async dispatchToWorkerQueue(req, result) {
    try {
      const queue = this.workerQueue();
      if (!queue || !queue.addRequestAnalysis) return;

      queue.addRequestAnalysis({
        url: req.url,
        path: req.path,
        method: req.method,
        ip: this.getClientIP(req),
        headers: req.headers,
        body: req.body,
        query: req.query,
        violations: result.violations,
      }).catch(err => {
        if (err.code !== 'ECONNREFUSED' && err.code !== 'NR_CLOSED') {
          console.error('Worker queue error:', err.message);
        }
      });

      if (result.violations.length > 0) {
        queue.addThreatProcessing({
          type: result.violations[0].type,
          severity: result.violations[0].severity,
          ip: this.getClientIP(req),
          url: req.url,
          timestamp: Date.now()
        }).catch(() => {});
      }
    } catch (err) {
      // Queue dispatch failures should never break the main flow
    }
  }

  /**
   * Notify webhook
   */
  notifyWebhook(type, req, result, extra) {
    const event = this.webhook.createEvent(type, req, result, {
      ...extra,
      rulesCount: this.rules.length,
      blockedCount: this.stats.blockedRequests
    });
    this.webhook.notify(event);
  }

  /**
   * Extract all request data for analysis
   */
  extractRequestData(req) {
    const data = {
      url: req.url || '',
      path: req.path || '',
      query: req.query || {},
      body: req.body || {},
      headers: req.headers || {},
      cookies: req.cookies || {},
      method: req.method || 'GET',
      userAgent: req.headers['user-agent'] || ''
    };

    data.all = JSON.stringify(data).toLowerCase();
    
    return data;
  }

  /**
   * Check a single rule against request data
   */
  checkRule(rule, data) {
    const locations = ['url', 'path', 'query', 'body', 'headers', 'cookies', 'userAgent'];
    
    for (const location of locations) {
      const value = data[location];
      if (!value) continue;

      const strValue = typeof value === 'string' ? value : JSON.stringify(value);
      
      if (rule.pattern.test(strValue)) {
        return {
          found: true,
          location: location,
          value: strValue.substring(0, 100)
        };
      }
    }

    return { found: false };
  }

  /**
   * Rate limiting check (Redis-backed with in-memory fallback)
   */
  async checkRateLimit(clientIP) {
    const windowSeconds = 60;
    const maxRequests = 100;
    const key = `ratelimit:global:${clientIP}`;

    if (this.redisClient) {
      try {
        const count = await this.redisClient.increment(key, windowSeconds);
        if (count > maxRequests) {
          return { allowed: false, count };
        }
        return { allowed: true, count };
      } catch {
        // Fallback to memory
      }
    }

    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    const windowStart = now - windowMs;
    
    if (!this.rateLimiter.has(clientIP)) {
      this.rateLimiter.set(clientIP, { count: 1, firstRequest: now });
      return { allowed: true };
    }

    const record = this.rateLimiter.get(clientIP);
    if (record.firstRequest < windowStart) {
      record.count = 1;
      record.firstRequest = now;
      return { allowed: true };
    }

    record.count++;
    if (record.count > maxRequests) {
      return { allowed: false, count: record.count };
    }
    return { allowed: true, count: record.count };
  }

  /**
   * Endpoint-specific rate limiting (Redis-backed with in-memory fallback)
   */
  async checkEndpointRateLimit(clientIP, path, method) {
    const key = `ratelimit:endpoint:${clientIP}:${method}:${path}`;
    const windowSeconds = 60;
    const maxRequests = 30;
    
    if (this.redisClient) {
      try {
        const count = await this.redisClient.increment(key, windowSeconds);
        if (count > maxRequests) {
          return { allowed: false, count };
        }
        return { allowed: true, count };
      } catch {
        // Fallback to memory
      }
    }

    const mapKey = `${clientIP}:${method}:${path}`;
    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    const windowStart = now - windowMs;
    
    if (!this.endpointRateLimiters.has(mapKey)) {
      this.endpointRateLimiters.set(mapKey, { count: 1, firstRequest: now });
      return { allowed: true };
    }

    const record = this.endpointRateLimiters.get(mapKey);
    if (record.firstRequest < windowStart) {
      record.count = 1;
      record.firstRequest = now;
      return { allowed: true };
    }

    record.count++;
    if (record.count > maxRequests) {
      return { allowed: false, count: record.count };
    }
    return { allowed: true, count: record.count };
  }

  /**
   * Get client IP address
   */
  getClientIP(req) {
    return req.headers['x-forwarded-for'] || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.ip || 
           'unknown';
  }

  // Rule Management
  addRule(rule) {
    rule.id = rule.id || crypto.randomUUID();
    this.rules.push(rule);
    return rule;
  }

  updateRule(id, updates) {
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) return null;
    this.rules[index] = { ...this.rules[index], ...updates };
    return this.rules[index];
  }

  deleteRule(id) {
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) return false;
    this.rules.splice(index, 1);
    return true;
  }

  getRules() {
    return this.rules;
  }

  getRule(id) {
    return this.rules.find(r => r.id === id);
  }

  // IP Management
  blockIP(ip) {
    this.blockedIPs.add(ip);
    return true;
  }

  unblockIP(ip) {
    this.blockedIPs.delete(ip);
    return true;
  }

  whitelistIP(ip) {
    this.whitelist.add(ip);
    return true;
  }

  unwhitelistIP(ip) {
    this.whitelist.delete(ip);
    return true;
  }

  getBlockedIPs() {
    return Array.from(this.blockedIPs);
  }

  getWhitelistedIPs() {
    return Array.from(this.whitelist);
  }

  // Country Management
  blockCountry(countryCode) {
    this.blockedCountries.add(countryCode.toUpperCase());
    this.geoBlocker.blockCountry(countryCode);
    return true;
  }

  unblockCountry(countryCode) {
    this.blockedCountries.delete(countryCode.toUpperCase());
    this.geoBlocker.unblockCountry(countryCode);
    return true;
  }

  allowCountry(countryCode) {
    this.allowedCountries.add(countryCode.toUpperCase());
    this.geoBlocker.allowCountry(countryCode);
    return true;
  }

  removeAllowedCountry(countryCode) {
    this.allowedCountries.delete(countryCode.toUpperCase());
    this.geoBlocker.removeAllowedCountry(countryCode);
    return true;
  }

  getBlockedCountries() {
    return this.geoBlocker.getBlockedCountries();
  }

  getAllowedCountries() {
    return this.geoBlocker.getAllowedCountries();
  }

  // Import/Export
  exportConfig() {
    return {
      version: '2.0.0',
      exportedAt: new Date().toISOString(),
      rules: this.rules.map(rule => ({
        ...rule,
        pattern: rule.pattern.source,
        flags: rule.pattern.flags
      })),
      blockedIPs: Array.from(this.blockedIPs),
      whitelistedIPs: Array.from(this.whitelist),
      blockedCountries: Array.from(this.blockedCountries),
      allowedCountries: Array.from(this.allowedCountries),
      config: this.config,
      stats: this.getStats()
    };
  }

  importConfig(config) {
    try {
      if (config.rules) {
        this.rules = config.rules.map(rule => ({
          ...rule,
          pattern: new RegExp(rule.pattern, rule.flags || 'i')
        }));
      }

      if (config.blockedIPs) {
        this.blockedIPs = new Set(config.blockedIPs);
      }
      if (config.whitelistedIPs) {
        this.whitelist = new Set(config.whitelistedIPs);
      }

      if (config.blockedCountries) {
        this.blockedCountries = new Set(config.blockedCountries);
        config.blockedCountries.forEach(c => this.geoBlocker.blockCountry(c));
      }
      if (config.allowedCountries) {
        this.allowedCountries = new Set(config.allowedCountries);
        config.allowedCountries.forEach(c => this.geoBlocker.allowCountry(c));
      }

      if (config.config) {
        this.config = { ...this.config, ...config.config };
      }

      return { success: true, message: 'Configuration imported successfully' };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // Statistics
  getStats() {
    return {
      ...this.stats,
      uptime: Date.now() - this.stats.startTime,
      rulesCount: this.rules.length,
      blockedIPsCount: this.blockedIPs.size,
      whitelistedIPsCount: this.whitelist.size
    };
  }

  resetStats() {
    this.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      threatsDetected: 0,
      startTime: Date.now()
    };
  }
}

module.exports = { WAFEngine, DEFAULT_RULES };
