/**
 * Prometheus Metrics Export
 * Provides /metrics endpoint for Grafana dashboards
 */

const client = require('prom-client');

class PrometheusMetrics {
  constructor(options = {}) {
    this.prefix = options.prefix || 'kavach_';
    this.register = new client.Registry();

    // Default metrics (memory, CPU, event loop lag, etc.)
    client.collectDefaultMetrics({ register: this.register, prefix: this.prefix });

    // Custom WAF metrics
    this.requestCounter = new client.Counter({
      name: `${this.prefix}requests_total`,
      help: 'Total number of requests processed',
      labelNames: ['method', 'status'],
      registers: [this.register]
    });

    this.blockedCounter = new client.Counter({
      name: `${this.prefix}blocked_requests_total`,
      help: 'Total number of blocked requests',
      labelNames: ['reason', 'severity'],
      registers: [this.register]
    });

    this.threatCounter = new client.Counter({
      name: `${this.prefix}threats_detected_total`,
      help: 'Total number of threats detected',
      labelNames: ['type'],
      registers: [this.register]
    });

    this.ruleGauge = new client.Gauge({
      name: `${this.prefix}active_rules`,
      help: 'Number of active WAF rules',
      registers: [this.register]
    });

    this.ipBlacklistGauge = new client.Gauge({
      name: `${this.prefix}blocked_ips`,
      help: 'Number of blocked IPs',
      registers: [this.register]
    });

    this.ipWhitelistGauge = new client.Gauge({
      name: `${this.prefix}whitelisted_ips`,
      help: 'Number of whitelisted IPs',
      registers: [this.register]
    });

    this.rateLimitGauge = new client.Gauge({
      name: `${this.prefix}rate_limit_entries`,
      help: 'Number of active rate limit entries',
      registers: [this.register]
    });

    this.cacheHitCounter = new client.Counter({
      name: `${this.prefix}cache_hits_total`,
      help: 'Total cache hits',
      labelNames: ['cache'],
      registers: [this.register]
    });

    this.cacheMissCounter = new client.Counter({
      name: `${this.prefix}cache_misses_total`,
      help: 'Total cache misses',
      labelNames: ['cache'],
      registers: [this.register]
    });

    this.webhookCounter = new client.Counter({
      name: `${this.prefix}webhooks_sent_total`,
      help: 'Total webhooks sent',
      labelNames: ['status'],
      registers: [this.register]
    });

    this.memoryGauge = new client.Gauge({
      name: `${this.prefix}memory_usage_bytes`,
      help: 'Current memory usage in bytes',
      labelNames: ['type'],
      registers: [this.register]
    });
  }

  recordRequest(method, blocked, reason, severity) {
    const status = blocked ? 'blocked' : 'allowed';
    this.requestCounter.inc({ method: method || 'GET', status });
    if (blocked) {
      this.blockedCounter.inc({ reason: reason || 'unknown', severity: severity || 'medium' });
    }
  }

  recordThreat(type) {
    this.threatCounter.inc({ type: type || 'unknown' });
  }

  setActiveRules(count) {
    this.ruleGauge.set(count);
  }

  setBlockedIPs(count) {
    this.ipBlacklistGauge.set(count);
  }

  setWhitelistedIPs(count) {
    this.ipWhitelistGauge.set(count);
  }

  setRateLimitEntries(count) {
    this.rateLimitGauge.set(count);
  }

  recordCacheHit(cache) {
    this.cacheHitCounter.inc({ cache });
  }

  recordCacheMiss(cache) {
    this.cacheMissCounter.inc({ cache });
  }

  recordWebhook(status) {
    this.webhookCounter.inc({ status });
  }

  updateMemory(metrics) {
    if (metrics.heapUsed) this.memoryGauge.set({ type: 'heap_used' }, metrics.heapUsed);
    if (metrics.heapTotal) this.memoryGauge.set({ type: 'heap_total' }, metrics.heapTotal);
    if (metrics.rss) this.memoryGauge.set({ type: 'rss' }, metrics.rss);
  }

  metrics() {
    return this.register.metrics();
  }

  contentType() {
    return this.register.contentType;
  }

  middleware() {
    return async (req, res, next) => {
      if (req.path === '/metrics') {
        res.set('Content-Type', this.contentType());
        res.end(await this.metrics());
        return;
      }
      next();
    };
  }
}

module.exports = { PrometheusMetrics };
