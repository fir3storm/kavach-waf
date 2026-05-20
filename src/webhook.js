/**
 * Webhook Notifications Module
 * Sends alerts when attacks are detected
 */

class WebhookNotifier {
  constructor(options = {}) {
    this.webhooks = [];
    this.minSeverity = options.minSeverity || 'medium';
    this.rateLimitWindow = options.rateLimitWindow || 60000; // 1 minute
    this.maxNotificationsPerWindow = options.maxNotificationsPerWindow || 10;
    this.notificationHistory = [];
    this.enabled = options.enabled !== false;
    
    // Severity levels
    this.severityLevels = {
      'low': 1,
      'medium': 2,
      'high': 3,
      'critical': 4
    };
  }

  /**
   * Add webhook endpoint
   */
  addWebhook(config) {
    const webhook = {
      id: config.id || this.generateId(),
      url: config.url,
      method: config.method || 'POST',
      headers: config.headers || {},
      events: config.events || ['block', 'critical'],
      minSeverity: config.minSeverity || this.minSeverity,
      enabled: config.enabled !== false,
      retryAttempts: config.retryAttempts || 3,
      timeout: config.timeout || 5000
    };

    this.webhooks.push(webhook);
    return webhook;
  }

  /**
   * Remove webhook
   */
  removeWebhook(id) {
    const index = this.webhooks.findIndex(w => w.id === id);
    if (index > -1) {
      this.webhooks.splice(index, 1);
      return true;
    }
    return false;
  }

  /**
   * Get all webhooks
   */
  getWebhooks() {
    return this.webhooks;
  }

  /**
   * Update webhook
   */
  updateWebhook(id, updates) {
    const webhook = this.webhooks.find(w => w.id === id);
    if (!webhook) return null;
    
    Object.assign(webhook, updates);
    return webhook;
  }

  /**
   * Send notification
   */
  async notify(event) {
    if (!this.enabled) return;

    // Check rate limiting
    if (this.isRateLimited()) {
      console.log('[Webhook] Rate limited, skipping notification');
      return;
    }

    // Check severity threshold
    const eventSeverity = this.severityLevels[event.severity] || 1;
    const minSeverity = this.severityLevels[this.minSeverity] || 1;
    
    if (eventSeverity < minSeverity) {
      return;
    }

    // Record notification
    this.recordNotification();

    // Send to all matching webhooks
    const promises = this.webhooks
      .filter(w => w.enabled && this.shouldNotify(w, event))
      .map(w => this.sendToWebhook(w, event));

    await Promise.allSettled(promises);
  }

  /**
   * Check if rate limited
   */
  isRateLimited() {
    const now = Date.now();
    const windowStart = now - this.rateLimitWindow;
    
    // Clean old entries
    this.notificationHistory = this.notificationHistory.filter(t => t > windowStart);
    
    return this.notificationHistory.length >= this.maxNotificationsPerWindow;
  }

  /**
   * Record notification timestamp
   */
  recordNotification() {
    this.notificationHistory.push(Date.now());
  }

  /**
   * Check if webhook should receive this event
   */
  shouldNotify(webhook, event) {
    // Check event type
    if (!webhook.events.includes(event.type) && !webhook.events.includes('all')) {
      return false;
    }

    // Check severity
    const eventSeverity = this.severityLevels[event.severity] || 1;
    const webhookMinSeverity = this.severityLevels[webhook.minSeverity] || 1;
    
    return eventSeverity >= webhookMinSeverity;
  }

  /**
   * Send notification to single webhook
   */
  async sendToWebhook(webhook, event) {
    const payload = this.buildPayload(event);
    
    for (let attempt = 0; attempt < webhook.retryAttempts; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), webhook.timeout);

        const response = await fetch(webhook.url, {
          method: webhook.method,
          headers: {
            'Content-Type': 'application/json',
            ...webhook.headers
          },
          body: JSON.stringify(payload),
          signal: controller.signal
        });

        clearTimeout(timeout);

        if (response.ok) {
          console.log(`[Webhook] Sent to ${webhook.url}`);
          return;
        }
        
        throw new Error(`HTTP ${response.status}`);
      } catch (err) {
        console.error(`[Webhook] Attempt ${attempt + 1} failed for ${webhook.url}:`, err.message);
        
        if (attempt < webhook.retryAttempts - 1) {
          await this.delay(1000 * (attempt + 1)); // Exponential backoff
        }
      }
    }
  }

  /**
   * Build notification payload
   */
  buildPayload(event) {
    return {
      timestamp: new Date().toISOString(),
      event: event.type,
      severity: event.severity,
      message: event.message,
      data: {
        ip: event.ip,
        method: event.method,
        url: event.url,
        path: event.path,
        userAgent: event.userAgent,
        violations: event.violations || [],
        country: event.country,
        isBot: event.isBot
      },
      waf: {
        version: '1.0.0',
        rulesCount: event.rulesCount,
        blockedCount: event.blockedCount
      }
    };
  }

  /**
   * Create notification event from request
   */
  createEvent(type, req, result, extra = {}) {
    return {
      type,
      severity: this.getSeverity(result),
      message: this.getMessage(type, result),
      ip: result.clientIP || req.ip,
      method: req.method,
      url: req.url,
      path: req.path,
      userAgent: req.headers['user-agent'],
      violations: result.violations || [],
      country: extra.country,
      isBot: extra.isBot,
      ...extra
    };
  }

  /**
   * Get severity from result
   */
  getSeverity(result) {
    if (!result.violations || result.violations.length === 0) {
      return 'low';
    }
    
    const severities = result.violations.map(v => this.severityLevels[v.severity] || 1);
    const maxSeverity = Math.max(...severities);
    
    const levels = ['low', 'medium', 'high', 'critical'];
    return levels[maxSeverity - 1] || 'low';
  }

  /**
   * Get human-readable message
   */
  getMessage(type, result) {
    switch (type) {
      case 'block':
        return `Request blocked: ${result.violations?.map(v => v.type).join(', ')}`;
      case 'rate_limit':
        return 'Rate limit exceeded';
      case 'geo_block':
        return 'Request blocked by geo restriction';
      case 'bot_detected':
        return 'Bot detected and blocked';
      default:
        return 'Security event detected';
    }
  }

  /**
   * Test webhook
   */
  async testWebhook(id) {
    const webhook = this.webhooks.find(w => w.id === id);
    if (!webhook) return { success: false, error: 'Webhook not found' };

    const testEvent = {
      type: 'test',
      severity: 'low',
      message: 'Test notification from WAF',
      ip: '127.0.0.1',
      method: 'GET',
      url: '/test',
      path: '/test',
      userAgent: 'WAF-Test/1.0',
      violations: []
    };

    try {
      await this.sendToWebhook(webhook, testEvent);
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { WebhookNotifier };
