/**
 * WAF Logger
 * Handles logging of requests, blocks, and security events
 */

const fs = require('fs');
const path = require('path');

class WAFLogger {
  constructor(options = {}) {
    this.logDir = options.logDir || path.join(__dirname, '..', 'data');
    this.maxLogs = options.maxLogs || 10000;
    this.logs = [];
    this.blockedRequests = [];
    
    // Ensure log directory exists
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
    
    this.logFile = path.join(this.logDir, 'waf-logs.json');
    this.blockedFile = path.join(this.logDir, 'blocked-requests.json');
    
    // Load existing logs
    this.loadLogs();
  }

  loadLogs() {
    try {
      if (fs.existsSync(this.logFile)) {
        const data = fs.readFileSync(this.logFile, 'utf8');
        this.logs = JSON.parse(data);
      }
      if (fs.existsSync(this.blockedFile)) {
        const data = fs.readFileSync(this.blockedFile, 'utf8');
        this.blockedRequests = JSON.parse(data);
      }
    } catch (err) {
      console.error('Error loading logs:', err.message);
    }
  }

  saveLogs() {
    try {
      // Keep only recent logs
      if (this.logs.length > this.maxLogs) {
        this.logs = this.logs.slice(-this.maxLogs);
      }
      if (this.blockedRequests.length > this.maxLogs) {
        this.blockedRequests = this.blockedRequests.slice(-this.maxLogs);
      }
      
      fs.writeFileSync(this.logFile, JSON.stringify(this.logs, null, 2));
      fs.writeFileSync(this.blockedFile, JSON.stringify(this.blockedRequests, null, 2));
    } catch (err) {
      console.error('Error saving logs:', err.message);
    }
  }

  logRequest(req, result) {
    const logEntry = {
      id: this.generateId(),
      timestamp: new Date().toISOString(),
      ip: result.clientIP || 'unknown',
      method: req.method,
      url: req.url,
      path: req.path,
      userAgent: req.headers['user-agent'] || 'unknown',
      allowed: result.allowed,
      violations: result.violations || [],
      action: result.action
    };

    this.logs.push(logEntry);
    
    if (!result.allowed) {
      this.blockedRequests.push(logEntry);
    }

    // Auto-save every 10 logs
    if (this.logs.length % 10 === 0) {
      this.saveLogs();
    }

    return logEntry;
  }

  logEvent(type, data) {
    const logEntry = {
      id: this.generateId(),
      timestamp: new Date().toISOString(),
      type,
      data
    };

    this.logs.push(logEntry);
    return logEntry;
  }

  getLogs(options = {}) {
    let logs = [...this.logs];
    
    if (options.type === 'blocked') {
      logs = [...this.blockedRequests];
    }
    
    if (options.limit) {
      logs = logs.slice(-options.limit);
    }
    
    if (options.since) {
      logs = logs.filter(l => new Date(l.timestamp) >= new Date(options.since));
    }
    
    return logs.reverse(); // Most recent first
  }

  getStats(timeRange = '24h') {
    const now = Date.now();
    const ranges = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000
    };
    
    const cutoff = now - (ranges[timeRange] || ranges['24h']);
    
    const recentLogs = this.logs.filter(l => new Date(l.timestamp).getTime() > cutoff);
    const recentBlocked = this.blockedRequests.filter(l => new Date(l.timestamp).getTime() > cutoff);
    
    // Group by threat type
    const threatsByType = {};
    recentBlocked.forEach(log => {
      log.violations.forEach(v => {
        const type = v.type || 'unknown';
        threatsByType[type] = (threatsByType[type] || 0) + 1;
      });
    });
    
    // Group by hour for chart
    const hourlyData = {};
    recentLogs.forEach(log => {
      const hour = new Date(log.timestamp).toISOString().slice(0, 13) + ':00';
      if (!hourlyData[hour]) {
        hourlyData[hour] = { total: 0, blocked: 0 };
      }
      hourlyData[hour].total++;
      if (!log.allowed) {
        hourlyData[hour].blocked++;
      }
    });
    
    return {
      totalRequests: recentLogs.length,
      blockedRequests: recentBlocked.length,
      allowedRequests: recentLogs.length - recentBlocked.length,
      threatsByType,
      hourlyData: Object.entries(hourlyData).map(([time, data]) => ({
        time,
        ...data
      })).sort((a, b) => a.time.localeCompare(b.time))
    };
  }

  clearLogs() {
    this.logs = [];
    this.blockedRequests = [];
    this.saveLogs();
  }

  generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  }
}

module.exports = { WAFLogger };
