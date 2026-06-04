/**
 * Health Check Module
 * Kubernetes liveness/readiness probes with dependency checks
 */

const fs = require('fs');
const path = require('path');

class HealthCheck {
  constructor(options = {}) {
    this.checks = new Map();
    this.ready = false;
    this.startTime = Date.now();
    this.minUptimeMs = options.minUptimeMs || 5000;
    this.diskThresholdPercent = options.diskThresholdPercent || 90;
    this.dataDir = options.dataDir || path.join(__dirname, '..', '..', 'data');
  }

  register(name, checker) {
    this.checks.set(name, checker);
  }

  async runChecks() {
    const results = {};
    let allHealthy = true;

    for (const [name, checker] of this.checks) {
      try {
        const result = await checker();
        results[name] = { status: result.healthy ? 'up' : 'down', ...result };
        if (!result.healthy) allHealthy = false;
      } catch (err) {
        results[name] = { status: 'down', error: err.message, healthy: false };
        allHealthy = false;
      }
    }

    return { healthy: allHealthy, checks: results };
  }

  async liveness() {
    // Liveness: is the process alive?
    const uptime = Date.now() - this.startTime;
    return {
      status: 'alive',
      uptime: Math.floor(uptime / 1000),
      timestamp: new Date().toISOString()
    };
  }

  async readiness(options = {}) {
    // Readiness: are dependencies ready?
    const uptime = Date.now() - this.startTime;
    if (uptime < this.minUptimeMs) {
      return { status: 'not ready', reason: 'Minimum uptime not reached', ready: false };
    }

    const { redisClient, workerQueue, memoryManager } = options;
    const checks = {};
    let ready = true;

    // Disk space check
    try {
      const disk = await this.checkDiskSpace();
      checks.disk = disk;
      if (!disk.healthy) ready = false;
    } catch (err) {
      checks.disk = { healthy: false, error: err.message };
      ready = false;
    }

    // Redis check
    if (redisClient) {
      try {
        const redisHealthy = redisClient.connected;
        checks.redis = { healthy: redisHealthy, status: redisHealthy ? 'connected' : 'disconnected' };
        if (!redisHealthy) ready = false;
      } catch (err) {
        checks.redis = { healthy: false, error: err.message };
        ready = false;
      }
    }

    // Worker queue check
    if (workerQueue) {
      checks.workerQueue = { healthy: workerQueue.initialized, status: workerQueue.initialized ? 'initialized' : 'disabled' };
    }

    // Memory check
    if (memoryManager) {
      const health = memoryManager.getHealth();
      checks.memory = { healthy: health.status !== 'critical', status: health.status, usage: health.usage };
      if (health.status === 'critical') ready = false;
    }

    return {
      status: ready ? 'ready' : 'not ready',
      ready,
      uptime: Math.floor(uptime / 1000),
      timestamp: new Date().toISOString(),
      checks
    };
  }

  async checkDiskSpace() {
    try {
      const stats = fs.statSync(this.dataDir);
      // Approximate using available free space on Windows via wmic or simple check
      // For cross-platform, just check writability
      const testFile = path.join(this.dataDir, '.healthcheck');
      fs.writeFileSync(testFile, '1');
      fs.unlinkSync(testFile);
      return { healthy: true, writable: true };
    } catch (err) {
      return { healthy: false, writable: false, error: err.message };
    }
  }

  middleware(options = {}) {
    return async (req, res, next) => {
      if (req.path === '/health/live') {
        const result = await this.liveness();
        res.status(200).json(result);
        return;
      }
      if (req.path === '/health/ready') {
        const result = await this.readiness(options);
        res.status(result.ready ? 200 : 503).json(result);
        return;
      }
      if (req.path === '/health') {
        const result = await this.runChecks();
        res.status(result.healthy ? 200 : 503).json(result);
        return;
      }
      next();
    };
  }
}

module.exports = { HealthCheck };
