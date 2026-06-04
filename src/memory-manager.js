/**
 * Memory Manager - Automatic cleanup and heap monitoring
 * Monitors memory usage and performs automatic cleanup when thresholds are exceeded
 */

class MemoryManager {
  constructor(options = {}) {
    // Configuration
    this.maxHeapSize = options.maxHeapSize || 512 * 1024 * 1024; // 512MB default
    this.gcThreshold = options.gcThreshold || 0.8; // 80% of max heap
    this.criticalThreshold = options.criticalThreshold || 0.95; // 95% critical
    this.checkInterval = options.checkInterval || 30000; // 30 seconds
    this.emergencyInterval = options.emergencyInterval || 5000; // 5 seconds when critical
    
    // Cleanup configuration
    this.maxLogsInMemory = options.maxLogsInMemory || 1000;
    this.maxRateLimitEntries = options.maxRateLimitEntries || 10000;
    this.maxCacheEntries = options.maxCacheEntries || 5000;
    this.logRetentionMs = options.logRetentionMs || 3600000; // 1 hour
    this.rateLimitRetentionMs = options.rateLimitRetentionMs || 600000; // 10 minutes
    
    // State
    this.monitoring = false;
    this.intervalId = null;
    this.metrics = {
      lastCheck: null,
      heapUsed: 0,
      heapTotal: 0,
      rss: 0,
      external: 0,
      usagePercent: 0,
      gcRuns: 0,
      cleanups: 0,
      emergencyCleanups: 0
    };
    
    // Callbacks
    this.onCleanup = options.onCleanup || null;
    this.onCritical = options.onCritical || null;
    this.onMetrics = options.onMetrics || null;
    
    // References to clean
    this.references = new Map();
    
    this.logger = options.logger || console;
  }

  start() {
    if (this.monitoring) {
      this.logger.warn('Memory manager already running');
      return;
    }
    
    this.monitoring = true;
    this.performCheck(); // Initial check
    
    this.intervalId = setInterval(() => {
      this.performCheck();
    }, this.checkInterval);
    
    this.logger.info('✅ Memory Manager started');
    this.logger.info(`   Max Heap: ${this.formatBytes(this.maxHeapSize)}`);
    this.logger.info(`   GC Threshold: ${(this.gcThreshold * 100).toFixed(0)}%`);
    this.logger.info(`   Check Interval: ${this.checkInterval}ms`);
  }

  stop() {
    if (!this.monitoring) return;
    
    this.monitoring = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    
    this.logger.info('Memory Manager stopped');
  }

  performCheck() {
    const usage = process.memoryUsage();
    this.metrics.lastCheck = Date.now();
    this.metrics.heapUsed = usage.heapUsed;
    this.metrics.heapTotal = usage.heapTotal;
    this.metrics.rss = usage.rss;
    this.metrics.external = usage.external;
    this.metrics.usagePercent = usage.heapUsed / this.maxHeapSize;

    // Emit metrics if callback provided
    if (this.onMetrics) {
      this.onMetrics({ ...this.metrics });
    }

    // Check thresholds
    if (this.metrics.usagePercent >= this.criticalThreshold) {
      this.handleCriticalMemory();
    } else if (this.metrics.usagePercent >= this.gcThreshold) {
      this.performCleanup();
    }

    // Adjust check interval based on memory pressure
    this.adjustCheckInterval();
  }

  handleCriticalMemory() {
    this.logger.error(`🚨 CRITICAL MEMORY: ${(this.metrics.usagePercent * 100).toFixed(1)}%`);
    this.metrics.emergencyCleanups++;
    
    // Emergency cleanup - aggressive
    this.performEmergencyCleanup();
    
    // Force GC if available
    this.forceGC();
    
    // Call critical callback
    if (this.onCritical) {
      this.onCritical({
        usage: this.metrics,
        action: 'emergency_cleanup'
      });
    }
  }

  performCleanup() {
    this.logger.warn(`⚠️  Memory threshold exceeded: ${(this.metrics.usagePercent * 100).toFixed(1)}%`);
    this.metrics.cleanups++;
    
    const beforeCleanup = process.memoryUsage().heapUsed;
    
    // Clean up registered references
    this.cleanupReferences();
    
    // Clean global objects if available
    this.cleanupGlobalObjects();
    
    // Force GC if available
    this.forceGC();
    
    const afterCleanup = process.memoryUsage().heapUsed;
    const freed = beforeCleanup - afterCleanup;
    
    this.logger.info(`🧹 Cleanup freed: ${this.formatBytes(freed)}`);
    
    // Call cleanup callback
    if (this.onCleanup) {
      this.onCleanup({
        before: beforeCleanup,
        after: afterCleanup,
        freed: freed
      });
    }
  }

  performEmergencyCleanup() {
    this.logger.warn('🚨 Performing emergency cleanup...');
    
    // Aggressive cleanup - reduce all limits by 50%
    const emergencyFactor = 0.5;
    
    // Clean logs more aggressively
    if (global.wafLogger) {
      const targetSize = Math.floor(this.maxLogsInMemory * emergencyFactor);
      if (global.wafLogger.logs.length > targetSize) {
        global.wafLogger.logs = global.wafLogger.logs.slice(-targetSize);
        this.logger.info(`   Logs reduced to ${targetSize} entries`);
      }
    }
    
    // Clean rate limiter
    this.cleanupRateLimiter(true);
    
    // Clean all caches
    this.cleanupCaches(true);
    
    // Clear non-essential references
    this.clearNonEssentialReferences();
  }

  cleanupReferences() {
    for (const [name, ref] of this.references) {
      if (ref && typeof ref.cleanup === 'function') {
        try {
          ref.cleanup();
          this.logger.debug(`   Cleaned reference: ${name}`);
        } catch (err) {
          this.logger.error(`   Failed to clean ${name}:`, err.message);
        }
      }
    }
  }

  cleanupGlobalObjects() {
    // Clean WAF logger
    if (global.wafLogger && global.wafLogger.logs) {
      const now = Date.now();
      const initialLength = global.wafLogger.logs.length;
      
      // Remove old logs
      global.wafLogger.logs = global.wafLogger.logs.filter(log => {
        return now - (log.timestamp || 0) < this.logRetentionMs;
      });
      
      // Limit total size
      if (global.wafLogger.logs.length > this.maxLogsInMemory) {
        global.wafLogger.logs = global.wafLogger.logs.slice(-this.maxLogsInMemory);
      }
      
      const removed = initialLength - global.wafLogger.logs.length;
      if (removed > 0) {
        this.logger.info(`   Cleaned ${removed} old log entries`);
      }
    }
    
    // Clean rate limiter
    this.cleanupRateLimiter(false);
    
    // Clean caches
    this.cleanupCaches(false);
  }

  cleanupRateLimiter(emergency = false) {
    // Access rate limiter from engine if available
    const rateLimiter = global.wafRateLimiter || this.getRateLimiter();
    if (!rateLimiter) return;
    
    const now = Date.now();
    let cleaned = 0;
    
    for (const [key, record] of rateLimiter.entries()) {
      const age = now - (record.firstRequest || record.lastRequest || 0);
      const threshold = emergency ? this.rateLimitRetentionMs / 2 : this.rateLimitRetentionMs;
      
      if (age > threshold) {
        rateLimiter.delete(key);
        cleaned++;
      }
    }
    
    // Emergency: limit total entries
    if (emergency && rateLimiter.size > this.maxRateLimitEntries * 0.5) {
      const entries = Array.from(rateLimiter.entries());
      const toRemove = entries.slice(0, entries.length - Math.floor(this.maxRateLimitEntries * 0.5));
      toRemove.forEach(([key]) => rateLimiter.delete(key));
      cleaned += toRemove.length;
    }
    
    if (cleaned > 0) {
      this.logger.info(`   Cleaned ${cleaned} rate limit entries`);
    }
  }

  cleanupCaches(emergency = false) {
    // Clean any registered caches
    for (const [name, cache] of this.references) {
      if (cache && cache instanceof Map) {
        const initialSize = cache.size;
        
        if (cache.size > this.maxCacheEntries) {
          // Remove oldest entries (first half)
          const entries = Array.from(cache.entries());
          const toRemove = entries.slice(0, Math.floor(entries.length / 2));
          toRemove.forEach(([key]) => cache.delete(key));
          
          this.logger.info(`   Cleaned cache ${name}: ${initialSize} → ${cache.size}`);
        }
      }
    }
  }

  clearNonEssentialReferences() {
    // Clear any non-essential data
    for (const [name, ref] of this.references) {
      if (ref && ref.essential === false) {
        if (ref.data && typeof ref.data.clear === 'function') {
          ref.data.clear();
          this.logger.info(`   Cleared non-essential: ${name}`);
        }
      }
    }
  }

  forceGC() {
    if (global.gc) {
      this.metrics.gcRuns++;
      global.gc();
      this.logger.debug('   Garbage collection triggered');
    } else {
      this.logger.debug('   GC not exposed (run with --expose-gc)');
    }
  }

  adjustCheckInterval() {
    const usage = this.metrics.usagePercent;
    let newInterval = this.checkInterval;
    
    if (usage >= this.criticalThreshold) {
      newInterval = this.emergencyInterval;
    } else if (usage >= this.gcThreshold) {
      newInterval = this.checkInterval / 2;
    }
    
    if (newInterval !== this.checkInterval && this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = setInterval(() => this.performCheck(), newInterval);
      this.logger.debug(`   Check interval adjusted: ${newInterval}ms`);
    }
  }

  // Registration methods
  registerReference(name, ref, options = {}) {
    this.references.set(name, {
      ...ref,
      essential: options.essential !== false,
      cleanup: ref.cleanup || null
    });
  }

  unregisterReference(name) {
    this.references.delete(name);
  }

  // Utility methods
  getRateLimiter() {
    // Try to find rate limiter from various sources
    if (global.wafEngine && global.wafEngine.rateLimiter) {
      return global.wafEngine.rateLimiter;
    }
    return null;
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // Metrics API
  getMetrics() {
    return {
      ...this.metrics,
      maxHeapSize: this.maxHeapSize,
      gcThreshold: this.gcThreshold,
      criticalThreshold: this.criticalThreshold,
      formatted: {
        heapUsed: this.formatBytes(this.metrics.heapUsed),
        heapTotal: this.formatBytes(this.metrics.heapTotal),
        rss: this.formatBytes(this.metrics.rss),
        external: this.formatBytes(this.metrics.external),
        maxHeap: this.formatBytes(this.maxHeapSize)
      }
    };
  }

  getHealth() {
    const usage = this.metrics.usagePercent;
    
    if (usage >= this.criticalThreshold) {
      return { status: 'critical', usage: usage * 100 };
    } else if (usage >= this.gcThreshold) {
      return { status: 'warning', usage: usage * 100 };
    } else {
      return { status: 'healthy', usage: usage * 100 };
    }
  }

  // Manual cleanup trigger
  async manualCleanup() {
    this.logger.info('Manual cleanup triggered');
    this.performCleanup();
    return this.getMetrics();
  }
}

module.exports = { MemoryManager };
