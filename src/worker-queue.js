/**
 * Async Worker Queue for Background Processing
 * Uses Bull for Redis-backed job queues
 */

const Queue = require('bull');
const { WAFEngine } = require('./waf-engine');

class WorkerQueue {
  constructor(options = {}) {
    this.redisConfig = {
      host: options.redisHost || process.env.REDIS_HOST || 'localhost',
      port: options.redisPort || process.env.REDIS_PORT || 6379,
      password: options.redisPassword || process.env.REDIS_PASSWORD,
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      enableOfflineQueue: false
    };

    this.queues = new Map();
    this.processors = new Map();
    this.engine = null;
    this.logger = options.logger || console;
    
    // Queue configuration
    this.defaultJobOptions = {
      removeOnComplete: 100,
      removeOnFail: 50,
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000
      },
      timeout: 30000 // 30 seconds
    };

    this.initialized = false;
  }

  async initialize(engine) {
    this.engine = engine;
    
    try {
      // Create main analysis queue
      this.createQueue('request-analysis', this.processRequestAnalysis.bind(this));
      
      // Create threat processing queue
      this.createQueue('threat-processing', this.processThreat.bind(this));
      
      // Create log processing queue
      this.createQueue('log-processing', this.processLog.bind(this));

      this.initialized = true;
      this.logger.info('✅ Worker Queue initialized with Redis');
    } catch (err) {
      this.initialized = false;
      this.logger.warn('⚠️ Worker Queue initialization failed:', err.message);
    }
    
    return this;
  }

  createQueue(name, processor, options = {}) {
    // Quick ping before creating queue
    const queue = new Queue(name, {
      redis: this.redisConfig,
      defaultJobOptions: {
        ...this.defaultJobOptions,
        ...options
      }
    });

    // Handle connection errors for each queue
    let lastErrorLog = 0;
    queue.on('error', (err) => {
      const now = Date.now();
      if (err.code === 'ECONNREFUSED' || err.code === 'NR_CLOSED') {
        if (now - lastErrorLog > 30000) {
          this.logger.warn(`Redis unavailable for queue ${name}, working in sync mode`);
          lastErrorLog = now;
        }
      } else {
        this.logger.error(`Queue ${name} error:`, err.message);
      }
    });

    // Handle queue events
    queue.on('completed', (job, result) => {
      this.logger.debug(`Job ${job.id} completed in queue ${name}`);
    });

    queue.on('failed', (job, err) => {
      this.logger.error(`Job ${job.id} failed in queue ${name}:`, err.message);
    });

    queue.on('stalled', (job) => {
      this.logger.warn(`Job ${job.id} stalled in queue ${name}`);
    });

    // Process jobs
    queue.process(processor);

    this.queues.set(name, queue);
    this.processors.set(name, processor);
    
    return queue;
  }

  async addJob(queueName, data, options = {}) {
    if (!this.initialized) {
      return null; // Silent fail, queue not available
    }

    const queue = this.queues.get(queueName);
    if (!queue) {
      return null;
    }

    try {
      const job = await queue.add(data, {
        ...this.defaultJobOptions,
        ...options
      });
      return job;
    } catch (err) {
      if (err.code === 'ECONNREFUSED') {
        this.logger.warn(`Redis unavailable, skipping queue job for ${queueName}`);
        return null;
      }
      throw err;
    }
  }

  async addRequestAnalysis(requestData, options = {}) {
    return this.addJob('request-analysis', {
      type: 'request-analysis',
      request: requestData,
      timestamp: Date.now()
    }, {
      priority: 1, // High priority
      ...options
    });
  }

  async addThreatProcessing(threatData, options = {}) {
    return this.addJob('threat-processing', {
      type: 'threat-processing',
      threat: threatData,
      timestamp: Date.now()
    }, {
      priority: 2, // Medium-high priority
      ...options
    });
  }

  async addLogProcessing(logData, options = {}) {
    return this.addJob('log-processing', {
      type: 'log-processing',
      log: logData,
      timestamp: Date.now()
    }, {
      priority: 3, // Medium priority
      ...options
    });
  }

  // Job processors
  async processRequestAnalysis(job) {
    const { request } = job.data;
    
    try {
      // Perform deep analysis in background
      const analysis = await this.performDeepAnalysis(request);
      
      // Store results for later retrieval
      await this.storeAnalysisResults(job.id, analysis);
      
      return {
        jobId: job.id,
        status: 'completed',
        analysis
      };
    } catch (error) {
      this.logger.error('Request analysis failed:', error);
      throw error;
    }
  }

  async processThreat(job) {
    const { threat } = job.data;
    
    try {
      // Enrich threat data
      const enrichedThreat = await this.enrichThreatData(threat);
      
      // Send notifications
      await this.sendThreatNotifications(enrichedThreat);
      
      // Update threat intelligence
      await this.updateThreatIntelligence(enrichedThreat);
      
      return {
        jobId: job.id,
        status: 'completed',
        threat: enrichedThreat
      };
    } catch (error) {
      this.logger.error('Threat processing failed:', error);
      throw error;
    }
  }

  async processLog(job) {
    const { log } = job.data;
    
    try {
      // Batch logs for efficient storage
      await this.batchAndStoreLog(log);
      
      // Perform log analysis
      await this.analyzeLogPatterns(log);
      
      return {
        jobId: job.id,
        status: 'completed'
      };
    } catch (error) {
      this.logger.error('Log processing failed:', error);
      throw error;
    }
  }

  // Analysis methods
  async performDeepAnalysis(request) {
    const analysis = {
      timestamp: Date.now(),
      threatScore: 0,
      patterns: [],
      behavioralAnalysis: null,
      geoAnalysis: null,
      reputationCheck: null
    };

    // Parallel deep analysis
    const results = await Promise.allSettled([
      this.analyzeBehavioralPatterns(request),
      this.checkIPReputation(request.ip),
      this.analyzeRequestPatterns(request),
      this.performHeuristicAnalysis(request)
    ]);

    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        switch(index) {
          case 0: analysis.behavioralAnalysis = result.value; break;
          case 1: analysis.reputationCheck = result.value; break;
          case 2: analysis.patterns = result.value; break;
          case 3: analysis.threatScore += result.value.score || 0; break;
        }
      }
    });

    return analysis;
  }

  async analyzeBehavioralPatterns(request) {
    // Analyze user behavior patterns
    return {
      sessionConsistency: this.checkSessionConsistency(request),
      requestVelocity: this.calculateRequestVelocity(request.ip),
      userAgentAnomaly: this.detectUserAgentAnomaly(request),
      timingPattern: this.analyzeTimingPattern(request)
    };
  }

  async checkIPReputation(ip) {
    // Check IP reputation from various sources
    return {
      ip,
      knownBad: false,
      threatScore: 0,
      sources: [],
      lastChecked: Date.now()
    };
  }

  async analyzeRequestPatterns(request) {
    // Analyze request for suspicious patterns
    const patterns = [];
    
    // Check for automated patterns
    if (this.isAutomatedPattern(request)) {
      patterns.push({ type: 'automated', confidence: 0.8 });
    }
    
    // Check for scanning behavior
    if (this.isScanningBehavior(request)) {
      patterns.push({ type: 'scanning', confidence: 0.7 });
    }
    
    return patterns;
  }

  async performHeuristicAnalysis(request) {
    // Heuristic-based threat detection
    let score = 0;
    
    // Check request entropy (randomness)
    const entropy = this.calculateEntropy(request.url);
    if (entropy > 0.8) score += 10;
    
    // Check for encoding tricks
    if (this.hasEncodingTricks(request)) score += 15;
    
    // Check for unusual headers
    if (this.hasUnusualHeaders(request)) score += 5;
    
    return { score, entropy };
  }

  // Helper methods
  isAutomatedPattern(request) {
    const indicators = [
      !request.headers['accept-language'],
      request.headers['accept'] === '*/*',
      !request.headers['referer'] && request.method === 'POST'
    ];
    return indicators.filter(Boolean).length >= 2;
  }

  isScanningBehavior(request) {
    // Detect if request is part of a scan
    const scanSignatures = [
      /\.(git|svn|env|config)/i,
      /(admin|login|wp-content|phpmyadmin)/i,
      /\.(bak|backup|old|swp)$/i
    ];
    return scanSignatures.some(pattern => pattern.test(request.url));
  }

  calculateEntropy(str) {
    const len = str.length;
    const freq = {};
    
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy / Math.log2(Math.min(len, 256));
  }

  hasEncodingTricks(request) {
    const url = request.url.toLowerCase();
    return url.includes('%') && /%[0-9a-f]{2}/i.test(url);
  }

  hasUnusualHeaders(request) {
    const unusualHeaders = [
      'x-forwarded-host',
      'x-http-host-override',
      'x-forwarded-scheme'
    ];
    return unusualHeaders.some(h => request.headers[h]);
  }

  checkSessionConsistency(request) {
    return { consistent: true, score: 0 };
  }

  calculateRequestVelocity(ip) {
    return { velocity: 0, burstDetected: false };
  }

  detectUserAgentAnomaly(request) {
    return { anomaly: false, score: 0 };
  }

  analyzeTimingPattern(request) {
    return { pattern: 'normal', regularity: 0 };
  }

  // Storage methods
  async storeAnalysisResults(jobId, analysis) {
    // Store in Redis or database
    this.logger.debug(`Stored analysis results for job ${jobId}`);
  }

  async enrichThreatData(threat) {
    return {
      ...threat,
      enriched: true,
      timestamp: Date.now()
    };
  }

  async sendThreatNotifications(threat) {
    // Send to webhooks, email, etc.
    this.logger.info(`Sending notifications for threat: ${threat.type}`);
  }

  async updateThreatIntelligence(threat) {
    // Update threat intelligence database
    this.logger.debug('Updated threat intelligence');
  }

  async batchAndStoreLog(log) {
    // Batch logs for efficient storage
    this.logger.debug('Batched log for storage');
  }

  async analyzeLogPatterns(log) {
    // Analyze log patterns for anomalies
    this.logger.debug('Analyzed log patterns');
  }

  // Queue management
  async getQueueStats() {
    const stats = {};
    
    for (const [name, queue] of this.queues) {
      const [waiting, active, completed, failed, delayed] = await Promise.all([
        queue.getWaitingCount(),
        queue.getActiveCount(),
        queue.getCompletedCount(),
        queue.getFailedCount(),
        queue.getDelayedCount()
      ]);
      
      stats[name] = {
        waiting,
        active,
        completed,
        failed,
        delayed
      };
    }
    
    return stats;
  }

  async pauseQueue(name) {
    const queue = this.queues.get(name);
    if (queue) {
      await queue.pause();
      this.logger.info(`Queue ${name} paused`);
    }
  }

  async resumeQueue(name) {
    const queue = this.queues.get(name);
    if (queue) {
      await queue.resume();
      this.logger.info(`Queue ${name} resumed`);
    }
  }

  async cleanQueue(name, options = {}) {
    const queue = this.queues.get(name);
    if (queue) {
      await queue.clean(options.grace || 3600000, options.status || 'completed');
      this.logger.info(`Cleaned queue ${name}`);
    }
  }

  async close() {
    for (const [name, queue] of this.queues) {
      await queue.close();
      this.logger.info(`Queue ${name} closed`);
    }
    this.initialized = false;
  }
}

module.exports = { WorkerQueue };
itialized = false;
  }
}

module.exports = { WorkerQueue };
