/**
 * Redis Client Wrapper
 * Provides distributed caching with graceful fallback to in-memory
 */

const Redis = require('ioredis');

class RedisClient {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.host = options.host || process.env.REDIS_HOST || 'localhost';
    this.port = options.port || process.env.REDIS_PORT || 6379;
    this.password = options.password || process.env.REDIS_PASSWORD;
    this.db = options.db || 0;
    this.keyPrefix = options.keyPrefix || 'kavach:';
    this.ttlSeconds = options.ttlSeconds || 3600;

    this.client = null;
    this.connected = false;
    this.fallbackCache = new Map();

    if (this.enabled) {
      this.connect();
    }
  }

  connect() {
    try {
      this.client = new Redis({
        host: this.host,
        port: this.port,
        password: this.password,
        db: this.db,
        keyPrefix: this.keyPrefix,
        retryStrategy: (times) => Math.min(times * 100, 3000),
        maxRetriesPerRequest: 3,
        enableOfflineQueue: false,
        lazyConnect: true
      });

      this.client.on('connect', () => {
        this.connected = true;
        console.log('✅ Redis cache connected');
      });

      this.client.on('error', (err) => {
        if (err.code === 'ECONNREFUSED') {
          this.connected = false;
        }
      });

      this.client.on('close', () => {
        this.connected = false;
      });

      this.client.connect().catch(() => {
        this.connected = false;
      });
    } catch (err) {
      this.connected = false;
      this.client = null;
    }
  }

  async get(key) {
    const fullKey = this.keyPrefix + key;
    if (this.connected && this.client) {
      try {
        const value = await this.client.get(fullKey);
        if (value) return JSON.parse(value);
      } catch {
        // fallback
      }
    }
    const entry = this.fallbackCache.get(fullKey);
    if (entry && entry.expires > Date.now()) {
      return entry.value;
    }
    this.fallbackCache.delete(fullKey);
    return null;
  }

  async set(key, value, ttlSeconds) {
    const fullKey = this.keyPrefix + key;
    const ttl = (ttlSeconds || this.ttlSeconds) * 1000;
    if (this.connected && this.client) {
      try {
        await this.client.setex(fullKey, ttlSeconds || this.ttlSeconds, JSON.stringify(value));
        return;
      } catch {
        // fallback
      }
    }
    this.fallbackCache.set(fullKey, { value, expires: Date.now() + ttl });
  }

  async del(key) {
    const fullKey = this.keyPrefix + key;
    if (this.connected && this.client) {
      try {
        await this.client.del(fullKey);
      } catch {
        // fallback
      }
    }
    this.fallbackCache.delete(fullKey);
  }

  async increment(key, windowSeconds) {
    const fullKey = this.keyPrefix + key;
    if (this.connected && this.client) {
      try {
        const pipeline = this.client.pipeline();
        pipeline.incr(fullKey);
        pipeline.expire(fullKey, windowSeconds);
        const results = await pipeline.exec();
        return results[0][1];
      } catch {
        // fallback
      }
    }
    const entry = this.fallbackCache.get(fullKey);
    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    if (!entry || entry.expires < now) {
      this.fallbackCache.set(fullKey, { value: 1, expires: now + windowMs });
      return 1;
    }
    entry.value++;
    return entry.value;
  }

  async getRateLimitCount(key, windowSeconds) {
    const fullKey = this.keyPrefix + key;
    if (this.connected && this.client) {
      try {
        const count = await this.client.get(fullKey);
        const ttl = await this.client.ttl(fullKey);
        return { count: parseInt(count || '0', 10), ttl };
      } catch {
        // fallback
      }
    }
    const entry = this.fallbackCache.get(fullKey);
    if (entry && entry.expires > Date.now()) {
      return { count: entry.value, ttl: Math.ceil((entry.expires - Date.now()) / 1000) };
    }
    return { count: 0, ttl: windowSeconds };
  }

  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.fallbackCache) {
      if (entry.expires < now) {
        this.fallbackCache.delete(key);
      }
    }
  }

  async close() {
    if (this.client) {
      await this.client.quit();
    }
    this.fallbackCache.clear();
  }
}

module.exports = { RedisClient };
