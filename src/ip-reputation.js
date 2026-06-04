/**
 * IP Reputation Service
 * Multi-source threat intelligence lookup with caching
 */

const https = require('https');
const { URL } = require('url');

class IPReputationService {
  constructor(options = {}) {
    this.abuseIPDBKey = options.abuseIPDBKey || process.env.ABUSEIPDB_KEY;
    this.virusTotalKey = options.virusTotalKey || process.env.VIRUSTOTAL_KEY;
    this.customBlacklist = new Set(options.customBlacklist || []);
    this.customWhitelist = new Set(options.customWhitelist || []);
    this.cache = options.cache || null; // RedisClient instance
    this.cacheTTL = options.cacheTTL || 3600; // 1 hour
    this.timeout = options.timeout || 5000;

    this.riskLevels = ['safe', 'low', 'medium', 'high', 'critical'];
  }

  async checkIP(ip) {
    if (!ip || ip === 'unknown' || ip === '127.0.0.1' || ip === '::1') {
      return { ip, risk: 'safe', score: 0, sources: [], reason: 'Local/unknown IP' };
    }

    if (this.customWhitelist.has(ip)) {
      return { ip, risk: 'safe', score: 0, sources: ['custom_whitelist'], reason: 'Whitelisted' };
    }

    if (this.customBlacklist.has(ip)) {
      return { ip, risk: 'critical', score: 100, sources: ['custom_blacklist'], reason: 'Custom blacklist' };
    }

    // Check cache
    const cacheKey = `iprep:${ip}`;
    if (this.cache) {
      const cached = await this.cache.get(cacheKey);
      if (cached) return cached;
    }

    const results = await Promise.allSettled([
      this.checkAbuseIPDB(ip),
      this.checkVirusTotal(ip)
    ]);

    let score = 0;
    const sources = [];
    const reasons = [];

    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        const src = index === 0 ? 'abuseipdb' : 'virustotal';
        sources.push(src);
        score = Math.max(score, result.value.score || 0);
        if (result.value.reason) reasons.push(result.value.reason);
      }
    });

    const risk = this.scoreToRisk(score);
    const report = { ip, risk, score, sources, reason: reasons.join('; ') || 'No threat intelligence found' };

    if (this.cache) {
      await this.cache.set(cacheKey, report, this.cacheTTL);
    }

    return report;
  }

  scoreToRisk(score) {
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 10) return 'low';
    return 'safe';
  }

  async checkAbuseIPDB(ip) {
    if (!this.abuseIPDBKey) return null;
    try {
      const data = await this.httpGet(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
        { 'Key': this.abuseIPDBKey, 'Accept': 'application/json' }
      );
      const json = JSON.parse(data);
      const score = json.data?.abuseConfidenceScore || 0;
      return { score, reason: `AbuseIPDB confidence: ${score}%` };
    } catch {
      return null;
    }
  }

  async checkVirusTotal(ip) {
    if (!this.virusTotalKey) return null;
    try {
      const data = await this.httpGet(
        `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
        { 'x-apikey': this.virusTotalKey }
      );
      const json = JSON.parse(data);
      const stats = json.data?.attributes?.last_analysis_stats;
      if (stats) {
        const malicious = stats.malicious || 0;
        const total = (stats.harmless || 0) + malicious + (stats.suspicious || 0);
        const score = total > 0 ? Math.round((malicious / total) * 100) : 0;
        return { score, reason: `VirusTotal: ${malicious}/${total} vendors flagged` };
      }
      return null;
    } catch {
      return null;
    }
  }

  httpGet(url, headers) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const req = https.get(parsed, { headers, timeout: this.timeout }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else {
            reject(new Error(`HTTP ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    });
  }

  addToBlacklist(ip) {
    this.customBlacklist.add(ip);
    this.customWhitelist.delete(ip);
  }

  removeFromBlacklist(ip) {
    this.customBlacklist.delete(ip);
  }

  addToWhitelist(ip) {
    this.customWhitelist.add(ip);
    this.customBlacklist.delete(ip);
  }

  removeFromWhitelist(ip) {
    this.customWhitelist.delete(ip);
  }

  getBlacklist() {
    return Array.from(this.customBlacklist);
  }

  getWhitelist() {
    return Array.from(this.customWhitelist);
  }
}

module.exports = { IPReputationService };
