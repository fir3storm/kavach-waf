/**
 * Bot Detection Module
 * Detects and blocks automated bots, crawlers, and scrapers
 */

class BotDetector {
  constructor(options = {}) {
    this.blockedBots = new Set(options.blockedBots || []);
    this.allowedBots = new Set(options.allowedBots || ['googlebot', 'bingbot', 'slurp']);
    this.challengeEnabled = options.challengeEnabled || false;
    
    // Known bad bot signatures
    this.botSignatures = [
      // Scrapers
      /scrapy/i, /scraping/i, /scraper/i,
      // Automated tools
      /curl/i, /wget/i, /python-requests/i, /axios/i, /node-fetch/i,
      /httpclient/i, /java\//i, /libwww/i, / mechanize/i,
      // SEO tools
      /ahrefs/i, /semrush/i, /moz\.com/i, /majestic/i,
      // Bad bots
      /petalbot/i, /dataprovider/i, /crawler/i, /spider/i,
      /bot\/\d/i, /spider\/\d/i, /crawler\/\d/i,
      // Headless browsers (often used for scraping)
      /headless/i, /phantomjs/i, /selenium/i, /puppeteer/i, /playwright/i,
      // Unknown/generic bots
      /unknown/i, /bot\/0/i, /crawler\/0/i
    ];
    
    // Good bots (search engines)
    this.goodBots = [
      /googlebot/i, /bingbot/i, /slurp/i, /duckduckbot/i,
      /baiduspider/i, /yandexbot/i, /facebookexternalhit/i,
      /twitterbot/i, /linkedinbot/i, /applebot/i
    ];
  }

  /**
   * Analyze request for bot detection
   */
  analyze(req) {
    const userAgent = req.headers['user-agent'] || '';
    const result = {
      isBot: false,
      isGoodBot: false,
      isBadBot: false,
      reason: null,
      score: 0
    };

    // Empty user agent is suspicious
    if (!userAgent || userAgent.length < 10) {
      result.score += 30;
      result.reason = 'Empty or very short user agent';
    }

    // Check for good bots
    for (const pattern of this.goodBots) {
      if (pattern.test(userAgent)) {
        result.isGoodBot = true;
        result.isBot = true;
        return result;
      }
    }

    // Check for bad bot signatures
    for (const pattern of this.botSignatures) {
      if (pattern.test(userAgent)) {
        result.isBadBot = true;
        result.isBot = true;
        result.reason = `Matched pattern: ${pattern}`;
        result.score += 50;
        break;
      }
    }

    // Check for browser-like behavior
    const browserIndicators = [
      /mozilla\/\d/i, /chrome\/\d/i, /safari\/\d/i,
      /firefox\/\d/i, /edge\/\d/i, /opera\/\d/i
    ];
    
    let hasBrowserIndicator = false;
    for (const pattern of browserIndicators) {
      if (pattern.test(userAgent)) {
        hasBrowserIndicator = true;
        break;
      }
    }

    if (!hasBrowserIndicator && !result.isGoodBot) {
      result.score += 20;
      if (!result.reason) {
        result.reason = 'No browser indicators in user agent';
      }
    }

    // Check for suspicious headers
    const suspiciousHeaders = this.checkHeaders(req);
    if (suspiciousHeaders.length > 0) {
      result.score += 15 * suspiciousHeaders.length;
      result.reason = result.reason || `Suspicious headers: ${suspiciousHeaders.join(', ')}`;
    }

    // Behavioral checks
    const behaviorScore = this.checkBehavior(req);
    result.score += behaviorScore;

    // Determine if it's a bot based on score
    if (result.score >= 50) {
      result.isBot = true;
      result.isBadBot = true;
    }

    return result;
  }

  /**
   * Check for suspicious headers
   */
  checkHeaders(req) {
    const suspicious = [];
    const headers = req.headers;

    // Missing accept headers
    if (!headers.accept) {
      suspicious.push('missing-accept');
    }

    // Missing accept-language
    if (!headers['accept-language']) {
      suspicious.push('missing-accept-language');
    }

    // Missing accept-encoding
    if (!headers['accept-encoding']) {
      suspicious.push('missing-accept-encoding');
    }

    // Check for automation headers
    if (headers['x-requested-with']) {
      suspicious.push('has-x-requested-with');
    }

    return suspicious;
  }

  /**
   * Check request behavior patterns
   */
  checkBehavior(req) {
    let score = 0;

    // Very fast requests (would need session tracking in real implementation)
    // This is a placeholder for behavioral analysis

    // Unusual request patterns
    const path = req.path || '';
    if (path.includes('wp-admin') || path.includes('wp-login')) {
      score += 10; // WordPress probing
    }

    if (path.includes('.env') || path.includes('config')) {
      score += 15; // Config file probing
    }

    if (path.includes('phpmyadmin') || path.includes('admin')) {
      score += 10; // Admin panel probing
    }

    return score;
  }

  /**
   * Generate challenge for suspected bots
   */
  generateChallenge() {
    const a = Math.floor(Math.random() * 20) + 1;
    const b = Math.floor(Math.random() * 20) + 1;
    const answer = a + b;
    
    return {
      question: `${a} + ${b} = ?`,
      answer: answer.toString(),
      token: Buffer.from(`${a}:${b}:${Date.now()}`).toString('base64')
    };
  }

  /**
   * Verify challenge response
   */
  verifyChallenge(token, answer) {
    try {
      const decoded = Buffer.from(token, 'base64').toString();
      const [a, b, timestamp] = decoded.split(':');
      const expected = (parseInt(a) + parseInt(b)).toString();
      
      // Check if challenge expired (5 minutes)
      if (Date.now() - parseInt(timestamp) > 300000) {
        return false;
      }
      
      return answer === expected;
    } catch {
      return false;
    }
  }

  // Management methods
  blockBot(name) {
    this.blockedBots.add(name.toLowerCase());
  }

  unblockBot(name) {
    this.blockedBots.delete(name.toLowerCase());
  }

  allowBot(name) {
    this.allowedBots.add(name.toLowerCase());
  }

  getBlockedBots() {
    return Array.from(this.blockedBots);
  }

  getAllowedBots() {
    return Array.from(this.allowedBots);
  }
}

module.exports = { BotDetector };
