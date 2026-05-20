/**
 * Request Sanitization Module
 * Cleans and sanitizes user input
 */

class RequestSanitizer {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.stripHtml = options.stripHtml !== false;
    this.encodeHtml = options.encodeHtml || false;
    this.trimWhitespace = options.trimWhitespace !== false;
    this.removeNullBytes = options.removeNullBytes !== false;
    this.maxLength = options.maxLength || 10000;
    this.allowedTags = options.allowedTags || [];
    this.allowedAttributes = options.allowedAttributes || [];
  }

  /**
   * Sanitize entire request object
   */
  sanitizeRequest(req) {
    if (!this.enabled) return req;

    const sanitized = { ...req };

    // Sanitize query parameters
    if (sanitized.query) {
      sanitized.query = this.sanitizeObject(sanitized.query);
    }

    // Sanitize body
    if (sanitized.body) {
      sanitized.body = this.sanitizeObject(sanitized.body);
    }

    // Sanitize headers (selectively)
    if (sanitized.headers) {
      sanitized.headers = this.sanitizeHeaders(sanitized.headers);
    }

    // Sanitize URL
    if (sanitized.url) {
      sanitized.url = this.sanitizeString(sanitized.url);
    }

    return sanitized;
  }

  /**
   * Sanitize an object recursively
   */
  sanitizeObject(obj) {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }

    if (typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        // Sanitize key as well
        const sanitizedKey = this.sanitizeString(key);
        sanitized[sanitizedKey] = this.sanitizeObject(value);
      }
      return sanitized;
    }

    // Return primitive types as-is
    return obj;
  }

  /**
   * Sanitize a string
   */
  sanitizeString(str) {
    if (typeof str !== 'string') {
      return str;
    }

    let sanitized = str;

    // Remove null bytes
    if (this.removeNullBytes) {
      sanitized = sanitized.replace(/\x00/g, '');
    }

    // Trim whitespace
    if (this.trimWhitespace) {
      sanitized = sanitized.trim();
    }

    // Limit length
    if (sanitized.length > this.maxLength) {
      sanitized = sanitized.substring(0, this.maxLength);
    }

    // Strip or encode HTML
    if (this.stripHtml) {
      sanitized = this.stripHtmlTags(sanitized);
    } else if (this.encodeHtml) {
      sanitized = this.encodeHtmlEntities(sanitized);
    }

    return sanitized;
  }

  /**
   * Strip HTML tags
   */
  stripHtmlTags(str) {
    if (this.allowedTags.length === 0) {
      // Remove all tags
      return str.replace(/<[^>]*>/g, '');
    }

    // Allow specific tags
    const allowedPattern = this.allowedTags.map(tag => 
      `<${tag}[^>]*>|<\\/${tag}>`
    ).join('|');
    
    const pattern = new RegExp(`<(?!${allowedPattern})[^>]*>`, 'gi');
    return str.replace(pattern, '');
  }

  /**
   * Encode HTML entities
   */
  encodeHtmlEntities(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Sanitize headers (selective)
   */
  sanitizeHeaders(headers) {
    const sanitized = {};
    const sanitizeHeadersList = ['referer', 'user-agent', 'x-forwarded-for'];

    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      if (sanitizeHeadersList.includes(lowerKey) && typeof value === 'string') {
        sanitized[key] = this.sanitizeString(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Sanitize specific field
   */
  sanitizeField(value) {
    return this.sanitizeObject(value);
  }

  /**
   * Validate email format
   */
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Sanitize email
   */
  sanitizeEmail(email) {
    if (typeof email !== 'string') return email;
    
    const sanitized = this.sanitizeString(email).toLowerCase().trim();
    
    if (!this.validateEmail(sanitized)) {
      return null;
    }
    
    return sanitized;
  }

  /**
   * Validate and sanitize URL
   */
  sanitizeUrl(url) {
    if (typeof url !== 'string') return null;

    try {
      const sanitized = this.sanitizeString(url).trim();
      const parsed = new URL(sanitized);
      
      // Only allow http and https
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return null;
      }

      return parsed.toString();
    } catch {
      return null;
    }
  }

  /**
   * Create middleware for Express
   */
  middleware() {
    return (req, res, next) => {
      if (!this.enabled) {
        return next();
      }

      // Store original
      req.originalBody = req.body;
      req.originalQuery = req.query;

      // Sanitize
      const sanitized = this.sanitizeRequest(req);
      req.body = sanitized.body;
      req.query = sanitized.query;
      
      // Add helper methods
      req.sanitize = (value) => this.sanitizeField(value);
      req.sanitizeEmail = (email) => this.sanitizeEmail(email);
      req.sanitizeUrl = (url) => this.sanitizeUrl(url);

      next();
    };
  }

  // Configuration methods
  setAllowedTags(tags) {
    this.allowedTags = tags;
  }

  setAllowedAttributes(attrs) {
    this.allowedAttributes = attrs;
  }

  enable() {
    this.enabled = true;
  }

  disable() {
    this.enabled = false;
  }
}

module.exports = { RequestSanitizer };
