/**
 * CSRF Protection Module
 * Validates CSRF tokens for state-changing requests
 */

const crypto = require('crypto');

class CSRFProtection {
  constructor(options = {}) {
    this.secret = options.secret || crypto.randomBytes(32).toString('hex');
    this.cookieName = options.cookieName || '_csrf';
    this.headerName = options.headerName || 'x-csrf-token';
    this.fieldName = options.fieldName || '_csrf';
    this.secure = options.secure || false;
    this.sameSite = options.sameSite || 'strict';
    this.maxAge = options.maxAge || 3600000; // 1 hour
    this.excludedPaths = new Set(options.excludedPaths || ['/api/webhook', '/api/callback']);
    this.excludedMethods = new Set(options.excludedMethods || ['GET', 'HEAD', 'OPTIONS']);
  }

  /**
   * Generate CSRF token
   */
  generateToken(sessionId = null) {
    const timestamp = Date.now().toString();
    const random = crypto.randomBytes(16).toString('hex');
    const data = sessionId ? `${sessionId}:${timestamp}:${random}` : `${timestamp}:${random}`;
    
    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(data)
      .digest('hex');
    
    return `${data}:${signature}`;
  }

  /**
   * Verify CSRF token
   */
  verifyToken(token, sessionId = null) {
    if (!token) return false;

    try {
      const parts = token.split(':');
      if (parts.length < 3) return false;

      const signature = parts.pop();
      const data = parts.join(':');

      // Verify signature
      const expected = crypto
        .createHmac('sha256', this.secret)
        .update(data)
        .digest('hex');

      if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
        return false;
      }

      // Check timestamp
      const timestamp = parseInt(parts[0]);
      if (Date.now() - timestamp > this.maxAge) {
        return false;
      }

      // Verify session if provided
      if (sessionId && parts[1] !== sessionId) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Express middleware for CSRF protection
   */
  middleware() {
    return (req, res, next) => {
      // Skip excluded methods
      if (this.excludedMethods.has(req.method)) {
        return next();
      }

      // Skip excluded paths
      if (this.excludedPaths.has(req.path)) {
        return next();
      }

      // Get session ID (can be customized based on your session implementation)
      const sessionId = req.session?.id || req.cookies?.session || null;

      // Generate and set token cookie if not present
      let token = req.cookies?.[this.cookieName];
      if (!token || !this.verifyToken(token, sessionId)) {
        token = this.generateToken(sessionId);
        res.cookie(this.cookieName, token, {
          httpOnly: true,
          secure: this.secure,
          sameSite: this.sameSite,
          maxAge: this.maxAge
        });
      }

      // Attach token to request for use in forms
      req.csrfToken = () => token;

      // Validate token for state-changing requests
      if (this.requiresValidation(req)) {
        const submittedToken = 
          req.headers[this.headerName.toLowerCase()] ||
          req.body?.[this.fieldName] ||
          req.query?.[this.fieldName];

        if (!submittedToken) {
          return res.status(403).json({
            error: 'CSRF token missing',
            message: 'CSRF token is required for this request'
          });
        }

        if (!this.verifyToken(submittedToken, sessionId)) {
          return res.status(403).json({
            error: 'CSRF token invalid',
            message: 'CSRF token is invalid or expired'
          });
        }
      }

      next();
    };
  }

  /**
   * Check if request requires CSRF validation
   */
  requiresValidation(req) {
    // Validate POST, PUT, DELETE, PATCH requests
    const methodsRequiringValidation = ['POST', 'PUT', 'DELETE', 'PATCH'];
    return methodsRequiringValidation.includes(req.method);
  }

  /**
   * Generate HTML form field
   */
  formField(token) {
    return `<input type="hidden" name="${this.fieldName}" value="${token}">`;
  }

  /**
   * Generate meta tag for AJAX requests
   */
  metaTag(token) {
    return `<meta name="csrf-token" content="${token}">`;
  }

  // Management methods
  excludePath(path) {
    this.excludedPaths.add(path);
  }

  includePath(path) {
    this.excludedPaths.delete(path);
  }

  getExcludedPaths() {
    return Array.from(this.excludedPaths);
  }
}

module.exports = { CSRFProtection };
