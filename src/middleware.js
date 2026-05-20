/**
 * Express Middleware for WAF
 */

const { WAFEngine } = require('./waf-engine');
const { WAFLogger } = require('./logger');

class WAFMiddleware {
  constructor(options = {}) {
    this.engine = new WAFEngine();
    this.logger = new WAFLogger(options.logger);
    this.options = {
      blockPage: options.blockPage || null,
      logAllRequests: options.logAllRequests || false,
      ...options
    };
  }

  /**
   * Main middleware function
   */
  middleware() {
    return async (req, res, next) => {
      try {
        // Analyze the request
        const result = await this.engine.analyzeRequest(req);
        
        // Log the request
        if (this.options.logAllRequests || !result.allowed) {
          this.logger.logRequest(req, result);
        }

        if (result.allowed) {
          // Add security headers
          this.addSecurityHeaders(res);
          next();
        } else {
          // Block the request
          this.blockRequest(req, res, result);
        }
      } catch (err) {
        console.error('[WAF] Error analyzing request:', err);
        // Allow request on error (fail open) or block (fail closed) based on config
        if (this.options.failClosed) {
          res.status(500).json({ error: 'WAF error', message: 'Security check failed' });
        } else {
          next();
        }
      }
    };
  }

  /**
   * Block a request and send appropriate response
   */
  blockRequest(req, res, result) {
    const statusCode = 403;
    const violations = result.violations || [];
    
    // Log the block
    console.log(`[WAF] Blocked request from ${result.clientIP} - ${violations.map(v => v.reason).join(', ')}`);
    
    // Check if client accepts JSON
    const acceptsJson = req.headers.accept && req.headers.accept.includes('application/json');
    
    if (acceptsJson) {
      res.status(statusCode).json({
        error: 'Access Denied',
        message: 'Request blocked by Web Application Firewall',
        violations: violations.map(v => ({
          type: v.type,
          severity: v.severity,
          reason: v.reason
        })),
        requestId: this.logger.logs[this.logger.logs.length - 1]?.id
      });
    } else {
      // HTML response
      if (this.options.blockPage) {
        res.status(statusCode).sendFile(this.options.blockPage);
      } else {
        res.status(statusCode).send(this.getDefaultBlockPage(violations));
      }
    }
  }

  /**
   * Default HTML block page
   */
  getDefaultBlockPage(violations) {
    const violationList = violations.map(v => 
      `<li><strong>${v.type}</strong>: ${v.reason}</li>`
    ).join('');

    return `<!DOCTYPE html>
<html>
<head>
  <title>Access Denied - Web Application Firewall</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0;
      padding: 20px;
    }
    .container {
      text-align: center;
      max-width: 600px;
    }
    .shield {
      font-size: 80px;
      margin-bottom: 20px;
    }
    h1 {
      font-size: 2.5em;
      margin: 0 0 10px;
      color: #e94560;
    }
    .subtitle {
      color: #888;
      margin-bottom: 30px;
    }
    .violations {
      background: rgba(255,255,255,0.05);
      border-radius: 10px;
      padding: 20px;
      margin: 20px 0;
      text-align: left;
    }
    .violations h3 {
      margin-top: 0;
      color: #e94560;
    }
    .violations ul {
      margin: 0;
      padding-left: 20px;
    }
    .violations li {
      margin: 10px 0;
      color: #ccc;
    }
    .footer {
      margin-top: 30px;
      color: #666;
      font-size: 0.9em;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="shield">🛡️</div>
    <h1>Access Denied</h1>
    <p class="subtitle">Your request has been blocked by the Web Application Firewall</p>
    <div class="violations">
      <h3>Detected Threats:</h3>
      <ul>${violationList}</ul>
    </div>
    <p class="footer">If you believe this is an error, please contact the administrator.</p>
  </div>
</body>
</html>`;
  }

  /**
   * Add security headers to response
   */
  addSecurityHeaders(res) {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Content Security Policy
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    
    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Remove server identification
    res.removeHeader('X-Powered-By');
  }

  // Expose engine and logger methods
  getEngine() {
    return this.engine;
  }

  getLogger() {
    return this.logger;
  }
}

module.exports = { WAFMiddleware };
