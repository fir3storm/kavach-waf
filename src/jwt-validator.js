/**
 * JWT Validator
 * Validates JWT tokens with JWKS, audience/issuer checks, and expiry enforcement
 */

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const crypto = require('crypto');

class JWTValidator {
  constructor(options = {}) {
    this.secret = options.secret || process.env.JWT_SECRET;
    this.issuer = options.issuer || process.env.JWT_ISSUER;
    this.audience = options.audience || process.env.JWT_AUDIENCE;
    this.jwksUri = options.jwksUri || process.env.JWKS_URI;
    this.algorithms = options.algorithms || ['RS256', 'HS256'];
    this.clockTolerance = options.clockTolerance || 60;
    this.maxAge = options.maxAge || '1h';

    this.client = null;
    if (this.jwksUri) {
      this.client = jwksClient({
        jwksUri: this.jwksUri,
        cache: true,
        cacheMaxEntries: 5,
        cacheMaxAge: 86400000,
        rateLimit: true,
        jwksRequestsPerMinute: 10
      });
    }

    this.blockedTokens = new Set();
  }

  async getKey(header, callback) {
    if (!this.client) {
      return callback(new Error('JWKS client not configured'));
    }
    try {
      const key = await this.client.getSigningKey(header.kid);
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    } catch (err) {
      callback(err);
    }
  }

  async validate(token) {
    if (!token) {
      return { valid: false, error: 'Token missing' };
    }

    if (this.blockedTokens.has(token)) {
      return { valid: false, error: 'Token has been revoked' };
    }

    try {
      let decoded;
      let payload;

      // Verify with secret (HS256) or JWKS (RS256)
      if (this.jwksUri) {
        payload = await new Promise((resolve, reject) => {
          jwt.verify(token, this.getKey.bind(this), {
            algorithms: this.algorithms,
            issuer: this.issuer,
            audience: this.audience,
            clockTolerance: this.clockTolerance,
            maxAge: this.maxAge
          }, (err, decoded) => {
            if (err) reject(err);
            else resolve(decoded);
          });
        });
      } else if (this.secret) {
        payload = jwt.verify(token, this.secret, {
          algorithms: this.algorithms.filter(a => a.startsWith('HS')),
          issuer: this.issuer,
          audience: this.audience,
          clockTolerance: this.clockTolerance,
          maxAge: this.maxAge
        });
      } else {
        // Decode only (no verification) - useful for analysis
        decoded = jwt.decode(token, { complete: true });
        if (!decoded) {
          return { valid: false, error: 'Invalid token format' };
        }
        payload = decoded.payload;
      }

      const suspicious = this.detectSuspiciousClaims(payload);

      return {
        valid: true,
        payload,
        suspicious,
        header: decoded ? decoded.header : undefined
      };
    } catch (err) {
      return { valid: false, error: err.message };
    }
  }

  detectSuspiciousClaims(payload) {
    const issues = [];
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp > now + 86400 * 365) {
      issues.push('Token expiry is more than 1 year in the future');
    }
    if (payload.iat && payload.iat > now + 60) {
      issues.push('Token issued in the future');
    }
    if (payload.sub && payload.sub.length > 256) {
      issues.push('Subject claim unusually long');
    }
    if (payload.alg && payload.alg === 'none') {
      issues.push('Algorithm "none" detected');
    }

    return issues;
  }

  revoke(token) {
    this.blockedTokens.add(token);
    // Limit set size
    if (this.blockedTokens.size > 10000) {
      const first = this.blockedTokens.values().next().value;
      this.blockedTokens.delete(first);
    }
  }

  middleware(options = {}) {
    return async (req, res, next) => {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : req.query.token;

      if (!token) {
        if (options.required === false) {
          req.jwtPayload = null;
          return next();
        }
        return res.status(401).json({ error: 'Authorization token required' });
      }

      const result = await this.validate(token);
      if (!result.valid) {
        return res.status(401).json({ error: result.error });
      }

      if (result.suspicious.length > 0 && options.strict) {
        return res.status(403).json({ error: 'Suspicious token claims detected', issues: result.suspicious });
      }

      req.jwtPayload = result.payload;
      req.token = token;
      next();
    };
  }

  // Management API helpers
  decode(token) {
    return jwt.decode(token, { complete: true });
  }

  generate(payload, options = {}) {
    if (!this.secret) {
      throw new Error('JWT secret not configured for token generation');
    }
    const signOptions = {
      expiresIn: options.expiresIn || this.maxAge,
      ...options
    };
    if (this.issuer) signOptions.issuer = this.issuer;
    if (this.audience) signOptions.audience = this.audience;
    return jwt.sign(payload, this.secret, signOptions);
  }
}

module.exports = { JWTValidator };
