/**
 * Session Manager
 * Signed-cookie sessions + role-based access control middleware.
 * HMAC-SHA256 signed, no external dependencies.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_COOKIE_NAME = 'kavach.sid';
const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;

function parseCookies(header) {
  const out = {};
  if (!header || typeof header !== 'string') return out;
  const parts = header.split(';');
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx < 0) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    if (!k) continue;
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

function b64urlEncode(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

function timingSafeStrEqual(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

class SessionManager {
  constructor(options = {}) {
    this.dataDir = options.dataDir || path.join(__dirname, '..', 'data');
    this.cookieName = options.cookieName || DEFAULT_COOKIE_NAME;
    this.ttlMs = options.ttlMs || DEFAULT_TTL_MS;
    this.isProduction = !!options.isProduction;

    let secret = options.secret || process.env.SESSION_SECRET;
    this.secretFile = path.join(this.dataDir, '.session-secret');

    if (!secret) {
      if (fs.existsSync(this.secretFile)) {
        secret = fs.readFileSync(this.secretFile, 'utf8').trim();
      } else {
        secret = crypto.randomBytes(64).toString('hex');
        try {
          if (!fs.existsSync(this.dataDir)) fs.mkdirSync(this.dataDir, { recursive: true });
          fs.writeFileSync(this.secretFile, secret, { mode: 0o600 });
          if (options.logger) {
            options.logger.warn('⚠️  SESSION_SECRET not set in env. Generated and persisted to data/.session-secret. For production, set SESSION_SECRET env var.');
          }
        } catch (err) {
          if (options.logger) options.logger.error('Failed to persist session secret:', err.message);
        }
      }
    }

    if (!secret || secret.length < 32) {
      throw new Error('Session secret must be at least 32 chars');
    }
    this.secret = secret;
  }

  sign(payload) {
    const body = b64urlEncode(JSON.stringify(payload));
    const sig = b64urlEncode(
      crypto.createHmac('sha256', this.secret).update(body).digest()
    );
    return `${body}.${sig}`;
  }

  verify(token) {
    if (!token || typeof token !== 'string') return null;
    const dot = token.lastIndexOf('.');
    if (dot < 0) return null;
    const body = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    let expected;
    try {
      expected = b64urlEncode(
        crypto.createHmac('sha256', this.secret).update(body).digest()
      );
    } catch {
      return null;
    }
    if (!timingSafeStrEqual(sig, expected)) return null;
    let payload;
    try {
      payload = JSON.parse(b64urlDecode(body).toString('utf8'));
    } catch {
      return null;
    }
    if (!payload || typeof payload !== 'object') return null;
    if (payload.expiresAt && Date.now() > payload.expiresAt) return null;
    return payload;
  }

  createToken(user) {
    const now = Date.now();
    return this.sign({
      userId: user.id,
      username: user.username,
      role: user.role,
      passwordVersion: user.passwordVersion || 1,
      createdAt: now,
      expiresAt: now + this.ttlMs
    });
  }

  setCookie(res, token) {
    const cookie = [
      `${this.cookieName}=${encodeURIComponent(token)}`,
      'Path=/',
      `Max-Age=${Math.floor(this.ttlMs / 1000)}`,
      'HttpOnly',
      'SameSite=Strict'
    ];
    if (this.isProduction) cookie.push('Secure');
    res.setHeader('Set-Cookie', cookie.join('; '));
  }

  clearCookie(res) {
    const cookie = [
      `${this.cookieName}=`,
      'Path=/',
      'Max-Age=0',
      'HttpOnly',
      'SameSite=Strict'
    ];
    if (this.isProduction) cookie.push('Secure');
    res.setHeader('Set-Cookie', cookie.join('; '));
  }

  /** Returns an Express middleware that attaches req.user. Does NOT 401. */
  middleware() {
    return (req, res, next) => {
      // Ensure req.cookies is populated. Prefer existing (e.g. cookie-parser upstream).
      if (!req.cookies || typeof req.cookies !== 'object') {
        req.cookies = parseCookies(req.headers.cookie);
      }
      const token = req.cookies[this.cookieName];
      if (!token) return next();

      const payload = this.verify(token);
      if (!payload) return next();

      const userManager = req.app?.locals?.userManager;
      if (!userManager) {
        // Without UserManager we cannot verify passwordVersion — fail closed.
        return next();
      }
      const user = userManager.users.get(payload.userId);
      if (!user) return next();
      if ((user.passwordVersion || 1) !== payload.passwordVersion) return next();

      req.user = { id: user.id, username: user.username, role: user.role };
      req.sessionPayload = payload;

      // Sliding renewal: if < 25% of TTL remains, re-issue cookie.
      const remaining = payload.expiresAt - Date.now();
      if (remaining < this.ttlMs * 0.25) {
        const newToken = this.createToken(user);
        this.setCookie(res, newToken);
      }
      next();
    };
  }

  requireAuth(...allowedRoles) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      if (allowedRoles.length && !allowedRoles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      next();
    };
  }
}

module.exports = { SessionManager, parseCookies };
