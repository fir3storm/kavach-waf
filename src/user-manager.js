/**
 * User Manager
 * Owns the user store, password hashing, role assignment, audit trail, and lockout.
 * Backed by data/users.json and data/audit-log.json.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROLES = ['admin', 'operator', 'viewer'];
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };
const KEY_LEN = 64;
const USERNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;
const MAX_AUDIT_ENTRIES = 10000;

function generateId() {
  return Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
}

function generateRandomPassword(len = 16) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.randomBytes(len);
  let pw = '';
  for (let i = 0; i < len; i++) pw += charset[bytes[i] % charset.length];
  // Ensure policy
  if (!/[a-zA-Z]/.test(pw) || !/[0-9]/.test(pw)) return generateRandomPassword(len);
  return pw;
}

function isValidPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw);
}

function isValidUsername(name) {
  return typeof name === 'string' && USERNAME_RE.test(name);
}

class UserManager {
  constructor(options = {}) {
    this.dataDir = options.dataDir || path.join(__dirname, '..', 'data');
    this.logger = options.logger || console;
    this.sessionTtlMs = options.sessionTtlMs || 8 * 60 * 60 * 1000;
    this.lockoutThreshold = options.lockoutThreshold ?? 5;
    this.lockoutWindowMs = options.lockoutWindowMs ?? 15 * 60 * 1000;
    this.lockoutDurationMs = options.lockoutDurationMs ?? 15 * 60 * 1000;

    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }

    this.usersFile = path.join(this.dataDir, 'users.json');
    this.auditFile = path.join(this.dataDir, 'audit-log.json');

    /** @type {Map<string, object>} id -> user */
    this.users = new Map();
    /** @type {string[]} order of ids as inserted */
    this.userOrder = [];
    /** @type {object[]} */
    this.audit = [];
    /** @type {Map<string, { count: number, firstAttemptAt: number, lockedUntil: number }>} */
    this.loginAttempts = new Map();

    this.loadUsers();
    this.loadAudit();
  }

  // ---------- Persistence ----------

  loadUsers() {
    try {
      if (fs.existsSync(this.usersFile)) {
        const raw = fs.readFileSync(this.usersFile, 'utf8');
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          for (const u of arr) {
            this.users.set(u.id, u);
            this.userOrder.push(u.id);
          }
        }
      }
    } catch (err) {
      this.logger.error('[user-manager] Error loading users:', err.message);
    }
  }

  saveUsers() {
    try {
      const arr = this.userOrder
        .map((id) => this.users.get(id))
        .filter(Boolean);
      fs.writeFileSync(this.usersFile, JSON.stringify(arr, null, 2));
    } catch (err) {
      this.logger.error('[user-manager] Error saving users:', err.message);
    }
  }

  loadAudit() {
    try {
      if (fs.existsSync(this.auditFile)) {
        const raw = fs.readFileSync(this.auditFile, 'utf8');
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) this.audit = arr.slice(-MAX_AUDIT_ENTRIES);
      }
    } catch (err) {
      this.logger.error('[user-manager] Error loading audit:', err.message);
    }
  }

  saveAudit() {
    try {
      const trimmed = this.audit.slice(-MAX_AUDIT_ENTRIES);
      fs.writeFileSync(this.auditFile, JSON.stringify(trimmed, null, 2));
    } catch (err) {
      this.logger.error('[user-manager] Error saving audit:', err.message);
    }
  }

  // ---------- Password hashing ----------

  hashPassword(password) {
    const salt = crypto.randomBytes(32);
    const hash = crypto.scryptSync(password, salt, KEY_LEN, SCRYPT_PARAMS);
    return {
      salt: salt.toString('hex'),
      hash: hash.toString('hex'),
      params: { ...SCRYPT_PARAMS }
    };
  }

  verifyPassword(password, stored) {
    if (!stored || !stored.salt || !stored.hash) return false;
    try {
      const salt = Buffer.from(stored.salt, 'hex');
      const params = { ...SCRYPT_PARAMS, ...(stored.params || {}) };
      const expected = Buffer.from(stored.hash, 'hex');
      const actual = crypto.scryptSync(password, salt, expected.length, params);
      if (expected.length !== actual.length) return false;
      return crypto.timingSafeEqual(expected, actual);
    } catch {
      return false;
    }
  }

  // ---------- Safe serializer ----------

  toSafeUser(user) {
    if (!user) return null;
    const { password, ...safe } = user;
    return safe;
  }

  // ---------- CRUD ----------

  createUser({ username, password, role, displayName }) {
    if (!isValidUsername(username)) {
      throw new Error('Username must be 3-32 chars, [a-zA-Z0-9_-]');
    }
    if (!ROLES.includes(role)) {
      throw new Error(`Role must be one of: ${ROLES.join(', ')}`);
    }
    if (!isValidPassword(password)) {
      throw new Error('Password must be at least 8 chars and contain a letter and a number');
    }
    const lower = username.toLowerCase();
    for (const u of this.users.values()) {
      if (u.username.toLowerCase() === lower) {
        throw new Error('Username already exists');
      }
    }
    const id = generateId();
    const now = new Date().toISOString();
    const user = {
      id,
      username,
      displayName: displayName || username,
      role,
      password: this.hashPassword(password),
      passwordVersion: 1,
      createdAt: now,
      updatedAt: now,
      lastLoginAt: null
    };
    this.users.set(id, user);
    this.userOrder.push(id);
    this.saveUsers();
    return this.toSafeUser(user);
  }

  updateUser(id, updates) {
    const user = this.users.get(id);
    if (!user) return null;
    if (updates.displayName !== undefined) {
      if (typeof updates.displayName !== 'string' || updates.displayName.length === 0) {
        throw new Error('displayName must be a non-empty string');
      }
      user.displayName = updates.displayName;
    }
    if (updates.role !== undefined) {
      if (!ROLES.includes(updates.role)) {
        throw new Error(`Role must be one of: ${ROLES.join(', ')}`);
      }
      // Prevent removing the last admin
      if (user.role === 'admin' && updates.role !== 'admin') {
        const adminCount = this.countByRole('admin');
        if (adminCount <= 1) {
          throw new Error('Cannot demote the last admin');
        }
      }
      user.role = updates.role;
    }
    if (updates.username !== undefined) {
      if (!isValidUsername(updates.username)) {
        throw new Error('Username must be 3-32 chars, [a-zA-Z0-9_-]');
      }
      const lower = updates.username.toLowerCase();
      for (const other of this.users.values()) {
        if (other.id !== id && other.username.toLowerCase() === lower) {
          throw new Error('Username already exists');
        }
      }
      user.username = updates.username;
    }
    user.updatedAt = new Date().toISOString();
    this.users.set(id, user);
    this.saveUsers();
    return this.toSafeUser(user);
  }

  deleteUser(id) {
    const user = this.users.get(id);
    if (!user) return false;
    if (user.role === 'admin') {
      const adminCount = this.countByRole('admin');
      if (adminCount <= 1) {
        throw new Error('Cannot delete the last admin');
      }
    }
    this.users.delete(id);
    this.userOrder = this.userOrder.filter((x) => x !== id);
    this.saveUsers();
    return true;
  }

  changePassword(id, newPassword) {
    const user = this.users.get(id);
    if (!user) return false;
    if (!isValidPassword(newPassword)) {
      throw new Error('Password must be at least 8 chars and contain a letter and a number');
    }
    user.password = this.hashPassword(newPassword);
    user.passwordVersion = (user.passwordVersion || 1) + 1;
    user.updatedAt = new Date().toISOString();
    this.users.set(id, user);
    this.saveUsers();
    return true;
  }

  resetPassword(id) {
    const user = this.users.get(id);
    if (!user) return null;
    const newPw = generateRandomPassword();
    this.changePassword(id, newPw);
    return newPw;
  }

  getUser(id) {
    return this.toSafeUser(this.users.get(id));
  }

  getUserByUsername(username) {
    if (!username) return null;
    const lower = username.toLowerCase();
    for (const u of this.users.values()) {
      if (u.username.toLowerCase() === lower) return this.toSafeUser(u);
    }
    return null;
  }

  /** Internal: returns full user record (with password) — verifyLogin only. */
  getUserRecordByUsername(username) {
    if (!username) return null;
    const lower = username.toLowerCase();
    for (const u of this.users.values()) {
      if (u.username.toLowerCase() === lower) return u;
    }
    return null;
  }

  listUsers() {
    return this.userOrder
      .map((id) => this.users.get(id))
      .filter(Boolean)
      .map((u) => this.toSafeUser(u));
  }

  countByRole(role) {
    let n = 0;
    for (const u of this.users.values()) if (u.role === role) n++;
    return n;
  }

  // ---------- Login / lockout ----------

  verifyLogin(username, password) {
    if (!username || !password) {
      return { success: false, reason: 'invalid_credentials' };
    }
    const lower = username.toLowerCase();
    const attempts = this.loginAttempts.get(lower);

    if (attempts && attempts.lockedUntil && attempts.lockedUntil > Date.now()) {
      return { success: false, reason: 'locked_out', lockedUntil: attempts.lockedUntil };
    }

    const user = this.getUserRecordByUsername(username);
    if (!user) {
      this.recordFailedAttempt(lower);
      return { success: false, reason: 'user_not_found' };
    }

    const ok = this.verifyPassword(password, user.password);
    if (!ok) {
      this.recordFailedAttempt(lower);
      return { success: false, reason: 'invalid_credentials' };
    }

    // Success
    this.loginAttempts.delete(lower);
    user.lastLoginAt = new Date().toISOString();
    this.users.set(user.id, user);
    this.saveUsers();
    return { success: true, user: this.toSafeUser(user) };
  }

  recordFailedAttempt(lowerUsername) {
    const now = Date.now();
    const a = this.loginAttempts.get(lowerUsername);
    if (!a || (now - a.firstAttemptAt) > this.lockoutWindowMs) {
      this.loginAttempts.set(lowerUsername, {
        count: 1,
        firstAttemptAt: now,
        lockedUntil: 0
      });
    } else {
      a.count += 1;
      if (a.count >= this.lockoutThreshold) {
        a.lockedUntil = now + this.lockoutDurationMs;
      }
    }
  }

  // ---------- Audit ----------

  logAudit({ user, action, ip, success, details }) {
    const entry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      user: user || null,
      action,
      ip: ip || null,
      success: success !== false,
      details: details || null
    };
    this.audit.push(entry);
    if (this.audit.length % 5 === 0) this.saveAudit();
    return entry;
  }

  readAudit({ user, action, limit } = {}) {
    let entries = this.audit;
    if (user) {
      const u = user.toLowerCase();
      entries = entries.filter((e) => (e.user || '').toLowerCase() === u);
    }
    if (action) {
      entries = entries.filter((e) => e.action === action);
    }
    const sorted = entries.slice().reverse();
    if (limit) return sorted.slice(0, limit);
    return sorted;
  }

  // ---------- Bootstrap ----------

  bootstrap() {
    if (this.users.size > 0) return { created: false };
    const password = generateRandomPassword(16);
    const safe = this.createUser({
      username: 'admin',
      password,
      role: 'admin',
      displayName: 'Administrator'
    });
    this.logAudit({ user: 'admin', action: 'user_created', success: true, details: { bootstrap: true } });
    this.saveAudit();
    return { created: true, username: safe.username, password };
  }
}

module.exports = { UserManager, ROLES };
