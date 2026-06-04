/**
 * WAF Test Suite
 */

const { WAFEngine } = require('../src/waf-engine');
const { RedisClient } = require('../src/cache/redis-client');
const { IPReputationService } = require('../src/ip-reputation');
const { JWTValidator } = require('../src/jwt-validator');
const { CSRFProtection } = require('../src/csrf-protection');

console.log('🧪 Running WAF Tests\n');

const engine = new WAFEngine({ enableWebhooks: false });
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (err) {
    console.log(`❌ ${name}: ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

// SQL Injection Tests
test('Detects basic SQL injection', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/search?q=' OR '1'='1",
    path: "/api/search",
    query: { q: "' OR '1'='1" },
    method: 'GET',
    headers: {}
  });
  assert(!result.allowed, 'Should block SQL injection');
  assert(result.violations.some(v => v.type === 'sql_injection'), 'Should detect SQL injection');
});

test('Detects UNION-based SQL injection', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/users?q=1 UNION SELECT * FROM users",
    path: "/api/users",
    query: { q: "1 UNION SELECT * FROM users" },
    method: 'GET',
    headers: {}
  });
  assert(!result.allowed, 'Should block UNION SQL injection');
});

// XSS Tests
test('Detects script tag XSS', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/comment",
    path: "/api/comment",
    method: 'POST',
    body: { comment: "<script>alert('xss')</script>" },
    headers: {}
  });
  assert(!result.allowed, 'Should block XSS');
  assert(result.violations.some(v => v.type === 'xss'), 'Should detect XSS');
});

test('Detects javascript: protocol XSS', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/redirect?url=javascript:alert(1)",
    path: "/api/redirect",
    query: { url: "javascript:alert(1)" },
    method: 'GET',
    headers: {}
  });
  assert(!result.allowed, 'Should block javascript: XSS');
});

// Path Traversal Tests
test('Detects path traversal', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/file?file=../../../etc/passwd",
    path: "/api/file",
    query: { file: "../../../etc/passwd" },
    method: 'GET',
    headers: {}
  });
  assert(!result.allowed, 'Should block path traversal');
  assert(result.violations.some(v => v.type === 'path_traversal'), 'Should detect path traversal');
});

// Command Injection Tests
test('Detects command injection', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/ping?host=127.0.0.1;cat /etc/passwd",
    path: "/api/ping",
    query: { host: "127.0.0.1;cat /etc/passwd" },
    method: 'GET',
    headers: {}
  });
  assert(!result.allowed, 'Should block command injection');
  assert(result.violations.some(v => v.type === 'command_injection'), 'Should detect command injection');
});

// LFI Tests
test('Detects file protocol LFI', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/file?file=file:///etc/passwd",
    path: "/api/file",
    query: { file: "file:///etc/passwd" },
    method: 'GET',
    headers: {}
  });
  assert(!result.allowed, 'Should block LFI');
  assert(result.violations.some(v => v.type === 'lfi'), 'Should detect LFI');
});

// NoSQL Injection Tests
test('Detects NoSQL injection', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/users",
    path: "/api/users",
    method: 'POST',
    body: { username: { $ne: null }, password: { $ne: null } },
    headers: {}
  });
  assert(!result.allowed, 'Should block NoSQL injection');
  assert(result.violations.some(v => v.type === 'nosql_injection'), 'Should detect NoSQL injection');
});

// XXE Tests
test('Detects XXE', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/xml",
    path: "/api/xml",
    method: 'POST',
    body: { xml: '<!ENTITY xxe SYSTEM "file:///etc/passwd">' },
    headers: {}
  });
  assert(!result.allowed, 'Should block XXE');
  assert(result.violations.some(v => v.type === 'xxe'), 'Should detect XXE');
});

// SSTI Tests
test('Detects SSTI', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/template?name={{7*7}}",
    path: "/api/template",
    query: { name: "{{7*7}}" },
    method: 'GET',
    headers: {}
  });
  assert(!result.allowed, 'Should block SSTI');
  assert(result.violations.some(v => v.type === 'ssti'), 'Should detect SSTI');
});

// Legitimate Requests
test('Allows legitimate requests', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/users",
    path: "/api/users",
    method: 'GET',
    headers: { 'user-agent': 'Mozilla/5.0 Test Browser' }
  });
  assert(result.allowed, 'Should allow legitimate requests');
});

test('Allows normal search', async () => {
  const result = await engine.analyzeRequest({
    url: "/api/search?q=hello world",
    path: "/api/search",
    query: { q: "hello world" },
    method: 'GET',
    headers: { 'user-agent': 'Mozilla/5.0 Test Browser' }
  });
  assert(result.allowed, 'Should allow normal search');
});

// IP Management Tests
test('Blocks blacklisted IPs', async () => {
  engine.blockIP('192.168.1.100');
  const result = await engine.analyzeRequest({
    url: "/",
    path: "/",
    method: 'GET',
    headers: { 'x-forwarded-for': '192.168.1.100' }
  });
  assert(!result.allowed, 'Should block blacklisted IP');
  engine.unblockIP('192.168.1.100');
});

test('Allows whitelisted IPs', async () => {
  engine.whitelistIP('192.168.1.1');
  const result = await engine.analyzeRequest({
    url: "/api/search?q=' OR '1'='1",
    path: "/api/search",
    query: { q: "' OR '1'='1" },
    method: 'GET',
    headers: { 'x-forwarded-for': '192.168.1.1' }
  });
  assert(result.allowed, 'Should allow whitelisted IP even with attack');
  assert(result.violations.length === 0, 'Should not check violations for whitelisted');
  engine.unwhitelistIP('192.168.1.1');
});

// Rule Management Tests
test('Can add custom rule', () => {
  const rule = engine.addRule({
    name: 'Test Rule',
    type: 'custom',
    pattern: /testattack/i,
    severity: 'medium',
    action: 'block'
  });
  assert(rule.id, 'Should assign ID to rule');
  assert(engine.getRule(rule.id), 'Should retrieve rule by ID');
  engine.deleteRule(rule.id);
});

test('Can update rule', () => {
  const rule = engine.addRule({
    name: 'Test Rule',
    type: 'custom',
    pattern: /test/i,
    severity: 'low',
    action: 'block'
  });
  const updated = engine.updateRule(rule.id, { severity: 'high' });
  assert(updated.severity === 'high', 'Should update severity');
  engine.deleteRule(rule.id);
});

// Statistics Tests
test('Tracks statistics', async () => {
  const initialStats = engine.getStats();
  
  await engine.analyzeRequest({
    url: "/test?q=<script>",
    path: "/test",
    query: { q: "<script>" },
    method: 'GET',
    headers: {}
  });
  
  const stats = engine.getStats();
  assert(stats.totalRequests > initialStats.totalRequests, 'Should track total requests');
  assert(stats.blockedRequests > initialStats.blockedRequests, 'Should track blocked requests');
  assert(stats.threatsDetected > initialStats.threatsDetected, 'Should track threats');
});

// NEW FEATURE TESTS

// Redis rate limiting fallback
test('Rate limiting works without Redis', async () => {
  const e = new WAFEngine({ enableWebhooks: false, enableBotDetection: false });
  let blocked = false;
  for (let i = 0; i < 105; i++) {
    const result = await e.analyzeRequest({
      url: "/api/test",
      path: "/api/test",
      method: 'GET',
      headers: { 'x-forwarded-for': '10.0.0.1', 'user-agent': 'Mozilla/5.0 Test' }
    });
    if (!result.allowed) {
      blocked = true;
      assert(result.violations.some(v => v.type === 'rate_limit' || v.type === 'endpoint_rate_limit'), 'Should detect rate limit');
      break;
    }
  }
  assert(blocked, 'Should block after exceeding rate limit');
});

// IP Reputation blocking
test('IP reputation blocks critical risk IPs', async () => {
  const rep = new IPReputationService();
  rep.addToBlacklist('10.20.30.40');
  const e = new WAFEngine({ enableWebhooks: false, ipReputation: rep, enableIPReputation: true });
  const result = await e.analyzeRequest({
    url: "/api/users",
    path: "/api/users",
    method: 'GET',
    headers: { 'x-forwarded-for': '10.20.30.40' }
  });
  assert(!result.allowed, 'Should block IP with critical reputation');
  assert(result.violations.some(v => v.type === 'ip_reputation'), 'Should detect IP reputation violation');
});

// CSRF Protection
test('CSRF protection generates and verifies tokens', () => {
  const csrf = new CSRFProtection({ secret: 'test-secret' });
  const token = csrf.generateToken('session-1');
  assert(token, 'Should generate token');
  assert(csrf.verifyToken(token, 'session-1'), 'Should verify valid token');
  assert(!csrf.verifyToken(token, 'session-2'), 'Should reject wrong session');
  assert(!csrf.verifyToken('invalid-token'), 'Should reject invalid token');
});

// JWT Validator
test('JWT validator decodes tokens', () => {
  const jwt = new JWTValidator({ secret: 'test-secret' });
  const token = jwt.generate({ sub: 'user-1', role: 'admin' });
  assert(token, 'Should generate token');
  const decoded = jwt.decode(token);
  assert(decoded && decoded.payload.sub === 'user-1', 'Should decode token');
});

// Import/Export regex round-trip
test('Import/export preserves regex patterns', () => {
  const e = new WAFEngine({ enableWebhooks: false });
  const exported = e.exportConfig();
  const rule = exported.rules.find(r => r.id === 'sql-injection-1');
  assert(rule && typeof rule.pattern === 'string', 'Should export pattern as string');
  assert(rule.flags === 'i', 'Should export flags');
  
  const e2 = new WAFEngine({ enableWebhooks: false });
  e2.importConfig(exported);
  const importedRule = e2.getRule('sql-injection-1');
  assert(importedRule.pattern instanceof RegExp, 'Should import pattern as RegExp');
  assert(importedRule.pattern.test("1 UNION SELECT * FROM users"), 'Imported regex should still match');
});

// Prometheus metrics callback (no crash)
test('Metrics callback does not crash engine', async () => {
  let called = false;
  const e = new WAFEngine({
    enableWebhooks: false,
    metricsCallback: () => { called = true; }
  });
  await e.analyzeRequest({
    url: "/test?q=<script>",
    path: "/test",
    query: { q: "<script>" },
    method: 'GET',
    headers: {}
  });
  assert(called, 'Metrics callback should have been called');
});

// Summary
setTimeout(() => {
  console.log('\n' + '='.repeat(50));
  console.log(`Tests: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(50));

  if (failed > 0) {
    process.exit(1);
  }
}, 100);
