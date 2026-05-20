/**
 * WAF Test Suite
 */

const { WAFEngine } = require('../src/waf-engine');

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
  
  // Trigger some blocks
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

// Summary
setTimeout(() => {
  console.log('\n' + '='.repeat(50));
  console.log(`Tests: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(50));

  if (failed > 0) {
    process.exit(1);
  }
}, 100);
