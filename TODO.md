# 🛡️ Kavach WAF — Development Roadmap

## 📅 Completed Features

- ✅ 8 core security rules (SQL Injection, XSS, Path Traversal, etc.)
- ✅ Bot detection and geo-blocking
- ✅ Real-time dashboard with Chart.js
- ✅ Webhook notifications (Slack, Discord, custom)
- ✅ Import/export configuration
- ✅ 17 passing tests
- ✅ Indian mythology-inspired design (Kavach branding)
- ✅ GitHub social preview and publication
- ✅ Async Worker Queue with Bull (Redis-backed, graceful fallback)
- ✅ Memory Manager with auto-cleanup and heap monitoring

---

## 🚧 In Progress

*(Nothing currently in progress)*

---

## 📋 Pending Features

### 🔴 Priority 1: Critical Infrastructure

- [ ] **Redis Integration** — Distributed caching for rate limiting, session storage, and IP reputation
  - File: `src/cache/redis-client.js`
  - Replace in-memory Map with Redis for multi-instance support
  - Dependencies: `ioredis` (already installed for worker queue)

- [ ] **Distributed Rate Limiting** — Share rate limit state across multiple WAF instances
  - Current: In-memory only, lost on restart
  - Target: Redis-backed with sliding window algorithm

### 🔴 Priority 2: Security Enhancements

- [ ] **JWT Validator** — Token validation with JWKS, audience/issuer checks, expiry enforcement
  - File: `src/jwt-validator.js`
  - Features: RSA/HS256 support, JWKS endpoint, suspicious claim detection
  - Dependencies: `jsonwebtoken`, `jwks-rsa`
  - API: `GET /api/jwt/validate`, middleware for automatic validation

- [ ] **IP Reputation Service** — Multi-source threat intelligence lookup
  - File: `src/ip-reputation.js`
  - Providers: AbuseIPDB, VirusTotal, custom blacklists
  - Risk levels: safe, low, medium, high, critical
  - Cache results for 1 hour

- [ ] **Advanced DDoS Protection** — Behavioral fingerprinting, JavaScript challenges, tarpit
  - File: `src/ddos-protection.js`
  - Features: Burst detection, slow loris protection, connection rate limiting
  - Challenge types: JavaScript, CAPTCHA integration

- [ ] **CSRF Protection** — CSRF token generation and validation
  - File: `src/csrf-protection.js`
  - Features: Token-based protection, double-submit cookie pattern
  - Status: File exists but needs testing and UI integration

### 🟡 Priority 3: Observability & Monitoring

- [ ] **Prometheus Metrics** — Export WAF metrics for Grafana dashboards
  - File: `src/metrics/prometheus.js`
  - Metrics: request rates, threat detections, cache hit ratio
  - API: `GET /metrics` endpoint
  - Dependencies: `prom-client`

- [ ] **OpenTelemetry Tracing** — Distributed tracing with Jaeger/Zipkin
  - File: `src/tracing/opentelemetry.js`
  - Instrument: HTTP, Express, Redis calls
  - Dependencies: `@opentelemetry/sdk-node`, `@opentelemetry/exporter-jaeger`

- [ ] **Health Checks** — Kubernetes liveness/readiness probes
  - File: `src/health/health-check.js`
  - Endpoints: `/health/live`, `/health/ready`
  - Checks: Redis, disk space

- [ ] **WebSocket Real-time Updates** — Live dashboard without polling
  - Technology: Socket.io or native WebSocket
  - Push: threat alerts, stats updates, log streams
  - Current: 10-second polling (works but not real-time)

### 🟢 Priority 5: Developer Experience

- [ ] **Dark Mode** — Theme switching in management dashboard
  - CSS variables for theme colors
  - LocalStorage for preference persistence
  - Toggle in header/settings

- [ ] **CLI Tool** — Command-line management interface
  - Commands: `kavach start`, `kavach rules`, `kavach block-ip`
  - Dependencies: `commander`
  - Package: `bin` entry in package.json

- [ ] **Docker Support** — Multi-container deployment
  - Files: `Dockerfile`, `docker-compose.yml`
  - Services: WAF app, Redis, Prometheus, Grafana
  - Health checks configured

- [ ] **Kubernetes Helm Chart** — Production K8s deployment
  - Horizontal Pod Autoscaling
  - ConfigMap for rules
  - Persistent volume for logs

- [ ] **npm Package** — Publish `kavach-waf` to npm registry
  - Status: Package ready, need `npm login`
  - namespace: `kavach-waf`

- [ ] **GitHub Actions CI/CD** — Automated testing and release
  - Workflows: test on PR, publish on tag
  - Matrix: Node.js 18, 20, 22
  - Lint: ESLint, Prettier

### 🟢 Priority 6: Integrations

- [ ] **SIEM Integration** — Send logs to security platforms
  - Targets: Splunk, ELK Stack, Datadog, Sumo Logic
  - Format: CEF, LEEF, or JSON

- [ ] **Cloud WAF Integration** — Sync with cloud providers
  - AWS WAF: IP set synchronization
  - Cloudflare: Firewall rule management
  - Azure Front Door: Custom rules

- [ ] **Notification Channels** — More alert destinations
  - Current: Slack, Discord webhooks
  - Add: Microsoft Teams, PagerDuty, Opsgenie, Email (SMTP)

- [ ] **GraphQL API** — Alternative to REST API
  - Apollo Server integration
  - Real-time subscriptions for threat alerts
  - Better querying for complex dashboard data

---

## 🐛 Known Issues

- [ ] Worker Queue spams ioredis errors when Redis is unavailable (needs ioredis connection handler cleanup)
- [ ] CSRF protection module exists but untested
- [ ] No integration tests — only unit tests for engine
- [ ] Dashboard memory bar appears even on bots/geo pages (should be dashboard-only)
- [ ] Import/export doesn't preserve RegExp patterns correctly (stringifying issue)

---

## 📝 Notes

- Worker Queue gracefully degrades to sync mode when Redis is down — this is intentional
- Memory Manager requires `--expose-gc` flag for forced garbage collection
- All 17 unit tests pass before any new feature work
- Dashboard uses 10-second polling — WebSocket would reduce server load

---

*Last updated: May 2026*
*Maintained by: Abhirup Guha (Fir3St0rm) @ Info Security Solution*
