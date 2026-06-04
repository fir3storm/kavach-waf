# Kavach WAF Dockerfile
FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application
COPY src/ ./src/
COPY public/ ./public/
COPY bin/ ./bin/
COPY data/ ./data/ || true
COPY docs/ ./docs/
COPY test/ ./test/
COPY README.md LICENSE CONTRIBUTING.md ./

# Create data directory
RUN mkdir -p /app/data

# Expose ports
EXPOSE 3000 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health/live', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

# Start
CMD ["node", "src/index.js"]
