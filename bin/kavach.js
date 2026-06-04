#!/usr/bin/env node
/**
 * Kavach WAF CLI
 * Command-line management interface
 */

const { Command } = require('commander');
const path = require('path');
const fs = require('fs');

const program = new Command();
program.name('kavach').description('Kavach WAF CLI').version('1.0.0');

const DATA_DIR = path.join(__dirname, '..', 'data');

function loadEngine() {
  const { WAFEngine } = require('../src/waf-engine');
  return new WAFEngine();
}

function loadUsers() {
  const { UserManager } = require('../src/user-manager');
  return new UserManager({ dataDir: DATA_DIR, logger: console });
}

program
  .command('start')
  .description('Start the WAF server')
  .option('-p, --port <port>', 'Protected app port', '3000')
  .option('-u, --ui-port <port>', 'Management UI port', '3001')
  .option('-r, --redis <url>', 'Redis connection URL')
  .action((options) => {
    process.env.PORT = options.port;
    process.env.WAF_UI_PORT = options.uiPort;
    if (options.redis) {
      const url = new URL(options.redis);
      process.env.REDIS_HOST = url.hostname;
      process.env.REDIS_PORT = url.port || '6379';
      if (url.password) process.env.REDIS_PASSWORD = url.password;
    }
    require('../src/index.js');
  });

program
  .command('rules')
  .description('List all WAF rules')
  .action(() => {
    const engine = loadEngine();
    const rules = engine.getRules();
    console.log(`\n${rules.length} rule(s):\n`);
    rules.forEach(r => {
      const status = r.enabled ? '\x1b[32mON\x1b[0m' : '\x1b[31mOFF\x1b[0m';
      console.log(`  [${status}] ${r.id} | ${r.name} (${r.type}) [${r.severity}]`);
    });
    console.log('');
  });

program
  .command('block-ip <ip>')
  .description('Block an IP address')
  .action((ip) => {
    const engine = loadEngine();
    engine.blockIP(ip);
    console.log(`✅ IP ${ip} blocked`);
  });

program
  .command('unblock-ip <ip>')
  .description('Unblock an IP address')
  .action((ip) => {
    const engine = loadEngine();
    engine.unblockIP(ip);
    console.log(`✅ IP ${ip} unblocked`);
  });

program
  .command('whitelist-ip <ip>')
  .description('Whitelist an IP address')
  .action((ip) => {
    const engine = loadEngine();
    engine.whitelistIP(ip);
    console.log(`✅ IP ${ip} whitelisted`);
  });

program
  .command('users')
  .description('List users')
  .action(() => {
    const um = loadUsers();
    const users = um.listUsers();
    console.log(`\n${users.length} user(s):\n`);
    users.forEach(u => {
      console.log(`  ${u.username} (${u.role})`);
    });
    console.log('');
  });

program
  .command('create-user <username>')
  .description('Create a new user')
  .requiredOption('-p, --password <password>', 'User password')
  .option('-r, --role <role>', 'User role', 'operator')
  .option('-d, --display <name>', 'Display name')
  .action((username, options) => {
    const um = loadUsers();
    try {
      const user = um.createUser({
        username,
        password: options.password,
        role: options.role,
        displayName: options.display || username
      });
      console.log(`✅ User ${user.username} created with role ${user.role}`);
    } catch (err) {
      console.error(`❌ ${err.message}`);
      process.exit(1);
    }
  });

program
  .command('status')
  .description('Show WAF status')
  .action(() => {
    const engine = loadEngine();
    const stats = engine.getStats();
    console.log('\n🛡️  Kavach WAF Status\n');
    console.log(`  Rules:        ${stats.rulesCount}`);
    console.log(`  Blocked IPs:  ${stats.blockedIPsCount}`);
    console.log(`  Whitelisted:  ${stats.whitelistedIPsCount}`);
    console.log(`  Uptime:       ${Math.floor(stats.uptime / 1000)}s`);
    console.log('');
  });

program
  .command('export <file>')
  .description('Export WAF configuration to file')
  .action((file) => {
    const engine = loadEngine();
    const config = engine.exportConfig();
    fs.writeFileSync(file, JSON.stringify(config, null, 2));
    console.log(`✅ Config exported to ${file}`);
  });

program
  .command('import <file>')
  .description('Import WAF configuration from file')
  .action((file) => {
    const engine = loadEngine();
    const config = JSON.parse(fs.readFileSync(file, 'utf8'));
    const result = engine.importConfig(config);
    if (result.success) {
      console.log(`✅ Config imported from ${file}`);
    } else {
      console.error(`❌ Import failed: ${result.error}`);
      process.exit(1);
    }
  });

program.parse();
