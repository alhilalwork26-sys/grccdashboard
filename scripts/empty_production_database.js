#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

const ROOT = path.resolve(__dirname, '..');
const ENV_PATH = path.join(ROOT, '.env.local');
const BACKUP_DIR = path.join(ROOT, 'backups');

const MODULE_TABLES = [
  'tasks',
  'schedules',
  'expenses',
  'programs',
  'daily_progresses',
  'timeline_equity',
  'reimburse_requests',
  'rab_items',
  'notifications'
];
const DEFAULT_PERMS = {
  'Super Admin + Manager': ['dashboard','tasks','daily_progress','schedule','programs','finance','reimburse','rab','documents','timeline','settings'],
  'Program Admin + Kepala Marketing/Kreatif': ['dashboard','tasks','daily_progress','schedule','programs','reimburse','documents'],
  'Staff Kreatif': ['dashboard','tasks','daily_progress','schedule','reimburse','documents'],
  'Staff Marketing': ['dashboard','tasks','daily_progress','schedule','reimburse','documents'],
  Finance: ['dashboard','daily_progress','schedule','finance','reimburse'],
  'Staff Finance + Dokumen': ['dashboard','daily_progress','schedule','finance','reimburse','documents'],
  'Kepala Trainer': ['dashboard','daily_progress','schedule','programs','reimburse','documents'],
  Riset: ['dashboard','tasks','daily_progress','schedule','reimburse','documents','timeline']
};
const DEFAULT_ROLE_COLORS = {
  'Super Admin + Manager': '#F97316',
  'Program Admin + Kepala Marketing/Kreatif': '#22C55E',
  'Staff Kreatif': '#22C55E',
  'Staff Marketing': '#22C55E',
  Finance: '#34D399',
  'Staff Finance + Dokumen': '#7C3AED',
  'Kepala Trainer': '#7C3AED',
  Riset: '#2563EB'
};
const EMPTY_STATE = {
  userId: null,
  page: 'dashboard',
  taskDetail: null,
  progDetail: null,
  calMonth: '2026-04-01T00:00:00.000Z',
  filterTaskStatus: 'Semua',
  filterTaskUser: 'Semua',
  searchTask: '',
  filterExpStatus: 'Semua',
  filterExpType: 'Semua',
  filterExpMonth: '',
  financeView: 'detail',
  financeReimbursements: {},
  searchDoc: '',
  folderDoc: 'Semua',
  notifEmail: true,
  notifDeadline: true,
  filterProgressUser: 'Semua',
  filterProgressStatus: 'Semua',
  filterProgressDate: '',
  researchItems: [],
  timelineEquity: [],
  reimburseRequests: [],
  rabItems: [],
  timelineEquitySeeded: false,
  filterReimburseStatus: 'Semua',
  filterRabStatus: 'Semua',
  filterEquityStatus: 'Semua',
  filterEquityOwner: 'Semua',
  deadlineReminderLog: {},
  reminderLog: {},
  emailIntegration: { enabled:false, provider:'emailjs', serviceId:'', templateId:'', publicKey:'', fallbackTo:'', fromName:'GRCC Dashboard' }
};

function loadEnv() {
  const raw = fs.readFileSync(ENV_PATH, 'utf8');
  raw.split(/\r?\n/).forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eq = trimmed.indexOf('=');
    if (eq < 0) return;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = value;
  });
}

function hashPassword(password, salt = crypto.randomBytes(16), iterations = 260000) {
  const derived = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  return `pbkdf2_sha256$${iterations}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

async function tableExists(sql, table) {
  const rows = await sql`SELECT to_regclass(${table}) AS name`;
  return Boolean(rows[0]?.name);
}

async function backupTables(sql, tables) {
  const backup = { createdAt: new Date().toISOString(), tables: {} };
  for (const table of tables) {
    if (!(await tableExists(sql, table))) continue;
    backup.tables[table] = await sql.query(`SELECT * FROM ${table}`);
  }
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(BACKUP_DIR, `production-reset-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(backup, null, 2));
  return file;
}

async function main() {
  loadEnv();
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL tidak ditemukan di .env.local');
  const sql = neon(process.env.DATABASE_URL);
  const tables = ['sessions','documents','audit_log',...MODULE_TABLES,'users','roles','app_state'];
  const backupFile = await backupTables(sql, tables);

  for (const [role, permissions] of Object.entries(DEFAULT_PERMS)) {
    await sql`INSERT INTO roles (name, permissions, color) VALUES (${role}, ${JSON.stringify(permissions)}, ${DEFAULT_ROLE_COLORS[role] || '#6B7280'}) ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions, color = EXCLUDED.color, updated_at = now()`;
  }

  await sql`DELETE FROM sessions`;
  for (const table of MODULE_TABLES) {
    if (await tableExists(sql, table)) await sql.query(`DELETE FROM ${table}`);
  }
  await sql`DELETE FROM documents`;
  await sql`DELETE FROM audit_log`;
  await sql`INSERT INTO app_state (id, payload, updated_at) VALUES (1, ${JSON.stringify(EMPTY_STATE)}, now()) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`;

  const counts = {};
  for (const table of tables) {
    if (!(await tableExists(sql, table))) continue;
    const rows = await sql.query(`SELECT count(*)::int AS count FROM ${table}`);
    counts[table] = rows[0].count;
  }
  console.log(JSON.stringify({ ok: true, backupFile, counts }, null, 2));
}

main().catch(err => {
  console.error(err.message || err);
  process.exit(1);
});
