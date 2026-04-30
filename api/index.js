const crypto = require('crypto');
const { Readable } = require('stream');
const { neon } = require('@neondatabase/serverless');
const { get, put } = require('@vercel/blob');
const { handleUpload } = require('@vercel/blob/client');

const SESSION_DAYS = 7;
const MODULE_TABLES = {
  tasks: 'tasks',
  schedules: 'schedules',
  expenses: 'expenses',
  programs: 'programs',
  dailyProgresses: 'daily_progresses',
  notifications: 'notifications'
};
const DEFAULT_PERMS = {
  'Super Admin + Manager': ['dashboard','tasks','daily_progress','schedule','programs','finance','documents','settings'],
  'Program Admin + Kepala Marketing/Kreatif': ['dashboard','tasks','daily_progress','schedule','programs','documents'],
  'Staff Kreatif': ['dashboard','tasks','daily_progress','documents'],
  'Staff Marketing': ['dashboard','tasks','daily_progress','schedule','documents'],
  Finance: ['dashboard','daily_progress','finance'],
  'Staff Finance + Dokumen': ['dashboard','daily_progress','finance','documents'],
  'Kepala Trainer': ['dashboard','daily_progress','schedule','programs','documents']
};
const DEFAULT_ROLE_COLORS = {
  'Super Admin + Manager': '#F97316',
  'Program Admin + Kepala Marketing/Kreatif': '#22C55E',
  'Staff Kreatif': '#22C55E',
  'Staff Marketing': '#22C55E',
  Finance: '#34D399',
  'Staff Finance + Dokumen': '#7C3AED',
  'Kepala Trainer': '#7C3AED'
};
const SUPER_ADMIN_ROLES = new Set(['Super Admin', 'Super Admin + Manager']);
const IMPORTANT_DOC_ROLES = new Set(['Super Admin', 'Super Admin + Manager', 'Program Admin', 'Program Admin + Kepala Marketing/Kreatif']);
const LEGACY_ROLE_MIGRATIONS = {
  'Super Admin': 'Super Admin + Manager',
  'Program Admin': 'Program Admin + Kepala Marketing/Kreatif',
  Trainer: 'Kepala Trainer',
  Staff: 'Staff Marketing'
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
  searchDoc: '',
  folderDoc: 'Semua',
  notifEmail: true,
  notifDeadline: true,
  filterProgressUser: 'Semua',
  filterProgressStatus: 'Semua',
  filterProgressDate: '',
  deadlineReminderLog: {},
  reminderLog: {},
  emailIntegration: { enabled:false, provider:'emailjs', serviceId:'', templateId:'', publicKey:'', fallbackTo:'', fromName:'GRCC Dashboard' }
};

let schemaReady = false;

function db() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL belum diset');
  return neon(process.env.DATABASE_URL);
}

function send(res, status, payload, headers = {}) {
  res.statusCode = status;
  Object.entries({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  }).forEach(([key, value]) => res.setHeader(key, value));
  res.end(JSON.stringify(payload));
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(part => {
    const idx = part.indexOf('=');
    return [part.slice(0, idx).trim(), decodeURIComponent(part.slice(idx + 1))];
  }));
}

function setSessionCookie(res, token, maxAge) {
  const secure = process.env.VERCEL ? ' Secure;' : '';
  res.setHeader('Set-Cookie', `grcc_session=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax;${secure}`);
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function hashPassword(password, salt = crypto.randomBytes(16), iterations = 260000) {
  const derived = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  return `pbkdf2_sha256$${iterations}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

function verifyPassword(password, stored) {
  try {
    const [alg, iterRaw, saltRaw, hashRaw] = stored.split('$');
    if (alg !== 'pbkdf2_sha256') return false;
    const actual = crypto.pbkdf2Sync(password, Buffer.from(saltRaw, 'base64'), Number(iterRaw), 32, 'sha256');
    return crypto.timingSafeEqual(actual, Buffer.from(hashRaw, 'base64'));
  } catch {
    return false;
  }
}

function publicUser(row) {
  const rawAvatarUrl = row.avatar_url || '';
  return {
    id: row.id,
    name: row.name,
    username: row.username,
    email: row.email,
    role: row.role,
    dept: row.dept || '',
    av: row.av || 'U',
    avatarUrl: rawAvatarUrl && rawAvatarUrl.includes('.private.blob.vercel-storage.com') ? `/api/users/${encodeURIComponent(row.id)}/avatar` : rawAvatarUrl,
    active: row.active !== false
  };
}

function initials(name) {
  return String(name || 'User').split(/\s+/).filter(Boolean).map(x => x[0]).join('').slice(0, 2).toUpperCase() || 'U';
}

async function uploadAvatarDataUrl(dataUrl, userId) {
  if (!dataUrl) return '';
  if (!process.env.BLOB_READ_WRITE_TOKEN) throw new Error('BLOB_READ_WRITE_TOKEN belum diset');
  const match = String(dataUrl).match(/^data:(image\/(?:png|jpeg|jpg|webp));base64,(.+)$/);
  if (!match) throw new Error('Foto profil harus berupa PNG, JPG, atau WebP');
  const contentType = match[1] === 'image/jpg' ? 'image/jpeg' : match[1];
  const buffer = Buffer.from(match[2], 'base64');
  if (buffer.length > 1.5 * 1024 * 1024) throw new Error('Ukuran foto profil maksimal 1.5 MB');
  const ext = contentType.split('/')[1].replace('jpeg', 'jpg');
  const blob = await put(`profiles/${userId}_${Date.now()}.${ext}`, buffer, {
    access: process.env.BLOB_ACCESS === 'private' ? 'private' : 'public',
    contentType
  });
  return blob.url;
}

function normalizedUser(row) {
  if (!row) return null;
  return {
    name: row.name || '',
    username: row.username || '',
    email: row.email || '',
    role: row.role || '',
    dept: row.dept || '',
    av: row.av || '',
    active: row.active !== false,
    avatarUrl: row.avatar_url || ''
  };
}

function auditDiff(before = {}, after = {}, fields = []) {
  const beforeDiff = {};
  const afterDiff = {};
  for (const field of fields) {
    const oldValue = before?.[field] ?? null;
    const newValue = after?.[field] ?? null;
    if (JSON.stringify(oldValue) !== JSON.stringify(newValue)) {
      beforeDiff[field] = oldValue;
      afterDiff[field] = newValue;
    }
  }
  return { before: beforeDiff, after: afterDiff };
}

function hasDiff(diff) {
  return Boolean(Object.keys(diff.before || {}).length || Object.keys(diff.after || {}).length);
}

function safeDownloadName(filename) {
  return String(filename || 'download').replace(/[\r\n"]/g, '_');
}

function canManageImportantDocuments(user) {
  return IMPORTANT_DOC_ROLES.has(user?.role);
}

async function streamToBuffer(stream) {
  const chunks = [];
  for await (const chunk of Readable.fromWeb(stream)) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function readableDocumentText(buffer, filename, contentType) {
  const name = String(filename || '').toLowerCase();
  const type = String(contentType || '').toLowerCase();
  const textLike = type.startsWith('text/') || /(\.txt|\.md|\.csv|\.json|\.html|\.xml)$/i.test(name);
  let text = buffer.toString('utf8');
  if (!textLike) {
    text = text
      .replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }
  text = text.replace(/\s+/g, ' ').trim().slice(0, 18000);
  return text;
}

function fallbackSummary(filename, text) {
  const sentences = text.match(/[^.!?\n]+[.!?]*/g) || [];
  const clean = sentences.map(s => s.trim()).filter(s => s.length > 35).slice(0, 5);
  const short = clean.length ? clean : [text.slice(0, 450)];
  return [
    `CUK AI membaca dokumen "${filename}" dan membuat ringkasan cepat otomatis.`,
    '',
    'Poin utama:',
    ...short.map((s, i) => `${i + 1}. ${s.slice(0, 280)}`),
    '',
    'Catatan: ringkasan ini dibuat dengan mode lokal karena OPENAI_API_KEY belum aktif di server.'
  ].join('\n');
}

function outputTextFromOpenAI(data) {
  if (data.output_text) return data.output_text;
  const parts = [];
  for (const item of data.output || []) {
    for (const content of item.content || []) {
      if (content.text) parts.push(content.text);
    }
  }
  return parts.join('\n').trim();
}

async function summarizeWithCukAI(filename, text) {
  if (!process.env.OPENAI_API_KEY) {
    return { summary: fallbackSummary(filename, text), model: 'cuk-ai-local' };
  }
  const model = process.env.OPENAI_SUMMARY_MODEL || 'gpt-4.1-mini';
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model,
      instructions: 'Kamu adalah CUK AI, singkatan dari Cepat Urus Kerjaan AI. Ringkas dokumen perusahaan dalam bahasa Indonesia yang jelas, rapi, profesional, dan langsung bisa dipakai manajemen. Jangan mengarang di luar isi dokumen.',
      input: `Nama dokumen: ${filename}\n\nBuat ringkasan dengan format:\n1. Ringkasan singkat\n2. Poin penting\n3. Action item / tindak lanjut jika ada\n4. Risiko atau angka penting jika ada\n\nIsi dokumen:\n${text}`,
      max_output_tokens: 900
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error?.message || `OpenAI gagal (${response.status})`);
  return { summary: outputTextFromOpenAI(data) || fallbackSummary(filename, text), model };
}

async function ensureSchema() {
  if (schemaReady) return;
  const sql = db();
  await sql`CREATE TABLE IF NOT EXISTS roles (name text PRIMARY KEY, permissions jsonb NOT NULL, color text NOT NULL DEFAULT '#6B7280', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS users (id text PRIMARY KEY, name text NOT NULL, username text NOT NULL UNIQUE, email text NOT NULL UNIQUE, password_hash text NOT NULL, role text NOT NULL REFERENCES roles(name) ON UPDATE CASCADE, dept text NOT NULL DEFAULT '', av text NOT NULL DEFAULT 'U', avatar_url text NOT NULL DEFAULT '', active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url text NOT NULL DEFAULT ''`;
  await sql`CREATE TABLE IF NOT EXISTS sessions (token text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS app_state (id integer PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS documents (id text PRIMARY KEY, filename text NOT NULL, content_type text NOT NULL, blob_url text NOT NULL, blob_access text NOT NULL DEFAULT 'public', size integer NOT NULL, uploaded_by text, uploaded_at timestamptz NOT NULL DEFAULT now())`;
  await sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS blob_access text NOT NULL DEFAULT 'public'`;
  await sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS visibility text NOT NULL DEFAULT 'public'`;
  await sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS pin_hash text NOT NULL DEFAULT ''`;
  await sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS ai_summary text NOT NULL DEFAULT ''`;
  await sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS ai_summary_at timestamptz`;
  await sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS ai_summary_model text NOT NULL DEFAULT ''`;
  await sql`CREATE TABLE IF NOT EXISTS audit_log (id bigserial PRIMARY KEY, actor_id text, actor_name text, action text NOT NULL, entity_type text NOT NULL, entity_id text, details jsonb, created_at timestamptz NOT NULL DEFAULT now())`;
  for (const table of Object.values(MODULE_TABLES)) {
    await sql.query(`CREATE TABLE IF NOT EXISTS ${table} (id text PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`);
  }
  for (const [role, permissions] of Object.entries(DEFAULT_PERMS)) {
    await sql`INSERT INTO roles (name, permissions, color) VALUES (${role}, ${JSON.stringify(permissions)}, ${DEFAULT_ROLE_COLORS[role] || '#6B7280'}) ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions, color = EXCLUDED.color, updated_at = now()`;
  }
  for (const [oldRole, newRole] of Object.entries(LEGACY_ROLE_MIGRATIONS)) {
    await sql`UPDATE users SET role = ${newRole}, updated_at = now() WHERE role = ${oldRole}`;
    await sql`DELETE FROM roles WHERE name = ${oldRole} AND NOT EXISTS (SELECT 1 FROM users WHERE role = ${oldRole})`;
  }
  const users = await sql`SELECT count(*)::int AS count FROM users`;
  if (users[0].count === 0) {
    await sql`INSERT INTO users (id, name, username, email, password_hash, role, dept, av) VALUES ('owner', 'Administrator GRCC', 'admin', 'admin@grcc.id', ${hashPassword(process.env.ADMIN_INITIAL_PASSWORD || 'admin12345')}, 'Super Admin + Manager', 'Manajemen', 'AG')`;
  }
  await sql`INSERT INTO app_state (id, payload) VALUES (1, ${JSON.stringify(EMPTY_STATE)}) ON CONFLICT (id) DO NOTHING`;
  schemaReady = true;
}

async function audit(actor, action, entityType, entityId = null, details = {}) {
  const sql = db();
  await sql`INSERT INTO audit_log (actor_id, actor_name, action, entity_type, entity_id, details) VALUES (${actor?.id || null}, ${actor?.name || null}, ${action}, ${entityType}, ${entityId}, ${JSON.stringify(details)})`;
}

async function currentUser(req) {
  const token = parseCookies(req).grcc_session;
  if (!token) return null;
  const sql = db();
  await sql`DELETE FROM sessions WHERE expires_at < ${Math.floor(Date.now() / 1000)}`;
  const rows = await sql`SELECT u.id, u.name, u.username, u.email, u.role, u.dept, u.av, u.avatar_url, u.active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ${token} AND s.expires_at >= ${Math.floor(Date.now() / 1000)} AND u.active = true`;
  return rows[0] ? publicUser(rows[0]) : null;
}

async function requireUser(req, res) {
  const user = await currentUser(req);
  if (!user) send(res, 401, { error: 'Sesi tidak valid, silakan login ulang' });
  return user;
}

async function requireAdmin(req, res) {
  const user = await requireUser(req, res);
  if (!user) return null;
  if (!SUPER_ADMIN_ROLES.has(user.role)) {
    send(res, 403, { error: 'Hanya Super Admin yang boleh mengakses fitur ini' });
    return null;
  }
  return user;
}

async function listUsers() {
  const sql = db();
  const rows = await sql`SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE active = true ORDER BY name`;
  return rows.map(publicUser);
}

async function listRoles() {
  const sql = db();
  const rows = await sql`SELECT name, permissions, color FROM roles ORDER BY name`;
  const permissions = {};
  const roleColors = {};
  rows.forEach(row => {
    permissions[row.name] = row.permissions;
    roleColors[row.name] = row.color;
  });
  return { permissions, roleColors };
}

async function syncModuleTables(state) {
  const sql = db();
  for (const [stateKey, table] of Object.entries(MODULE_TABLES)) {
    const items = Array.isArray(state[stateKey]) ? state[stateKey] : [];
    const ids = [];
    for (const item of items) {
      const id = String(item.id || crypto.randomBytes(8).toString('hex'));
      item.id = id;
      ids.push(id);
      await sql.query(`INSERT INTO ${table} (id, payload, updated_at) VALUES ($1, $2::jsonb, now()) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`, [id, JSON.stringify(item)]);
    }
    if (ids.length) await sql.query(`DELETE FROM ${table} WHERE id <> ALL($1)`, [ids]);
    else await sql.query(`DELETE FROM ${table}`);
  }
}

async function moduleItems(table) {
  const sql = db();
  return (await sql.query(`SELECT payload FROM ${table} ORDER BY updated_at DESC`)).map(row => row.payload);
}

async function loadState() {
  const sql = db();
  const appRows = await sql`SELECT payload, updated_at FROM app_state WHERE id = 1`;
  const state = { ...EMPTY_STATE, ...(appRows[0]?.payload || {}) };
  delete state.accounts;
  delete state.permissions;
  delete state.roleColors;
  for (const [stateKey, table] of Object.entries(MODULE_TABLES)) state[stateKey] = await moduleItems(table);
  state.accounts = await listUsers();
  const roles = await listRoles();
  state.permissions = roles.permissions;
  state.roleColors = roles.roleColors;
  return { state, updatedAt: appRows[0]?.updated_at || null };
}

function cleanState(state) {
  const cleaned = { ...state, serverSavedAt: new Date().toISOString() };
  delete cleaned.accounts;
  delete cleaned.permissions;
  delete cleaned.roleColors;
  delete cleaned.user;
  Object.keys(MODULE_TABLES).forEach(key => delete cleaned[key]);
  return cleaned;
}

async function handle(req, res) {
  await ensureSchema();
  const url = new URL(req.url, 'https://local.invalid');
  let path = url.pathname.replace(/^\/api/, '') || '/';
  const method = req.method;
  const sql = db();

  if (path === '/health') return send(res, 200, { ok: true, db: 'postgres' });

  if (path === '/auth/login' && method === 'POST') {
    const body = await readBody(req);
    const identifier = String(body.identifier || '').trim().toLowerCase();
    const password = String(body.password || '');
    const rows = await sql`SELECT id, name, username, email, password_hash, role, dept, av, active FROM users WHERE active = true AND (lower(username) = ${identifier} OR lower(email) = ${identifier})`;
    if (!rows[0] || !verifyPassword(password, rows[0].password_hash)) return send(res, 401, { error: 'Username/email atau password salah' });
    const token = crypto.randomBytes(32).toString('base64url');
    await sql`INSERT INTO sessions (token, user_id, expires_at) VALUES (${token}, ${rows[0].id}, ${Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400})`;
    const user = publicUser(rows[0]);
    await audit(user, 'login', 'session', user.id);
    const loaded = await loadState();
    loaded.state.userId = user.id;
    setSessionCookie(res, token, SESSION_DAYS * 86400);
    return send(res, 200, { ok: true, user, state: loaded.state, updatedAt: loaded.updatedAt });
  }

  if (path === '/auth/logout' && method === 'POST') {
    const user = await currentUser(req);
    const token = parseCookies(req).grcc_session;
    if (token) await sql`DELETE FROM sessions WHERE token = ${token}`;
    if (user) await audit(user, 'logout', 'session', user.id);
    setSessionCookie(res, '', 0);
    return send(res, 200, { ok: true });
  }

  if (path === '/auth/me' && method === 'GET') {
    const user = await requireUser(req, res);
    if (!user) return;
    return send(res, 200, { user });
  }

  const avatarMatch = path.match(/^\/users\/([^/]+)\/avatar$/);
  if (avatarMatch && method === 'GET') {
    const requester = await requireUser(req, res);
    if (!requester) return;
    const id = decodeURIComponent(avatarMatch[1]);
    const rows = await sql`SELECT avatar_url FROM users WHERE id=${id} AND active=true`;
    const avatarUrl = rows[0]?.avatar_url || '';
    if (!avatarUrl) return send(res, 404, { error: 'Foto profil tidak ditemukan' });
    if (avatarUrl.startsWith('data:image/')) {
      const match = avatarUrl.match(/^data:([^;]+);base64,(.+)$/);
      if (!match) return send(res, 404, { error: 'Foto profil tidak valid' });
      const buffer = Buffer.from(match[2], 'base64');
      res.statusCode = 200;
      res.setHeader('Content-Type', match[1]);
      res.setHeader('Cache-Control', 'private, max-age=300');
      return res.end(buffer);
    }
    if (!avatarUrl.includes('.private.blob.vercel-storage.com')) {
      res.statusCode = 302;
      res.setHeader('Location', avatarUrl);
      return res.end();
    }
    const blob = await get(avatarUrl, { access: 'private' });
    if (!blob || blob.statusCode !== 200 || !blob.stream) return send(res, 404, { error: 'Foto profil tidak ditemukan' });
    res.statusCode = 200;
    res.setHeader('Content-Type', blob.contentType || 'application/octet-stream');
    res.setHeader('Cache-Control', 'private, max-age=300');
    return Readable.fromWeb(blob.stream).pipe(res);
  }

  if (path === '/profile' && method === 'PUT') {
    const user = await requireUser(req, res);
    if (!user) return;
    const body = await readBody(req);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const avatarDataUrl = String(body.avatarDataUrl || '');
    let avatarUrl = String(body.avatarUrl || user.avatarUrl || '').trim();
    if (!name || !email) return send(res, 400, { error: 'Nama dan email wajib diisi' });
    try {
      const current = await sql`SELECT name, username, email, role, dept, av, avatar_url, active, password_hash FROM users WHERE id = ${user.id}`;
      if (!current[0]) return send(res, 404, { error: 'User tidak ditemukan' });
      if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, user.id);
      if (!avatarUrl) avatarUrl = current[0].avatar_url || '';
      const av = initials(name);
      await sql`UPDATE users SET name=${name}, email=${email}, password_hash=${password ? hashPassword(password) : current[0].password_hash}, av=${av}, avatar_url=${avatarUrl}, updated_at=now() WHERE id=${user.id}`;
      const rows = await sql`SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE id=${user.id}`;
      const diff = auditDiff(normalizedUser(current[0]), normalizedUser(rows[0]), ['name', 'email', 'av', 'avatarUrl']);
      await audit(user, 'update', 'profile', user.id, { ...diff, changed: Object.keys(diff.after), passwordChanged: Boolean(password), avatarUpdated: Boolean(avatarDataUrl) });
      return send(res, 200, { ok: true, user: publicUser(rows[0]) });
    } catch (err) {
      if (err.message) return send(res, 409, { error: err.message });
      return send(res, 409, { error: 'Email mungkin sudah digunakan akun lain' });
    }
  }

  if (path === '/state' && method === 'GET') {
    const user = await requireUser(req, res);
    if (!user) return;
    return send(res, 200, await loadState());
  }

  if (path === '/state' && (method === 'PUT' || method === 'POST')) {
    const user = await requireUser(req, res);
    if (!user) return;
    const body = await readBody(req);
    if (!body.state || typeof body.state !== 'object') return send(res, 400, { error: 'Field state wajib berupa object' });
    await syncModuleTables(body.state);
    const cleaned = cleanState(body.state);
    await sql`INSERT INTO app_state (id, payload, updated_at) VALUES (1, ${JSON.stringify(cleaned)}, now()) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`;
    await audit(user, 'update', 'app_state', '1', { modules: Object.keys(MODULE_TABLES) });
    return send(res, 200, { ok: true, savedAt: cleaned.serverSavedAt });
  }

  if (path === '/users' && method === 'GET') {
    if (!await requireAdmin(req, res)) return;
    return send(res, 200, { users: await listUsers() });
  }

  if ((path === '/users' && method === 'POST') || (/^\/users\/[^/]+$/.test(path) && method === 'PUT')) {
    const actor = await requireAdmin(req, res);
    if (!actor) return;
    const updateId = method === 'PUT' ? decodeURIComponent(path.split('/').pop()) : null;
    const body = await readBody(req);
    const name = String(body.name || '').trim();
    const username = String(body.username || '').trim().toLowerCase();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const role = String(body.role || 'Staff Marketing').trim();
    const dept = String(body.dept || '').trim();
    const av = String(body.av || initials(name)).trim().slice(0, 3).toUpperCase();
    const avatarDataUrl = String(body.avatarDataUrl || '');
    let avatarUrl = String(body.avatarUrl || '').trim();
    if (!name || !username || !email) return send(res, 400, { error: 'Nama, username, dan email wajib diisi' });
    if (!updateId && password.length < 6) return send(res, 400, { error: 'Password minimal 6 karakter' });
    try {
      let id = updateId;
      let beforeUserRecord = null;
      if (updateId) {
        const current = await sql`SELECT name, username, email, role, dept, av, avatar_url, active, password_hash FROM users WHERE id = ${updateId}`;
        if (!current[0]) return send(res, 404, { error: 'User tidak ditemukan' });
        beforeUserRecord = current[0];
        if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, updateId);
        if (!avatarUrl) avatarUrl = current[0].avatar_url || '';
        await sql`UPDATE users SET name=${name}, username=${username}, email=${email}, password_hash=${password ? hashPassword(password) : current[0].password_hash}, role=${role}, dept=${dept}, av=${av}, avatar_url=${avatarUrl}, updated_at=now() WHERE id=${updateId}`;
      } else {
        id = crypto.randomBytes(8).toString('base64url');
        if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, id);
        await sql`INSERT INTO users (id, name, username, email, password_hash, role, dept, av, avatar_url) VALUES (${id}, ${name}, ${username}, ${email}, ${hashPassword(password)}, ${role}, ${dept}, ${av}, ${avatarUrl})`;
      }
      const rows = await sql`SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE id=${id}`;
      const afterUser = normalizedUser(rows[0]);
      if (updateId) {
        const beforeUser = normalizedUser(beforeUserRecord);
        const diff = auditDiff(beforeUser, afterUser, ['name', 'username', 'email', 'role', 'dept', 'av', 'avatarUrl', 'active']);
        await audit(actor, 'update', 'user', id, { ...diff, changed: Object.keys(diff.after), passwordChanged: Boolean(password), avatarUpdated: Boolean(avatarDataUrl) });
      } else {
        await audit(actor, 'create', 'user', id, { after: afterUser, passwordSet: true, avatarUpdated: Boolean(avatarDataUrl) });
      }
      return send(res, 200, { ok: true, user: publicUser(rows[0]) });
    } catch (err) {
      return send(res, 409, { error: 'Username/email mungkin sudah digunakan atau role tidak valid' });
    }
  }

  if (/^\/users\/[^/]+$/.test(path) && method === 'DELETE') {
    const actor = await requireAdmin(req, res);
    if (!actor) return;
    const id = decodeURIComponent(path.split('/').pop());
    if (id === actor.id) return send(res, 400, { error: 'Tidak bisa menghapus akun sendiri' });
    const beforeRows = await sql`SELECT name, username, email, role, dept, av, avatar_url, active FROM users WHERE id=${id}`;
    await sql`UPDATE users SET active=false, updated_at=now() WHERE id=${id}`;
    await sql`DELETE FROM sessions WHERE user_id=${id}`;
    await audit(actor, 'delete', 'user', id, { before: normalizedUser(beforeRows[0]) });
    return send(res, 200, { ok: true });
  }

  if (path === '/roles' && method === 'GET') {
    if (!await requireAdmin(req, res)) return;
    return send(res, 200, await listRoles());
  }

  if ((path === '/roles' && method === 'POST') || (/^\/roles\/[^/]+$/.test(path) && method === 'PUT')) {
    const actor = await requireAdmin(req, res);
    if (!actor) return;
    const oldName = method === 'PUT' ? decodeURIComponent(path.split('/').pop()) : null;
    const body = await readBody(req);
    const name = String(body.name || '').trim();
    const permissions = Array.isArray(body.permissions) ? [...new Set(['dashboard', ...body.permissions.map(String)])] : ['dashboard'];
    const color = String(body.color || '#6B7280');
    if (!name) return send(res, 400, { error: 'Nama role wajib diisi' });
    if (oldName && oldName !== name) {
      if (SUPER_ADMIN_ROLES.has(oldName)) return send(res, 400, { error: 'Role Super Admin tidak boleh diganti nama' });
      const beforeRows = await sql`SELECT name, permissions, color FROM roles WHERE name=${oldName}`;
      await sql`UPDATE roles SET name=${name}, permissions=${JSON.stringify(permissions)}, color=${color}, updated_at=now() WHERE name=${oldName}`;
      await audit(actor, 'rename', 'role', name, { before: beforeRows[0] || { name: oldName }, after: { name, permissions, color }, oldName });
    } else {
      const beforeRows = await sql`SELECT name, permissions, color FROM roles WHERE name=${name}`;
      await sql`INSERT INTO roles (name, permissions, color, updated_at) VALUES (${name}, ${JSON.stringify(permissions)}, ${color}, now()) ON CONFLICT (name) DO UPDATE SET permissions=EXCLUDED.permissions, color=EXCLUDED.color, updated_at=now()`;
      const beforeRole = beforeRows[0] || null;
      const afterRole = { name, permissions, color };
      const action = beforeRole ? 'update' : 'create';
      const diff = beforeRole ? auditDiff(beforeRole, afterRole, ['name', 'permissions', 'color']) : { after: afterRole };
      await audit(actor, action, 'role', name, { ...diff, changed: beforeRole ? Object.keys(diff.after) : Object.keys(afterRole) });
    }
    return send(res, 200, { ok: true });
  }

  if (/^\/roles\/[^/]+$/.test(path) && method === 'DELETE') {
    const actor = await requireAdmin(req, res);
    if (!actor) return;
    const name = decodeURIComponent(path.split('/').pop());
    if (SUPER_ADMIN_ROLES.has(name)) return send(res, 400, { error: 'Role Super Admin tidak boleh dihapus' });
    const used = await sql`SELECT id FROM users WHERE role=${name} AND active=true LIMIT 1`;
    if (used[0]) return send(res, 400, { error: 'Role masih dipakai user' });
    const beforeRows = await sql`SELECT name, permissions, color FROM roles WHERE name=${name}`;
    await sql`DELETE FROM roles WHERE name=${name}`;
    await audit(actor, 'delete', 'role', name, { before: beforeRows[0] || { name } });
    return send(res, 200, { ok: true });
  }

  if (path === '/documents/client-upload' && method === 'POST') {
    const body = await readBody(req);
    const request = new Request(`https://${req.headers.host || 'local.invalid'}${req.url}`, {
      method: req.method,
      headers: req.headers
    });
    const jsonResponse = await handleUpload({
      body,
      request,
      onBeforeGenerateToken: async (_pathname, clientPayload) => {
        const user = await currentUser(req);
        if (!user) throw new Error('Sesi tidak valid, silakan login ulang');
        const payload = JSON.parse(clientPayload || '{}');
        const id = String(payload.id || '').trim();
        const filename = String(payload.filename || '').trim();
        const contentType = String(payload.contentType || 'application/octet-stream');
        const size = Number(payload.size || 0);
        const visibility = String(payload.visibility || 'public') === 'important' ? 'important' : 'public';
        const pin = String(payload.pin || '');
        if (!id || !filename) throw new Error('id dan filename wajib diisi');
        if (visibility === 'important' && !canManageImportantDocuments(user)) throw new Error('Hanya Super Admin/Admin yang boleh membuat dokumen penting');
        if (visibility === 'important' && pin.length < 4) throw new Error('PIN dokumen penting minimal 4 digit/karakter');
        return {
          tokenPayload: JSON.stringify({
            id,
            filename,
            contentType,
            size,
            visibility,
            pinHash: visibility === 'important' ? hashPassword(pin) : '',
            userId: user.id,
            userName: user.name,
            userRole: user.role
          })
        };
      },
      onUploadCompleted: async ({ blob, tokenPayload }) => {
        const payload = JSON.parse(tokenPayload || '{}');
        const actor = { id: payload.userId, name: payload.userName, role: payload.userRole };
        const previous = await sql`SELECT filename, content_type, blob_url, blob_access, visibility, size, uploaded_by FROM documents WHERE id=${payload.id}`;
        const access = blob.url && blob.url.includes('.private.blob.vercel-storage.com') ? 'private' : 'public';
        await sql`INSERT INTO documents (id, filename, content_type, blob_url, blob_access, visibility, pin_hash, size, uploaded_by, uploaded_at) VALUES (${payload.id}, ${payload.filename}, ${payload.contentType || blob.contentType || 'application/octet-stream'}, ${blob.url}, ${access}, ${payload.visibility || 'public'}, ${payload.pinHash || ''}, ${payload.size || 0}, ${payload.userId}, now()) ON CONFLICT (id) DO UPDATE SET filename=EXCLUDED.filename, content_type=EXCLUDED.content_type, blob_url=EXCLUDED.blob_url, blob_access=EXCLUDED.blob_access, visibility=EXCLUDED.visibility, pin_hash=EXCLUDED.pin_hash, size=EXCLUDED.size, uploaded_by=EXCLUDED.uploaded_by, ai_summary='', ai_summary_at=NULL, ai_summary_model='', uploaded_at=now()`;
        await audit(actor, previous[0] ? 'replace' : 'upload', 'document', payload.id, { before: previous[0] || null, after: { filename: payload.filename, contentType: payload.contentType || blob.contentType, size: payload.size, visibility: payload.visibility || 'public', blobAccess: access, pinProtected: payload.visibility === 'important' } });
      }
    });
    return send(res, 200, jsonResponse);
  }

  if (path === '/documents' && method === 'POST') {
    const user = await requireUser(req, res);
    if (!user) return;
    if (!process.env.BLOB_READ_WRITE_TOKEN) return send(res, 500, { error: 'BLOB_READ_WRITE_TOKEN belum diset' });
    const body = await readBody(req);
    const id = String(body.id || '').trim();
    const filename = String(body.filename || '').trim();
    const contentType = String(body.contentType || 'application/octet-stream');
    const dataUrl = String(body.dataUrl || '');
    const visibility = String(body.visibility || 'public').trim() === 'important' ? 'important' : 'public';
    const pin = String(body.pin || '');
    if (!id || !filename || !dataUrl.includes(',')) return send(res, 400, { error: 'id, filename, dan dataUrl wajib diisi' });
    if (visibility === 'important' && !canManageImportantDocuments(user)) return send(res, 403, { error: 'Hanya Super Admin/Admin yang boleh membuat dokumen penting' });
    if (visibility === 'important' && pin.length < 4) return send(res, 400, { error: 'PIN dokumen penting minimal 4 digit/karakter' });
    const buffer = Buffer.from(dataUrl.split(',', 2)[1], 'base64');
    const blobAccess = process.env.DOCUMENT_BLOB_ACCESS || process.env.BLOB_ACCESS || 'public';
    const blob = await put(`grcc/${id}_${filename.replace(/[^A-Za-z0-9._-]+/g, '_')}`, buffer, {
      access: blobAccess === 'private' ? 'private' : 'public',
      contentType
    });
    const previous = await sql`SELECT filename, content_type, blob_url, blob_access, visibility, size, uploaded_by FROM documents WHERE id=${id}`;
    const pinHash = visibility === 'important' ? hashPassword(pin) : '';
    await sql`INSERT INTO documents (id, filename, content_type, blob_url, blob_access, visibility, pin_hash, size, uploaded_by, uploaded_at) VALUES (${id}, ${filename}, ${contentType}, ${blob.url}, ${blobAccess === 'private' ? 'private' : 'public'}, ${visibility}, ${pinHash}, ${buffer.length}, ${user.id}, now()) ON CONFLICT (id) DO UPDATE SET filename=EXCLUDED.filename, content_type=EXCLUDED.content_type, blob_url=EXCLUDED.blob_url, blob_access=EXCLUDED.blob_access, visibility=EXCLUDED.visibility, pin_hash=EXCLUDED.pin_hash, size=EXCLUDED.size, uploaded_by=EXCLUDED.uploaded_by, uploaded_at=now()`;
    await audit(user, previous[0] ? 'replace' : 'upload', 'document', id, { before: previous[0] || null, after: { filename, contentType, size: buffer.length, visibility, blobAccess: blobAccess === 'private' ? 'private' : 'public', pinProtected: visibility === 'important' } });
    return send(res, 200, { ok: true, downloadUrl: `/api/documents/${encodeURIComponent(id)}/download`, size: buffer.length });
  }

  const docMatch = path.match(/^\/documents\/([^/]+)\/download$/);
  if (docMatch && method === 'GET') {
    const user = await requireUser(req, res);
    if (!user) return;
    const id = decodeURIComponent(docMatch[1]);
    const rows = await sql`SELECT filename, content_type, blob_url, blob_access, visibility, pin_hash, size FROM documents WHERE id=${id}`;
    if (!rows[0]) return send(res, 404, { error: 'Dokumen tidak ditemukan' });
    const doc = rows[0];
    if (doc.visibility === 'important') {
      const suppliedPin = String(req.headers['x-document-pin'] || url.searchParams.get('pin') || '');
      if (!canManageImportantDocuments(user)) {
        await audit(user, 'denied', 'document', id, { filename: doc.filename, reason: 'role_not_allowed', visibility: doc.visibility });
        return send(res, 403, { error: 'Dokumen penting hanya bisa diakses Super Admin/Admin' });
      }
      if (!doc.pin_hash || !verifyPassword(suppliedPin, doc.pin_hash)) {
        await audit(user, 'denied', 'document', id, { filename: doc.filename, reason: 'pin_invalid', visibility: doc.visibility });
        return send(res, 403, { error: 'PIN dokumen penting salah' });
      }
    }
    const access = doc.blob_access === 'private' || doc.blob_url.includes('.private.blob.vercel-storage.com') ? 'private' : 'public';
    try {
      const blob = await get(doc.blob_url, { access });
      if (!blob || blob.statusCode !== 200 || !blob.stream) return send(res, 404, { error: 'Dokumen tidak ditemukan' });
      await audit(user, 'download', 'document', id, { filename: doc.filename, size: doc.size, visibility: doc.visibility || 'public', accessChecked: true });
      res.statusCode = 200;
      res.setHeader('Content-Type', blob.contentType || doc.content_type || 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${safeDownloadName(doc.filename)}"`);
      res.setHeader('Cache-Control', 'private, max-age=0, must-revalidate');
      return Readable.fromWeb(blob.stream).pipe(res);
    } catch (err) {
      if (access === 'public') {
        await audit(user, 'download', 'document', id, { filename: doc.filename, size: doc.size, visibility: doc.visibility || 'public', accessChecked: true, fallback: 'redirect' });
        res.statusCode = 302;
        res.setHeader('Location', doc.blob_url);
        return res.end();
      }
      throw err;
    }
  }

  const summaryMatch = path.match(/^\/documents\/([^/]+)\/summary$/);
  if (summaryMatch && method === 'POST') {
    const user = await requireUser(req, res);
    if (!user) return;
    const id = decodeURIComponent(summaryMatch[1]);
    const body = await readBody(req);
    const suppliedPin = String(body.pin || req.headers['x-document-pin'] || '');
    const rows = await sql`SELECT filename, content_type, blob_url, blob_access, visibility, pin_hash, size, ai_summary, ai_summary_at, ai_summary_model FROM documents WHERE id=${id}`;
    if (!rows[0]) return send(res, 404, { error: 'Dokumen tidak ditemukan' });
    const doc = rows[0];
    if (doc.visibility === 'important') {
      if (!canManageImportantDocuments(user)) {
        await audit(user, 'denied', 'document_ai_summary', id, { filename: doc.filename, reason: 'role_not_allowed', visibility: doc.visibility });
        return send(res, 403, { error: 'Dokumen penting hanya bisa diringkas Super Admin/Admin' });
      }
      if (!doc.pin_hash || !verifyPassword(suppliedPin, doc.pin_hash)) {
        await audit(user, 'denied', 'document_ai_summary', id, { filename: doc.filename, reason: 'pin_invalid', visibility: doc.visibility });
        return send(res, 403, { error: 'PIN dokumen penting salah' });
      }
    }
    if (doc.ai_summary && !body.refresh) {
      return send(res, 200, { ok: true, summary: doc.ai_summary, model: doc.ai_summary_model || 'cached', cached: true, summarizedAt: doc.ai_summary_at });
    }
    const access = doc.blob_access === 'private' || doc.blob_url.includes('.private.blob.vercel-storage.com') ? 'private' : 'public';
    const blob = await get(doc.blob_url, { access });
    if (!blob || blob.statusCode !== 200 || !blob.stream) return send(res, 404, { error: 'Dokumen tidak ditemukan' });
    const buffer = await streamToBuffer(blob.stream);
    const text = readableDocumentText(buffer, doc.filename, blob.contentType || doc.content_type);
    if (text.length < 80) return send(res, 422, { error: 'CUK AI belum bisa membaca cukup teks dari dokumen ini. Coba file PDF teks, DOCX teks, TXT, CSV, atau dokumen yang tidak berupa scan gambar.' });
    const result = await summarizeWithCukAI(doc.filename, text);
    await sql`UPDATE documents SET ai_summary=${result.summary}, ai_summary_at=now(), ai_summary_model=${result.model} WHERE id=${id}`;
    await audit(user, 'ai_summary', 'document', id, { filename: doc.filename, model: result.model, visibility: doc.visibility || 'public', textLength: text.length });
    return send(res, 200, { ok: true, summary: result.summary, model: result.model, cached: false, summarizedAt: new Date().toISOString() });
  }

  if (path === '/audit' && method === 'GET') {
    if (!await requireAdmin(req, res)) return;
    const auditRows = await sql`SELECT id, actor_id, actor_name, action, entity_type, entity_id, details, created_at FROM audit_log ORDER BY id DESC LIMIT 200`;
    return send(res, 200, { audit: auditRows });
  }

  return send(res, 404, { error: 'Endpoint tidak ditemukan' });
}

module.exports = async (req, res) => {
  try {
    await handle(req, res);
  } catch (err) {
    console.error(err);
    send(res, 500, { error: err.message || 'Server error' });
  }
};
