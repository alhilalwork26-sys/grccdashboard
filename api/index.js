const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');
const { put } = require('@vercel/blob');

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
  return {
    id: row.id,
    name: row.name,
    username: row.username,
    email: row.email,
    role: row.role,
    dept: row.dept || '',
    av: row.av || 'U',
    avatarUrl: row.avatar_url || '',
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

async function ensureSchema() {
  if (schemaReady) return;
  const sql = db();
  await sql`CREATE TABLE IF NOT EXISTS roles (name text PRIMARY KEY, permissions jsonb NOT NULL, color text NOT NULL DEFAULT '#6B7280', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS users (id text PRIMARY KEY, name text NOT NULL, username text NOT NULL UNIQUE, email text NOT NULL UNIQUE, password_hash text NOT NULL, role text NOT NULL REFERENCES roles(name) ON UPDATE CASCADE, dept text NOT NULL DEFAULT '', av text NOT NULL DEFAULT 'U', avatar_url text NOT NULL DEFAULT '', active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url text NOT NULL DEFAULT ''`;
  await sql`CREATE TABLE IF NOT EXISTS sessions (token text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS app_state (id integer PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS documents (id text PRIMARY KEY, filename text NOT NULL, content_type text NOT NULL, blob_url text NOT NULL, size integer NOT NULL, uploaded_by text, uploaded_at timestamptz NOT NULL DEFAULT now())`;
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
      const current = await sql`SELECT password_hash, avatar_url FROM users WHERE id = ${user.id}`;
      if (!current[0]) return send(res, 404, { error: 'User tidak ditemukan' });
      if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, user.id);
      if (!avatarUrl) avatarUrl = current[0].avatar_url || '';
      const av = initials(name);
      await sql`UPDATE users SET name=${name}, email=${email}, password_hash=${password ? hashPassword(password) : current[0].password_hash}, av=${av}, avatar_url=${avatarUrl}, updated_at=now() WHERE id=${user.id}`;
      await audit(user, 'update', 'profile', user.id, { avatarUpdated: Boolean(avatarDataUrl) });
      const rows = await sql`SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE id=${user.id}`;
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
      if (updateId) {
        const current = await sql`SELECT password_hash, avatar_url FROM users WHERE id = ${updateId}`;
        if (!current[0]) return send(res, 404, { error: 'User tidak ditemukan' });
        if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, updateId);
        if (!avatarUrl) avatarUrl = current[0].avatar_url || '';
        await sql`UPDATE users SET name=${name}, username=${username}, email=${email}, password_hash=${password ? hashPassword(password) : current[0].password_hash}, role=${role}, dept=${dept}, av=${av}, avatar_url=${avatarUrl}, updated_at=now() WHERE id=${updateId}`;
        await audit(actor, 'update', 'user', updateId, { username, role, avatarUpdated: Boolean(avatarDataUrl) });
      } else {
        id = crypto.randomBytes(8).toString('base64url');
        if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, id);
        await sql`INSERT INTO users (id, name, username, email, password_hash, role, dept, av, avatar_url) VALUES (${id}, ${name}, ${username}, ${email}, ${hashPassword(password)}, ${role}, ${dept}, ${av}, ${avatarUrl})`;
        await audit(actor, 'create', 'user', id, { username, role, avatarUpdated: Boolean(avatarDataUrl) });
      }
      const rows = await sql`SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE id=${id}`;
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
    await sql`UPDATE users SET active=false, updated_at=now() WHERE id=${id}`;
    await sql`DELETE FROM sessions WHERE user_id=${id}`;
    await audit(actor, 'delete', 'user', id);
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
      await sql`UPDATE roles SET name=${name}, permissions=${JSON.stringify(permissions)}, color=${color}, updated_at=now() WHERE name=${oldName}`;
      await audit(actor, 'rename', 'role', name, { oldName, permissions });
    } else {
      await sql`INSERT INTO roles (name, permissions, color, updated_at) VALUES (${name}, ${JSON.stringify(permissions)}, ${color}, now()) ON CONFLICT (name) DO UPDATE SET permissions=EXCLUDED.permissions, color=EXCLUDED.color, updated_at=now()`;
      await audit(actor, 'update', 'role', name, { permissions });
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
    await sql`DELETE FROM roles WHERE name=${name}`;
    await audit(actor, 'delete', 'role', name);
    return send(res, 200, { ok: true });
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
    if (!id || !filename || !dataUrl.includes(',')) return send(res, 400, { error: 'id, filename, dan dataUrl wajib diisi' });
    const buffer = Buffer.from(dataUrl.split(',', 2)[1], 'base64');
    const blob = await put(`grcc/${id}_${filename.replace(/[^A-Za-z0-9._-]+/g, '_')}`, buffer, {
      access: process.env.BLOB_ACCESS === 'private' ? 'private' : 'public',
      contentType
    });
    await sql`INSERT INTO documents (id, filename, content_type, blob_url, size, uploaded_by, uploaded_at) VALUES (${id}, ${filename}, ${contentType}, ${blob.url}, ${buffer.length}, ${user.id}, now()) ON CONFLICT (id) DO UPDATE SET filename=EXCLUDED.filename, content_type=EXCLUDED.content_type, blob_url=EXCLUDED.blob_url, size=EXCLUDED.size, uploaded_by=EXCLUDED.uploaded_by, uploaded_at=now()`;
    await audit(user, 'upload', 'document', id, { filename, size: buffer.length });
    return send(res, 200, { ok: true, downloadUrl: `/api/documents/${encodeURIComponent(id)}/download`, size: buffer.length });
  }

  const docMatch = path.match(/^\/documents\/([^/]+)\/download$/);
  if (docMatch && method === 'GET') {
    if (!await requireUser(req, res)) return;
    const id = decodeURIComponent(docMatch[1]);
    const rows = await sql`SELECT blob_url FROM documents WHERE id=${id}`;
    if (!rows[0]) return send(res, 404, { error: 'Dokumen tidak ditemukan' });
    res.statusCode = 302;
    res.setHeader('Location', rows[0].blob_url);
    return res.end();
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
