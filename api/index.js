const crypto = require('crypto');
const { Readable } = require('stream');
const postgres = require('postgres');
const { get, put } = require('@vercel/blob');
const { handleUpload } = require('@vercel/blob/client');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const SESSION_SECONDS = 8 * 60 * 60; // 8 jam (sliding window via /api/auth/me)
const MODULE_TABLES = {
  tasks: 'tasks',
  schedules: 'schedules',
  expenses: 'expenses',
  programs: 'programs',
  dailyProgresses: 'daily_progresses',
  timelineEquity: 'timeline_equity',
  reimburseRequests: 'reimburse_requests',
  rabItems: 'rab_items',
  notifications: 'notifications',
  researchItems: 'research_items'
};
const DEFAULT_PERMS = {
  'Super Admin + Manager': ['dashboard','tasks','daily_progress','schedule','programs','finance','reimburse','rab','documents','timeline','settings'],
  'Program Admin + Kepala Marketing/Kreatif': ['dashboard','tasks','daily_progress','schedule','programs','reimburse','documents'],
  'Staff Kreatif': ['dashboard','tasks','daily_progress','schedule','reimburse','documents'],
  'Staff Marketing': ['dashboard','tasks','daily_progress','schedule','reimburse','documents'],
  Finance: ['dashboard','tasks','daily_progress','schedule','finance','reimburse'],
  'Staff Finance + Dokumen': ['dashboard','tasks','daily_progress','schedule','finance','reimburse','documents'],
  'Kepala Trainer': ['dashboard','tasks','daily_progress','schedule','programs','reimburse','documents'],
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
const SUPER_ADMIN_ROLES = new Set(['Super Admin', 'Super Admin + Manager']);
const REIMBURSE_REVIEW_ROLES = new Set(['Finance', 'Staff Finance + Dokumen']);
const ADMIN_ONLY_PAGES = new Set(['rab', 'settings']);
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
  get calMonth() { const d = new Date(); return new Date(d.getFullYear(), d.getMonth(), 1).toISOString(); },
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
  filterProgramStatus: 'Semua',
  filterProgramTrainer: 'Semua',
  notificationFilter: 'all',
  timelineEquity: [],
  reimburseRequests: [],
  rabItems: [],
  timelineEquitySeeded: false,
  filterEquityStatus: 'Semua',
  filterEquityOwner: 'Semua',
  deadlineReminderLog: {},
  reminderLog: {},
  emailIntegration: { enabled:false, provider:'emailjs', serviceId:'', templateId:'', publicKey:'', fallbackTo:'', fromName:'GRCC Dashboard' }
};

let schemaReady = false;
let _sqlClient = null; // cached postgres client — reused across warm invocations
const JAKARTA_TIMEZONE = 'Asia/Jakarta';
let googleDriveTokenCache = null;

/* ── Rate Limiter (in-memory, per IP/key) ── */
const _rateBuckets = new Map();
function rateLimit(key, maxHits, windowMs) {
  const now = Date.now();
  const bucket = _rateBuckets.get(key) || { count: 0, reset: now + windowMs };
  if (now > bucket.reset) { bucket.count = 0; bucket.reset = now + windowMs; }
  bucket.count++;
  _rateBuckets.set(key, bucket);
  return bucket.count <= maxHits;
}
// Cleanup stale buckets every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _rateBuckets) if (now > v.reset) _rateBuckets.delete(k);
}, 300_000);

/* ── Validation helpers ── */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function validateEmail(v) { return EMAIL_RE.test(String(v || '')); }
function validateName(v)  { const s = String(v || '').trim(); return s.length >= 2 && s.length <= 100; }
function validatePassword(v) { return String(v || '').length >= 6; }
function validateUsername(v) {
  const s = String(v || '').trim();
  return s.length >= 3 && s.length <= 50 && /^[a-z0-9._-]+$/.test(s);
}

/* ── Safe table accessor ── */
const VALID_MODULE_TABLES = new Set(Object.values(MODULE_TABLES));
function safeTable(name) {
  if (!VALID_MODULE_TABLES.has(name)) throw new Error(`Invalid table: ${name}`);
  return name;
}

/* ── Client IP helper ── */
function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
}

function db() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL belum diset');
  if (!_sqlClient) {
    const pg = postgres(process.env.DATABASE_URL, {
      ssl: 'require',
      max: Number(process.env.DB_POOL_MAX || 5),
      idle_timeout: 20,
      connect_timeout: 10,
      prepare: false,
    });
    const wrapped = (strings, ...values) => pg(strings, ...values);
    wrapped.unsafe = (text, params) => pg.unsafe(text, params || []);
    wrapped.begin = (fn) => pg.begin(fn);
    _sqlClient = wrapped;
  }
  return _sqlClient;
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

const MAX_BODY_BYTES = 52 * 1024 * 1024; // 52 MB (sama dengan server.py MAX_BODY)
async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw Object.assign(new Error('Payload terlalu besar (maks 52 MB)'), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function hashPassword(password, salt = crypto.randomBytes(16), iterations = 260000) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, 32, 'sha256', (err, derived) => {
      if (err) return reject(err);
      resolve(`pbkdf2_sha256$${iterations}$${salt.toString('base64')}$${derived.toString('base64')}`);
    });
  });
}

async function verifyPassword(password, stored) {
  try {
    const [alg, iterRaw, saltRaw, hashRaw] = stored.split('$');
    if (alg !== 'pbkdf2_sha256') return false;
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, Buffer.from(saltRaw, 'base64'), Number(iterRaw), 32, 'sha256', (err, actual) => {
        if (err) return resolve(false);
        try { resolve(crypto.timingSafeEqual(actual, Buffer.from(hashRaw, 'base64'))); }
        catch { resolve(false); }
      });
    });
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
    whatsapp: row.whatsapp || '',
    av: row.av || 'U',
    avatarUrl: rawAvatarUrl && rawAvatarUrl.includes('.private.blob.vercel-storage.com') ? `/api/users/${encodeURIComponent(row.id)}/avatar` : rawAvatarUrl,
    active: row.active !== false
  };
}

function initials(name) {
  return String(name || 'User').split(/\s+/).filter(Boolean).map(x => x[0]).join('').slice(0, 2).toUpperCase() || 'U';
}

function normalizeWhatsapp(value) {
  const digits = String(value || '').replace(/[^\d]/g, '');
  if (!digits) return '';
  if (digits.startsWith('0')) return `62${digits.slice(1)}`;
  if (digits.startsWith('8')) return `62${digits}`;
  return digits;
}

async function uploadAvatarDataUrl(dataUrl, userId) {
  if (!dataUrl) return '';
  if (!process.env.BLOB_READ_WRITE_TOKEN) throw new Error('BLOB_READ_WRITE_TOKEN belum diset');
  const match = String(dataUrl).match(/^data:(image\/(?:png|jpeg|jpg|webp));base64,(.+)$/);
  if (!match) throw new Error('Foto profil harus berupa PNG, JPG, atau WebP');
  const contentType = match[1] === 'image/jpg' ? 'image/jpeg' : match[1];
  const buffer = Buffer.from(match[2], 'base64');
  if (buffer.length > 15 * 1024 * 1024) throw new Error('Ukuran foto profil maksimal 15 MB');
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
    whatsapp: row.whatsapp || '',
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

function mimeFromFilename(filename) {
  const ext = String(filename || '').toLowerCase().split('.').pop();
  const types = {
    pdf: 'application/pdf',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ppt: 'application/vnd.ms-powerpoint',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    webp: 'image/webp'
  };
  return types[ext] || '';
}

function downloadContentType(filename, ...candidates) {
  const byName = mimeFromFilename(filename);
  const current = candidates.find(Boolean);
  if (byName && (!current || ['text/plain', 'application/octet-stream', 'binary/octet-stream'].includes(String(current).toLowerCase()))) return byName;
  return current || byName || 'application/octet-stream';
}

function canManageImportantDocuments(user) {
  return IMPORTANT_DOC_ROLES.has(user?.role);
}

async function streamToBuffer(stream) {
  const chunks = [];
  for await (const chunk of Readable.fromWeb(stream)) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function base64Url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function googleDriveConfig() {
  const raw = process.env.GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64
    ? Buffer.from(process.env.GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64, 'base64').toString('utf8')
    : process.env.GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON;
  const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID;
  if (!raw || !folderId) return null;
  const credentials = JSON.parse(raw);
  if (!credentials.client_email || !credentials.private_key) throw new Error('Credential Google Drive tidak lengkap');
  return { credentials, folderId };
}

function isGoogleDriveConfigured() {
  return Boolean(process.env.GOOGLE_DRIVE_FOLDER_ID && (process.env.GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON || process.env.GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64));
}

async function getGoogleDriveToken() {
  if (googleDriveTokenCache && googleDriveTokenCache.expiresAt > Date.now() + 60000) return googleDriveTokenCache.token;
  const config = googleDriveConfig();
  if (!config) return '';
  const { credentials } = config;
  const now = Math.floor(Date.now() / 1000);
  const tokenUri = credentials.token_uri || 'https://oauth2.googleapis.com/token';
  const unsigned = `${base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64Url(JSON.stringify({
    iss: credentials.client_email,
    scope: 'https://www.googleapis.com/auth/drive',
    aud: tokenUri,
    iat: now,
    exp: now + 3600
  }))}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), String(credentials.private_key).replace(/\\n/g, '\n'));
  const assertion = `${unsigned}.${signature.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')}`;
  const response = await fetch(tokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error_description || data.error || `Google token gagal (${response.status})`);
  googleDriveTokenCache = { token: data.access_token, expiresAt: Date.now() + Number(data.expires_in || 3600) * 1000 };
  return googleDriveTokenCache.token;
}

function driveQueryValue(value) {
  return String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

async function ensureGoogleDriveFolder(folderName) {
  const config = googleDriveConfig();
  if (!config) return '';
  const token = await getGoogleDriveToken();
  const name = String(folderName || 'Dokumen Resmi').trim() || 'Dokumen Resmi';
  const query = `mimeType='application/vnd.google-apps.folder' and trashed=false and '${driveQueryValue(config.folderId)}' in parents and name='${driveQueryValue(name)}'`;
  const search = await fetch(`https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(query)}&fields=files(id,name)&supportsAllDrives=true`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const found = await search.json().catch(() => ({}));
  if (search.ok && found.files?.[0]?.id) return found.files[0].id;
  const create = await fetch('https://www.googleapis.com/drive/v3/files?fields=id,name&supportsAllDrives=true', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      mimeType: 'application/vnd.google-apps.folder',
      parents: [config.folderId]
    })
  });
  const created = await create.json().catch(() => ({}));
  if (!create.ok) throw new Error(created.error?.message || `Buat folder Drive gagal (${create.status})`);
  return created.id;
}

async function uploadToGoogleDrive({ filename, contentType, buffer, folder, documentId, visibility }) {
  const config = googleDriveConfig();
  if (!config) return null;
  const token = await getGoogleDriveToken();
  const parentId = await ensureGoogleDriveFolder(folder);
  const boundary = `grcc_${crypto.randomBytes(12).toString('hex')}`;
  const metadata = {
    name: filename,
    parents: [parentId || config.folderId],
    description: `GRCC Dashboard document ${documentId || ''} (${visibility || 'public'})`
  };
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Type: ${contentType || 'application/octet-stream'}\r\n\r\n`),
    buffer,
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);
  const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink,webContentLink&supportsAllDrives=true', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary=${boundary}`,
      'Content-Length': String(body.length)
    },
    body
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error?.message || `Upload Google Drive gagal (${response.status})`);
  return data;
}

async function mirrorDocumentToGoogleDrive({ buffer, blobUrl, blobAccess, filename, contentType, folder, documentId, visibility }) {
  if (!googleDriveConfig()) return null;
  let fileBuffer = buffer;
  if (!fileBuffer && blobUrl) {
    const blob = await get(blobUrl, { access: blobAccess === 'private' ? 'private' : 'public' });
    if (!blob || blob.statusCode !== 200 || !blob.stream) throw new Error('Blob tidak bisa dibaca untuk mirror Drive');
    fileBuffer = await streamToBuffer(blob.stream);
  }
  if (!fileBuffer) throw new Error('File buffer kosong untuk mirror Drive');
  return uploadToGoogleDrive({ filename, contentType, buffer: fileBuffer, folder, documentId, visibility });
}

async function googleDriveStatus() {
  const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID || '';
  const hasCredential = Boolean(process.env.GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON || process.env.GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64);
  if (!folderId && !hasCredential) {
    return { ready: false, state: 'not_configured', folderId: '', serviceAccountEmail: '', message: 'Google Drive belum dikonfigurasi' };
  }
  if (!folderId) {
    return { ready: false, state: 'missing_folder', folderId: '', serviceAccountEmail: '', message: 'Folder ID Google Drive belum diisi' };
  }
  if (!hasCredential) {
    return { ready: false, state: 'missing_credential', folderId, serviceAccountEmail: '', message: 'Folder sudah dipilih, credential Service Account belum diisi' };
  }
  const config = googleDriveConfig();
  const token = await getGoogleDriveToken();
  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(folderId)}?fields=id,name,mimeType&supportsAllDrives=true`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    return {
      ready: false,
      state: 'folder_check_failed',
      folderId,
      serviceAccountEmail: config.credentials.client_email,
      message: data.error?.message || `Folder Google Drive belum bisa diakses (${response.status})`
    };
  }
  return {
    ready: true,
    state: 'ready',
    folderId,
    folderName: data.name || '',
    serviceAccountEmail: config.credentials.client_email,
    message: `Google Drive siap: ${data.name || folderId}`
  };
}

function normalizeDocumentText(text) {
  return String(text || '')
    .replace(/\u0000/g, ' ')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim()
    .slice(0, 18000);
}

async function readableDocumentText(buffer, filename, contentType) {
  const name = String(filename || '').toLowerCase();
  const type = String(contentType || '').toLowerCase();
  if (type.includes('pdf') || name.endsWith('.pdf')) {
    const result = await pdfParse(buffer);
    const text = normalizeDocumentText(result?.text || '');
    if (text) return text;
  }
  if (type.includes('wordprocessingml') || name.endsWith('.docx')) {
    const result = await mammoth.extractRawText({ buffer });
    const text = normalizeDocumentText(result?.value || '');
    if (text) return text;
  }
  const textLike = type.startsWith('text/') || /(\.txt|\.md|\.csv|\.json|\.html|\.xml)$/i.test(name);
  let text = buffer.toString('utf8');
  if (!textLike) {
    text = text
      .replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }
  return normalizeDocumentText(text);
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

function outputTextFromGemini(data) {
  const parts = [];
  for (const candidate of data.candidates || []) {
    for (const part of candidate.content?.parts || []) {
      if (part.text) parts.push(part.text);
    }
  }
  return parts.join('\n').trim();
}

async function summarizeWithGemini(filename, text) {
  const model = process.env.GEMINI_SUMMARY_MODEL || 'gemini-1.5-flash';
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(process.env.GEMINI_API_KEY)}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      systemInstruction: {
        parts: [{ text: 'Kamu adalah CUK AI, singkatan dari Cepat Urus Kerjaan AI. Ringkas dokumen perusahaan dalam bahasa Indonesia yang jelas, rapi, profesional, dan langsung bisa dipakai manajemen. Jangan mengarang di luar isi dokumen.' }]
      },
      contents: [{
        role: 'user',
        parts: [{ text: `Nama dokumen: ${filename}\n\nBuat ringkasan dengan format:\n1. Ringkasan singkat\n2. Poin penting\n3. Action item / tindak lanjut jika ada\n4. Risiko atau angka penting jika ada\n\nIsi dokumen:\n${text}` }]
      }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 900
      }
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error?.message || `Gemini gagal (${response.status})`);
  return { summary: outputTextFromGemini(data) || fallbackSummary(filename, text), model: `gemini:${model}` };
}

async function summarizeWithCukAI(filename, text) {
  if (process.env.OPENAI_API_KEY) {
    const model = process.env.OPENAI_SUMMARY_MODEL || 'gpt-4o-mini';
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
    return { summary: outputTextFromOpenAI(data) || fallbackSummary(filename, text), model: `openai:${model}` };
  }
  if (process.env.GEMINI_API_KEY) return summarizeWithGemini(filename, text);
  return { summary: fallbackSummary(filename, text), model: 'cuk-ai-local' };
}

/*
 * Schema version — naikkan setiap kali ada perubahan DDL.
 * Pada warm path (schema sudah di DB): hanya 1 query SELECT.
 * Pada cold path (deploy baru): jalankan semua DDL lalu simpan versi baru.
 */
const SCHEMA_VERSION = '2026-06-04-v3';

async function ensureSchema() {
  if (schemaReady) return;
  const sql = db();

  /* ── Fast path: cek versi schema di DB ── */
  try {
    const vRow = await sql`
      SELECT value FROM app_config WHERE key = 'schema_version' LIMIT 1`;
    if (vRow[0]?.value === SCHEMA_VERSION) {
      schemaReady = true;
      return; // schema sudah up-to-date, skip semua DDL
    }
  } catch { /* app_config belum ada → lanjut ke full schema setup */ }

  /* ── Slow path: jalankan semua DDL secara paralel ── */

  // Batch 1: tabel fondasi (harus ada sebelum tabel lain yang punya FK)
  await sql`CREATE TABLE IF NOT EXISTS app_config (key text PRIMARY KEY, value text NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS roles (name text PRIMARY KEY, permissions jsonb NOT NULL, color text NOT NULL DEFAULT '#6B7280', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`;

  // Batch 2: tabel users (butuh roles)
  await sql`CREATE TABLE IF NOT EXISTS users (id text PRIMARY KEY, name text NOT NULL, username text NOT NULL UNIQUE, email text NOT NULL UNIQUE, password_hash text NOT NULL, role text NOT NULL REFERENCES roles(name) ON UPDATE CASCADE, dept text NOT NULL DEFAULT '', av text NOT NULL DEFAULT 'U', avatar_url text NOT NULL DEFAULT '', active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`;

  // Batch 3: tabel lain + ALTER TABLE secara paralel
  await Promise.all([
    sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url text NOT NULL DEFAULT ''`,
    sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS whatsapp text NOT NULL DEFAULT ''`,
    sql`CREATE TABLE IF NOT EXISTS sessions (token text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`,
    sql`CREATE TABLE IF NOT EXISTS app_state (id integer PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`,
    sql`CREATE TABLE IF NOT EXISTS audit_log (id bigserial PRIMARY KEY, actor_id text, actor_name text, action text NOT NULL, entity_type text NOT NULL, entity_id text, details jsonb, created_at timestamptz NOT NULL DEFAULT now())`,
    sql`CREATE TABLE IF NOT EXISTS module_deletions (module_key text NOT NULL, entity_id text NOT NULL, deleted_at timestamptz NOT NULL DEFAULT now(), deleted_by text, PRIMARY KEY (module_key, entity_id))`,
  ]);

  // Batch 4: tabel documents + kolom barunya secara paralel
  await sql`CREATE TABLE IF NOT EXISTS documents (id text PRIMARY KEY, filename text NOT NULL, content_type text NOT NULL, blob_url text NOT NULL, blob_access text NOT NULL DEFAULT 'public', size integer NOT NULL, uploaded_by text, uploaded_at timestamptz NOT NULL DEFAULT now())`;
  await Promise.all([
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS blob_access text NOT NULL DEFAULT 'public'`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS visibility text NOT NULL DEFAULT 'public'`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS pin_hash text NOT NULL DEFAULT ''`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS ai_summary text NOT NULL DEFAULT ''`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS ai_summary_at timestamptz`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS ai_summary_model text NOT NULL DEFAULT ''`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS folder text NOT NULL DEFAULT 'Dokumen Resmi'`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS google_drive_file_id text NOT NULL DEFAULT ''`,
    sql`ALTER TABLE documents ADD COLUMN IF NOT EXISTS google_drive_url text NOT NULL DEFAULT ''`,
  ]);

  // Batch 5: semua module tables + index secara paralel
  await Promise.all(Object.values(MODULE_TABLES).map(table => {
    const t = safeTable(table);
    return sql.unsafe(`CREATE TABLE IF NOT EXISTS ${t} (id text PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`);
  }));
  await Promise.all([
    ...Object.values(MODULE_TABLES).map(table => {
      const t = safeTable(table);
      return sql.unsafe(`CREATE INDEX IF NOT EXISTS idx_${t}_updated_at ON ${t}(updated_at DESC)`);
    }),
    sql`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
    sql`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
    sql`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`,
    sql`CREATE INDEX IF NOT EXISTS idx_users_active ON users(active)`,
    sql`CREATE INDEX IF NOT EXISTS idx_documents_visibility ON documents(visibility)`,
    sql`CREATE INDEX IF NOT EXISTS idx_documents_folder ON documents(folder)`,
    sql`CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id)`,
    sql`CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(id DESC)`,
  ]);

  // Batch 6: seed default roles secara paralel
  await Promise.all(Object.entries(DEFAULT_PERMS).map(([role, permissions]) =>
    sql`INSERT INTO roles (name, permissions, color)
        VALUES (${role}, ${JSON.stringify(permissions)}, ${DEFAULT_ROLE_COLORS[role] || '#6B7280'})
        ON CONFLICT (name) DO NOTHING`
  ));

  // Batch 7: migrasi data sekuensial (urutan penting)
  await Promise.all([
    sql.unsafe(`UPDATE roles SET permissions = permissions || '["schedule"]'::jsonb, updated_at = now() WHERE NOT permissions ? 'schedule'`),
    sql.unsafe(`UPDATE roles SET permissions = permissions || '["reimburse"]'::jsonb, updated_at = now() WHERE NOT permissions ? 'reimburse'`),
    sql.unsafe(`UPDATE roles SET permissions = permissions || '["tasks"]'::jsonb, updated_at = now() WHERE name IN ('Finance','Staff Finance + Dokumen','Kepala Trainer') AND NOT permissions ? 'tasks'`),
    sql.unsafe(`UPDATE roles SET permissions = permissions - 'rab' - 'settings', updated_at = now() WHERE name NOT IN ('Super Admin','Super Admin + Manager') AND (permissions ? 'rab' OR permissions ? 'settings')`),
  ]);

  for (const [oldRole, newRole] of Object.entries(LEGACY_ROLE_MIGRATIONS)) {
    await sql`UPDATE users SET role = ${newRole}, updated_at = now() WHERE role = ${oldRole}`;
    await sql`DELETE FROM roles WHERE name = ${oldRole} AND NOT EXISTS (SELECT 1 FROM users WHERE role = ${oldRole})`;
  }

  // Migrasi: pindah researchItems dari app_state.payload ke tabel research_items
  try {
    const appRow = await sql`SELECT payload FROM app_state WHERE id = 1`;
    const legacyItems = appRow[0]?.payload?.researchItems;
    if (Array.isArray(legacyItems) && legacyItems.length > 0) {
      await Promise.all(legacyItems.filter(Boolean).map(item => {
        const id = String(item.id || crypto.randomBytes(8).toString('hex'));
        item.id = id;
        return sql.unsafe(
          `INSERT INTO research_items (id, payload, updated_at) VALUES ($1, $2::jsonb, now()) ON CONFLICT (id) DO NOTHING`,
          [id, JSON.stringify(item)]
        );
      }));
      await sql`UPDATE app_state SET payload = payload - 'researchItems', updated_at = now() WHERE id = 1`;
    }
  } catch (_migErr) { /* abaikan jika data sudah bersih */ }

  // Seed admin user jika DB kosong
  const users = await sql`SELECT count(*)::int AS count FROM users`;
  if (users[0].count === 0) {
    const adminPw = process.env.ADMIN_INITIAL_PASSWORD || '';
    if (!adminPw || adminPw.length < 8) throw new Error('Set ADMIN_INITIAL_PASSWORD (min 8 karakter) sebelum deploy pertama kali');
    await sql`INSERT INTO users (id, name, username, email, password_hash, role, dept, av) VALUES ('owner', 'Administrator GRCC', 'admin', 'admin@grcc.id', ${await hashPassword(adminPw)}, 'Super Admin + Manager', 'Manajemen', 'AG')`;
  }
  await sql`INSERT INTO app_state (id, payload) VALUES (1, ${JSON.stringify(EMPTY_STATE)}) ON CONFLICT (id) DO NOTHING`;

  /* ── Simpan versi schema — request berikutnya akan skip semua DDL di atas ── */
  await sql`INSERT INTO app_config (key, value) VALUES ('schema_version', ${SCHEMA_VERSION})
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`;
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
  const rows = await sql`SELECT u.id, u.name, u.username, u.email, u.role, u.dept, u.whatsapp, u.av, u.avatar_url, u.active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ${token} AND s.expires_at >= ${Math.floor(Date.now() / 1000)} AND u.active = true`;
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

function canReviewReimburseBackend(user) {
  return SUPER_ADMIN_ROLES.has(user?.role) || REIMBURSE_REVIEW_ROLES.has(user?.role);
}

async function listUsers() {
  const sql = db();
  const rows = await sql`SELECT id, name, username, email, role, dept, whatsapp, av, avatar_url, active FROM users WHERE active = true ORDER BY name`;
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

/*
 * syncModuleTables — BATCH version
 * Sebelumnya: 2-3 query per item → N×items queries total → TIMEOUT
 * Sekarang:   3-5 query per modul → ~40 queries total → ~2-4 detik
 */
async function syncModuleTables(state) {
  const sql = db();

  for (const [stateKey, table] of Object.entries(MODULE_TABLES)) {
    if (!Object.prototype.hasOwnProperty.call(state, stateKey)) continue;
    if (!Array.isArray(state[stateKey])) continue;
    const t = safeTable(table);
    const items = state[stateKey];
    if (!items.length) continue;

    /* Assign ID ke item yang belum punya */
    items.forEach(item => { if (!item.id) item.id = crypto.randomBytes(8).toString('hex'); });

    const deletedItems = items.filter(item => item._deleted === true);
    const activeItems  = items.filter(item => item._deleted !== true);

    /* ── 1. Batch DELETE + batch INSERT module_deletions (atomic) ── */
    if (deletedItems.length) {
      const ids = deletedItems.map(item => String(item.id));
      const bys = deletedItems.map(item => String(item.deletedById || item.updatedById || item.deletedByName || ''));
      /* Jalankan dalam satu transaction agar tidak ada state inconsistent
         (item terhapus tapi tidak ada record di module_deletions atau sebaliknya) */
      await sql.begin(async tx => {
        await tx.unsafe(`DELETE FROM ${t} WHERE id = ANY($1::text[])`, [ids]);
        await tx.unsafe(
          `INSERT INTO module_deletions (module_key, entity_id, deleted_at, deleted_by)
           SELECT $1, unnest($2::text[]), now(), unnest($3::text[])
           ON CONFLICT (module_key, entity_id) DO UPDATE
           SET deleted_at = EXCLUDED.deleted_at, deleted_by = EXCLUDED.deleted_by`,
          [stateKey, ids, bys]
        );
      });
    }

    if (!activeItems.length) continue;

    const activeIds = activeItems.map(item => String(item.id));

    /* ── 2. Batch check module_deletions (1 query utk semua ID aktif) ── */
    const delRows = await sql.unsafe(
      `SELECT entity_id, deleted_at FROM module_deletions
       WHERE module_key = $1 AND entity_id = ANY($2::text[])`,
      [stateKey, activeIds]
    );
    const delMap = new Map(
      (delRows.rows || delRows).map(row => [String(row.entity_id), row.deleted_at])
    );

    /* Filter item yg sudah dihapus dan belum di-recreate */
    const toUpsert = activeItems.filter(item => {
      const deletedAt = delMap.get(String(item.id));
      if (!deletedAt) return true;
      const updatedAt = Date.parse(item.updatedAt || item.createdAt || '');
      return Number.isFinite(updatedAt) && updatedAt > Date.parse(deletedAt);
    });
    if (!toUpsert.length) continue;

    /* ── 3. Batch fetch existing + merge (hanya untuk tasks & dailyProgresses) ── */
    let finalPayloads;

    if (stateKey === 'tasks') {
      /* Batch SELECT semua task yang ada di DB sekaligus */
      const ids = toUpsert.map(item => String(item.id));
      const existRows = await sql.unsafe(
        `SELECT id, payload FROM ${t} WHERE id = ANY($1::text[])`, [ids]
      );
      const existMap = new Map((existRows.rows || existRows).map(row => [String(row.id), row.payload]));
      finalPayloads = toUpsert.map(item => {
        const merged = mergeTaskPayload(existMap.get(String(item.id)) || null, item);
        merged.id = String(item.id);
        return merged;
      });

    } else if (stateKey === 'dailyProgresses') {
      /* Dedup client items by userId+date — ambil yang paling baru */
      const dedupMap = new Map();
      for (const item of toUpsert) {
        const key = `${item.userId||''}|${item.date||''}`;
        const existing = dedupMap.get(key);
        if (!existing) { dedupMap.set(key, item); continue; }
        const existTime = Date.parse(existing.updatedAt || '');
        const itemTime  = Date.parse(item.updatedAt || '');
        if (!Number.isFinite(existTime) || (Number.isFinite(itemTime) && itemTime > existTime)) {
          dedupMap.set(key, mergeDailyProgressPayload(existing, item));
        }
      }
      const dedupedItems = [...dedupMap.values()];
      /* Batch SELECT existing dari DB.
         Progress harian uniknya adalah userId+date, bukan hanya id.
         Jika client sempat punya id lokal lalu server memberi id lain, lookup by id saja
         membuat data pagi/sore terlihat hilang atau menjadi duplikat setelah refresh. */
      const ids = dedupedItems.map(item => String(item.id));
      const keys = dedupedItems
        .map(item => `${item.userId || ''}|${item.date || ''}`)
        .filter(key => key !== '|');
      const existRows = await sql.unsafe(
        `SELECT id, payload FROM ${t}
         WHERE id = ANY($1::text[])
            OR ((payload->>'userId') || '|' || (payload->>'date')) = ANY($2::text[])
         ORDER BY updated_at DESC`,
        [ids, keys]
      );
      const existMap = new Map((existRows.rows || existRows).map(row => [String(row.id), row.payload]));
      const existKeyMap = new Map();
      (existRows.rows || existRows).forEach(row => {
        const key = `${row.payload?.userId || ''}|${row.payload?.date || ''}`;
        if (key !== '|' && !existKeyMap.has(key)) existKeyMap.set(key, { id: String(row.id), payload: row.payload });
      });
      finalPayloads = dedupedItems.map(item => {
        const key = `${item.userId || ''}|${item.date || ''}`;
        const byKey = existKeyMap.get(key) || null;
        const existing = existMap.get(String(item.id)) || byKey?.payload || null;
        const merged = mergeDailyProgressPayload(existing, item);
        merged.id = String(existing?.id || byKey?.id || item.id);
        return merged;
      });

    } else {
      finalPayloads = toUpsert.map(item => ({ ...item, id: String(item.id) }));
    }

    /* ── 4. Batch UPSERT — SATU query untuk semua item dalam modul ── */
    const upsertIds   = finalPayloads.map(p => p.id);
    const upsertJsons = finalPayloads.map(p => JSON.stringify(p));
    await sql.unsafe(
      `INSERT INTO ${t} (id, payload, updated_at)
       SELECT unnest($1::text[]), unnest($2::jsonb[]), now()
       ON CONFLICT (id) DO UPDATE
       SET payload = EXCLUDED.payload, updated_at = now()`,
      [upsertIds, upsertJsons]
    );

    if (stateKey === 'dailyProgresses') {
      const uniq = finalPayloads
        .filter(p => p.userId && p.date && p.id)
        .map(p => ({ userId: String(p.userId), date: String(p.date), id: String(p.id) }));
      if (uniq.length) {
        await sql.unsafe(
          `DELETE FROM daily_progresses d
           USING (
             SELECT unnest($1::text[]) AS user_id,
                    unnest($2::text[]) AS date_key,
                    unnest($3::text[]) AS keep_id
           ) v
           WHERE (d.payload->>'userId') = v.user_id
             AND (d.payload->>'date') = v.date_key
             AND d.id <> v.keep_id`,
          [
            uniq.map(x => x.userId),
            uniq.map(x => x.date),
            uniq.map(x => x.id)
          ]
        );
      }
    }
  }
}

function newerIso(a, b) {
  const aTime = a ? Date.parse(a) : -Infinity;
  const bTime = b ? Date.parse(b) : -Infinity;
  if (!Number.isFinite(aTime) && !Number.isFinite(bTime)) return '';
  if (!Number.isFinite(aTime)) return b;
  if (!Number.isFinite(bTime)) return a;
  return aTime >= bTime ? a : b;
}

function earlierIso(a, b) {
  const aTime = a ? Date.parse(a) : Infinity;
  const bTime = b ? Date.parse(b) : Infinity;
  if (!Number.isFinite(aTime) && !Number.isFinite(bTime)) return '';
  if (!Number.isFinite(aTime)) return b;
  if (!Number.isFinite(bTime)) return a;
  return aTime <= bTime ? a : b;
}

function mergeDailyProgressPayload(existing, incoming) {
  if (!existing || typeof existing !== 'object') return incoming;
  const existingTime = Date.parse(existing.updatedAt || '');
  const incomingTime = Date.parse(incoming.updatedAt || '');
  const incomingIsNewer = Number.isFinite(incomingTime) && (!Number.isFinite(existingTime) || incomingTime >= existingTime);
  const merged = incomingIsNewer ? { ...existing, ...incoming } : { ...incoming, ...existing };
  ['morningPlan', 'eveningUpdate', 'blockers', 'tomorrowPlan', 'progressStatus', 'userName', 'role'].forEach(field => {
    const preferred = incomingIsNewer ? incoming[field] : existing[field];
    const fallback = incomingIsNewer ? existing[field] : incoming[field];
    merged[field] = (preferred === undefined || preferred === null || preferred === '') ? (fallback || '') : preferred;
  });
  merged.morningInputTime = earlierIso(existing.morningInputTime, incoming.morningInputTime);
  merged.eveningUpdateTime = newerIso(existing.eveningUpdateTime, incoming.eveningUpdateTime);
  merged.updatedAt = newerIso(existing.updatedAt, incoming.updatedAt);
  return merged;
}

async function upsertDailyProgressItem(sql, incoming, actor) {
  const item = incoming && typeof incoming === 'object' ? { ...incoming } : {};
  const date = String(item.date || '').trim();
  const userId = String(item.userId || actor?.id || '').trim();
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('Tanggal progres tidak valid');
  if (!userId) throw new Error('User progres tidak valid');
  if (actor?.id && userId !== actor.id && !SUPER_ADMIN_ROLES.has(actor.role)) throw new Error('Tidak boleh menyimpan progres user lain');
  item.userId = userId;
  item.userName = String(item.userName || actor?.name || '').trim();
  item.role = String(item.role || actor?.role || '').trim();
  item.updatedAt = item.updatedAt || new Date().toISOString();

  const existingRows = await sql.unsafe(
    `SELECT id, payload FROM daily_progresses
     WHERE id = $1
        OR ((payload->>'userId') = $2 AND (payload->>'date') = $3)
     ORDER BY updated_at DESC
     LIMIT 1`,
    [String(item.id || ''), userId, date]
  );
  const existingRow = existingRows.rows?.[0] || existingRows[0] || null;
  const existing = existingRow?.payload || null;
  const id = String(existing?.id || item.id || crypto.randomBytes(8).toString('base64url'));
  item.id = id;
  const payload = mergeDailyProgressPayload(existing, item);
  payload.id = id;
  await sql.unsafe(`DELETE FROM daily_progresses WHERE ((payload->>'userId') = $1 AND (payload->>'date') = $2) AND id <> $3`, [userId, date, id]);
  await sql.unsafe(
    `INSERT INTO daily_progresses (id, payload, updated_at)
     VALUES ($1, $2::jsonb, now())
     ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`,
    [id, JSON.stringify(payload)]
  );
  return payload;
}

function mergeByIdOrSignature(existing = [], incoming = []) {
  const map = new Map();
  const keyOf = item => String(item?.id || item?.url || item?.downloadUrl || `${item?.by || item?.uploadedBy || ''}|${item?.text || item?.name || ''}|${item?.ts || item?.uploadedAt || ''}`);
  [...existing, ...incoming].forEach(item => {
    if (!item || typeof item !== 'object') return;
    map.set(keyOf(item), { ...(map.get(keyOf(item)) || {}), ...item });
  });
  return [...map.values()];
}

function mergeTaskPayload(existing, incoming) {
  if (!existing || typeof existing !== 'object') return incoming;
  const merged = { ...existing, ...incoming };
  merged.comments = mergeByIdOrSignature(existing.comments || [], incoming.comments || []);
  const evidenceTypes = new Set([
    ...Object.keys(existing.evidence || {}),
    ...Object.keys(incoming.evidence || {})
  ]);
  merged.evidence = {};
  evidenceTypes.forEach(type => {
    merged.evidence[type] = mergeByIdOrSignature(existing.evidence?.[type] || [], incoming.evidence?.[type] || []);
  });
  return merged;
}

async function moduleItems(table) {
  const sql = db();
  const t = safeTable(table);
  const result = await sql.unsafe(`SELECT payload FROM ${t} ORDER BY updated_at DESC`);
  return (result.rows || result).map(row => row.payload).filter(item => !item?._deleted);
}

function normalizeDailyProgressItems(items = []) {
  const map = new Map();
  items.forEach(item => {
    if (!item || typeof item !== 'object') return;
    const key = `${item.userId || ''}|${item.date || ''}`;
    if (!item.userId || !item.date) {
      map.set(item.id || crypto.randomBytes(4).toString('hex'), item);
      return;
    }
    map.set(key, mergeDailyProgressPayload(map.get(key), item));
  });
  return [...map.values()].sort((a, b) => Date.parse(b.updatedAt || b.date || '') - Date.parse(a.updatedAt || a.date || ''));
}

async function loadState() {
  const sql = db();
  const appRows = await sql`SELECT payload, updated_at FROM app_state WHERE id = 1`;
  const state = { ...EMPTY_STATE, ...(appRows[0]?.payload || {}) };
  delete state.accounts;
  delete state.permissions;
  delete state.roleColors;
  const moduleEntries = Object.entries(MODULE_TABLES);
  const [moduleResults, users, roles] = await Promise.all([
    Promise.all(moduleEntries.map(([stateKey, table]) => moduleItems(table).then(items => [stateKey, items]))),
    listUsers(),
    listRoles()
  ]);
  moduleResults.forEach(([stateKey, items]) => {
    state[stateKey] = stateKey === 'dailyProgresses' ? normalizeDailyProgressItems(items) : items;
  });
  state.accounts = users;
  state.permissions = roles.permissions;
  state.roleColors = roles.roleColors;
  return { state, updatedAt: appRows[0]?.updated_at || null };
}

function jakartaDateKey(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: JAKARTA_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(date).reduce((acc, part) => {
    acc[part.type] = part.value;
    return acc;
  }, {});
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function jakartaTimeLabel(date = new Date()) {
  return new Intl.DateTimeFormat('id-ID', {
    timeZone: JAKARTA_TIMEZONE,
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

function jakartaIsWeekend(date = new Date()) {
  const day = new Intl.DateTimeFormat('en-US', { timeZone: JAKARTA_TIMEZONE, weekday: 'short' }).format(date);
  return day === 'Sat' || day === 'Sun';
}

function userCanUseDailyProgress(user, permissions = {}) {
  if (!user || user.active === false || SUPER_ADMIN_ROLES.has(user.role)) return false;
  return (permissions[user.role] || []).includes('daily_progress');
}

function progressReminderMessage(phase, user, dateKey) {
  if (phase === 'morning') {
    return `Halo ${user.name}, jangan lupa isi progres pagi hari ini (${dateKey}) sebelum mulai kerja. Buka GRCC Dashboard > Progres Harian.`;
  }
  return `Halo ${user.name}, jangan lupa isi update progres sore hari ini (${dateKey}) sebelum selesai kerja. Buka GRCC Dashboard > Progres Harian.`;
}

function jakartaDateMs(dateKey) {
  const match = String(dateKey || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return NaN;
  return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
}

function daysUntilJakarta(dateKey, baseDateKey = jakartaDateKey()) {
  const due = jakartaDateMs(dateKey);
  const base = jakartaDateMs(baseDateKey);
  if (!Number.isFinite(due) || !Number.isFinite(base)) return null;
  return Math.round((due - base) / 86400000);
}

function taskReminderStage(days) {
  if (days === null) return null;
  if (days === 2) return 'h-2';
  if (days === 1) return 'h-1';
  if (days === 0) return 'today';
  if (days < 0) return 'overdue';
  return null;
}

function taskDeadlineReminderMessage(task, user, days) {
  const title = task.title || 'Task';
  const deadline = task.deadline || '-';
  const priority = task.priority ? ` Prioritas: ${task.priority}.` : '';
  if (days < 0) {
    return `Halo ${user.name}, task "${title}" sudah melewati deadline ${deadline}. Mohon update status/progresnya hari ini di GRCC Dashboard > Task Management.${priority}`;
  }
  if (days === 0) {
    return `Halo ${user.name}, task "${title}" jatuh tempo HARI INI (${deadline}). Mohon selesaikan atau update progresnya di GRCC Dashboard > Task Management.${priority}`;
  }
  return `Halo ${user.name}, reminder task "${title}" akan jatuh tempo dalam ${days} hari (${deadline}). Mohon cek dan update progresnya di GRCC Dashboard > Task Management.${priority}`;
}

function taskAssignee(task, users = []) {
  if (!task || !task.aId) return null;
  return users.find(user => user.id === task.aId) || null;
}

async function sendWhatsappMessage(to, message, meta = {}) {
  const target = normalizeWhatsapp(to);
  if (!target) return { ok: false, skipped: true, reason: 'missing_whatsapp' };

  const customUrl = process.env.WHATSAPP_WEBHOOK_URL || '';
  const token = process.env.WHATSAPP_TOKEN || process.env.FONNTE_TOKEN || '';
  if (customUrl) {
    const response = await fetch(customUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      },
      body: JSON.stringify({ to: target, message, ...meta })
    });
    const body = await response.text().catch(() => '');
    return { ok: response.ok, status: response.status, provider: 'custom', body: body.slice(0, 500) };
  }

  if (!token) return { ok: false, skipped: true, reason: 'whatsapp_not_configured' };
  const response = await fetch(process.env.FONNTE_API_URL || 'https://api.fonnte.com/send', {
    method: 'POST',
    headers: {
      Authorization: token,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({ target, message, countryCode: '62' })
  });
  const body = await response.text().catch(() => '');
  return { ok: response.ok, status: response.status, provider: 'fonnte', body: body.slice(0, 500) };
}

async function runWhatsappProgressReminder(phase) {
  const loaded = await loadState();
  const state = loaded.state;
  const dateKey = jakartaDateKey();
  if (jakartaIsWeekend()) {
    return {
      ok: true,
      phase,
      date: dateKey,
      timeWib: jakartaTimeLabel(),
      weekend: true,
      total: 0,
      sent: 0,
      skipped: 0,
      failed: 0,
      complete: 0,
      results: []
    };
  }
  const progressItems = Array.isArray(state.dailyProgresses) ? state.dailyProgresses : [];
  const users = (Array.isArray(state.accounts) ? state.accounts : [])
    .filter(user => userCanUseDailyProgress(user, state.permissions || {}));
  const results = [];
  for (const user of users) {
    const progress = progressItems.find(item => item.userId === user.id && item.date === dateKey);
    const shouldSend = phase === 'morning'
      ? !progress?.morningPlan
      : !progress?.eveningUpdate;
    if (!shouldSend) {
      results.push({ userId: user.id, name: user.name, status: 'complete' });
      continue;
    }
    const message = progressReminderMessage(phase, user, dateKey);
    let result;
    try {
      result = await sendWhatsappMessage(user.whatsapp, message, { phase, userId: user.id, date: dateKey });
    } catch (err) {
      result = { ok: false, reason: err.message || 'send_failed' };
    }
    const status = result.ok ? 'sent' : result.skipped ? 'skipped' : 'failed';
    results.push({ userId: user.id, name: user.name, whatsapp: user.whatsapp ? 'set' : 'missing', status, reason: result.reason || null });
    await audit(
      { id: 'system', name: 'GRCC Reminder' },
      status === 'sent' ? 'whatsapp_reminder_sent' : `whatsapp_reminder_${status}`,
      'daily_progress',
      `${dateKey}_${phase}_${user.id}`,
      { phase, date: dateKey, userId: user.id, userName: user.name, result }
    );
  }
  return {
    ok: true,
    phase,
    date: dateKey,
    timeWib: jakartaTimeLabel(),
    total: users.length,
    sent: results.filter(item => item.status === 'sent').length,
    skipped: results.filter(item => item.status === 'skipped').length,
    failed: results.filter(item => item.status === 'failed').length,
    complete: results.filter(item => item.status === 'complete').length,
    results
  };
}

async function reminderAlreadyHandled(entityType, entityId) {
  const sql = db();
  const rows = await sql`SELECT id FROM audit_log WHERE entity_type=${entityType} AND entity_id=${entityId} AND action LIKE 'whatsapp_%' LIMIT 1`;
  return Boolean(rows[0]);
}

async function runWhatsappTaskDeadlineReminder() {
  const loaded = await loadState();
  const state = loaded.state;
  const dateKey = jakartaDateKey();
  const users = Array.isArray(state.accounts) ? state.accounts.filter(user => user.active !== false) : [];
  const tasks = (Array.isArray(state.tasks) ? state.tasks : [])
    .filter(task => task && !task._deleted && task.status !== 'Done' && task.deadline);
  const results = [];
  for (const task of tasks) {
    const days = daysUntilJakarta(task.deadline, dateKey);
    const stage = taskReminderStage(days);
    if (!stage) continue;
    const user = taskAssignee(task, users);
    if (!user) {
      results.push({ taskId: task.id, title: task.title, status: 'skipped', reason: 'assignee_not_found' });
      continue;
    }
    const logKey = `${dateKey}_${stage}_${task.id}_${user.id}`;
    if (await reminderAlreadyHandled('task', logKey)) {
      results.push({ taskId: task.id, title: task.title, userId: user.id, name: user.name, status: 'duplicate_skipped', stage });
      continue;
    }
    const message = taskDeadlineReminderMessage(task, user, days);
    let result;
    try {
      result = await sendWhatsappMessage(user.whatsapp, message, { stage, taskId: task.id, userId: user.id, deadline: task.deadline });
    } catch (err) {
      result = { ok: false, reason: err.message || 'send_failed' };
    }
    const status = result.ok ? 'sent' : result.skipped ? 'skipped' : 'failed';
    results.push({ taskId: task.id, title: task.title, userId: user.id, name: user.name, whatsapp: user.whatsapp ? 'set' : 'missing', status, stage, days, reason: result.reason || null });
    await audit(
      { id: 'system', name: 'GRCC Reminder' },
      status === 'sent' ? 'whatsapp_task_deadline_sent' : `whatsapp_task_deadline_${status}`,
      'task',
      logKey,
      { stage, days, date: dateKey, taskId: task.id, title: task.title, deadline: task.deadline, userId: user.id, userName: user.name, result }
    );
  }
  return {
    ok: true,
    date: dateKey,
    timeWib: jakartaTimeLabel(),
    total: results.length,
    sent: results.filter(item => item.status === 'sent').length,
    skipped: results.filter(item => item.status === 'skipped' || item.status === 'duplicate_skipped').length,
    failed: results.filter(item => item.status === 'failed').length,
    results
  };
}

function cleanState(state) {
  const cleaned = { ...state, serverSavedAt: new Date().toISOString() };
  delete cleaned.accounts;
  delete cleaned.permissions;
  delete cleaned.roleColors;
  delete cleaned.user;
  delete cleaned.userId;
  Object.keys(MODULE_TABLES).forEach(key => delete cleaned[key]);
  return cleaned;
}

function mergeStateItems(existing = [], incoming = []) {
  const map = new Map();
  existing.forEach(item => {
    if (item?.id && !item._deleted) map.set(String(item.id), item);
  });
  incoming.forEach(item => {
    if (!item?.id) return;
    const id = String(item.id);
    if (item._deleted) {
      map.delete(id);
      return;
    }
    map.set(id, { ...(map.get(id) || {}), ...item });
  });
  return [...map.values()];
}

async function mergeAppStatePayload(sql, cleaned, incomingState) {
  const rows = await sql`SELECT payload FROM app_state WHERE id = 1`;
  const previous = rows[0]?.payload || {};
  if (Array.isArray(incomingState.docs)) {
    cleaned.docs = mergeStateItems(previous.docs || [], incomingState.docs || []);
    const deletedDocIds = incomingState.docs.filter(doc => doc?._deleted && doc.id).map(doc => String(doc.id));
    for (const id of deletedDocIds) {
      await sql`DELETE FROM documents WHERE id=${id}`;
    }
  } else if (Array.isArray(previous.docs)) {
    cleaned.docs = previous.docs;
  }
  return cleaned;
}

async function touchAppStateMarker(sql) {
  const savedAt = new Date().toISOString();
  const marker = JSON.stringify({ serverSavedAt: savedAt });
  await sql.unsafe(
    `INSERT INTO app_state (id, payload, updated_at)
     VALUES (1, $1::jsonb, now())
     ON CONFLICT (id) DO UPDATE
     SET payload = app_state.payload || $1::jsonb, updated_at = now()`,
    [marker]
  );
  return savedAt;
}

async function handle(req, res) {
  const url = new URL(req.url, 'https://local.invalid');
  let path = url.pathname.replace(/^\/api/, '') || '/';
  const method = req.method;

  if (path === '/health') {
    try {
      const sql = db();
      await sql`SELECT 1`;
      return send(res, 200, {
        ok: true,
        db: 'ok',
        cukAI: process.env.OPENAI_API_KEY ? 'openai' : process.env.GEMINI_API_KEY ? 'gemini' : 'fallback',
        ts: new Date().toISOString()
      });
    } catch (err) {
      return send(res, 503, { ok: false, db: 'error', error: err.message });
    }
  }

  await ensureSchema();
  const sql = db();

  const cronMatch = path.match(/^\/cron\/progress-(morning|evening)$/);
  if (cronMatch && method === 'GET') {
    if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
      return send(res, 401, { error: 'Unauthorized cron request' });
    }
    return send(res, 200, await runWhatsappProgressReminder(cronMatch[1]));
  }

  if (path === '/cron/task-deadlines' && method === 'GET') {
    if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
      return send(res, 401, { error: 'Unauthorized cron request' });
    }
    return send(res, 200, await runWhatsappTaskDeadlineReminder());
  }

  if (path === '/auth/login' && method === 'POST') {
    const ip = clientIp(req);
    if (!rateLimit(`login:${ip}`, 10, 60_000)) {
      return send(res, 429, { error: 'Terlalu banyak percobaan login. Coba lagi dalam 1 menit.' });
    }
    const body = await readBody(req);
    const identifier = String(body.identifier || '').trim().toLowerCase();
    const password = String(body.password || '');
    const rows = await sql`SELECT id, name, username, email, password_hash, role, dept, whatsapp, av, active FROM users WHERE active = true AND (lower(username) = ${identifier} OR lower(email) = ${identifier})`;
    if (!rows[0] || !await verifyPassword(password, rows[0].password_hash)) {
      await audit(
        { id: 'system', name: 'GRCC Auth' },
        'login_failed', 'session', identifier,
        { reason: rows[0] ? 'invalid_password' : 'user_not_found', ip }
      );
      return send(res, 401, { error: 'Username/email atau password salah' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    const sessionExpiresAt = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
    /* Jalankan insert session dan audit secara paralel — tidak perlu tunggu keduanya selesai */
    const [, user] = await Promise.all([
      sql`INSERT INTO sessions (token, user_id, expires_at) VALUES (${token}, ${rows[0].id}, ${sessionExpiresAt})`,
      Promise.resolve(publicUser(rows[0]))
    ]);
    audit(user, 'login', 'session', user.id, { ip }).catch(() => {}); // fire-and-forget
    setSessionCookie(res, token, SESSION_SECONDS);
    /* Tidak load state di sini — frontend akan fetch GET /api/state sendiri.
       Ini memotong waktu login dari ~1-3s menjadi ~300-500ms. */
    return send(res, 200, { ok: true, user, sessionExpiresAt });
  }

  if (path === '/auth/logout' && method === 'POST') {
    const user = await currentUser(req);
    const token = parseCookies(req).grcc_session;
    if (token) await sql`DELETE FROM sessions WHERE token = ${token}`;
    if (user) await audit(user, 'logout', 'session', user.id);
    setSessionCookie(res, '', 0);
    await touchAppStateMarker(sql);
    const loaded = await loadState();
    return send(res, 200, { ok: true, state: loaded.state, updatedAt: loaded.updatedAt });
  }

  if (path === '/auth/me' && method === 'GET') {
    const user = await requireUser(req, res);
    if (!user) return;
    // Slide session window on activity
    const token = parseCookies(req).grcc_session;
    const newExpiry = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
    if (token) await sql`UPDATE sessions SET expires_at=${newExpiry} WHERE token=${token}`;
    return send(res, 200, { user, sessionExpiresAt: newExpiry });
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
    const whatsapp = normalizeWhatsapp(body.whatsapp || '');
    const password = String(body.password || '');
    const avatarDataUrl = String(body.avatarDataUrl || '');
    let avatarUrl = String(body.avatarUrl || user.avatarUrl || '').trim();
    if (!validateName(name)) return send(res, 400, { error: 'Nama harus 2–100 karakter' });
    if (!validateEmail(email)) return send(res, 400, { error: 'Format email tidak valid' });
    if (password && !validatePassword(password)) return send(res, 400, { error: 'Password minimal 6 karakter' });
    try {
      const current = await sql`SELECT name, username, email, role, dept, whatsapp, av, avatar_url, active, password_hash FROM users WHERE id = ${user.id}`;
      if (!current[0]) return send(res, 404, { error: 'User tidak ditemukan' });
      if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, user.id);
      if (!avatarUrl) avatarUrl = current[0].avatar_url || '';
      const av = initials(name);
      await sql`UPDATE users SET name=${name}, email=${email}, whatsapp=${whatsapp}, password_hash=${password ? await hashPassword(password) : current[0].password_hash}, av=${av}, avatar_url=${avatarUrl}, updated_at=now() WHERE id=${user.id}`;
      const rows = await sql`SELECT id, name, username, email, role, dept, whatsapp, av, avatar_url, active FROM users WHERE id=${user.id}`;
      const diff = auditDiff(normalizedUser(current[0]), normalizedUser(rows[0]), ['name', 'email', 'whatsapp', 'av', 'avatarUrl']);
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

  if (path === '/daily-progress' && (method === 'PUT' || method === 'POST')) {
    const user = await requireUser(req, res);
    if (!user) return;
    const body = await readBody(req);
    try {
      const item = await upsertDailyProgressItem(sql, body.item || body.progress || body, user);
      const savedAt = await touchAppStateMarker(sql);
      await audit(user, 'upsert', 'daily_progress', item.id, {
        date: item.date,
        userId: item.userId,
        phase: body.phase || null
      });
      return send(res, 200, { ok: true, item, savedAt });
    } catch (err) {
      return send(res, 400, { error: err.message || 'Progres harian gagal disimpan' });
    }
  }

  if (path === '/state' && (method === 'PUT' || method === 'POST')) {
    const user = await requireUser(req, res);
    if (!user) return;
    const body = await readBody(req);
    if (!body.state || typeof body.state !== 'object') return send(res, 400, { error: 'Field state wajib berupa object' });
    await syncModuleTables(body.state);
    const cleaned = await mergeAppStatePayload(sql, cleanState(body.state), body.state);
    await sql`INSERT INTO app_state (id, payload, updated_at) VALUES (1, ${JSON.stringify(cleaned)}, now()) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`;
    await audit(user, 'update', 'app_state', '1', { modules: Object.keys(MODULE_TABLES) });
    return send(res, 200, { ok: true, savedAt: cleaned.serverSavedAt });
  }

  const reimburseMatch = path.match(/^\/reimburse-requests\/([^/]+)$/);
  if (reimburseMatch && method === 'DELETE') {
    const user = await requireUser(req, res);
    if (!user) return;
    const id = decodeURIComponent(reimburseMatch[1]);
    const rows = await sql`SELECT payload FROM reimburse_requests WHERE id=${id}`;
    if (!rows[0]) {
      await sql`
        INSERT INTO module_deletions (module_key, entity_id, deleted_at, deleted_by)
        VALUES ('reimburseRequests', ${id}, now(), ${user.id})
        ON CONFLICT (module_key, entity_id) DO UPDATE
        SET deleted_at = EXCLUDED.deleted_at, deleted_by = EXCLUDED.deleted_by
      `;
      await touchAppStateMarker(sql);
      return send(res, 200, { ok: true, deleted: false });
    }
    const item = rows[0].payload || {};
    const allowed = canReviewReimburseBackend(user) || (item.applicantId === user.id && item.status === 'Submitted');
    if (!allowed) return send(res, 403, { error: 'Anda tidak punya akses menghapus pengajuan ini' });
    await sql`DELETE FROM reimburse_requests WHERE id=${id}`;
    await sql`
      INSERT INTO module_deletions (module_key, entity_id, deleted_at, deleted_by)
      VALUES ('reimburseRequests', ${id}, now(), ${user.id})
      ON CONFLICT (module_key, entity_id) DO UPDATE
      SET deleted_at = EXCLUDED.deleted_at, deleted_by = EXCLUDED.deleted_by
    `;
    const savedAt = await touchAppStateMarker(sql);
    await audit(user, 'delete', 'reimburse_request', id, { before: item });
    return send(res, 200, { ok: true, deleted: true, savedAt });
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
    const whatsapp = normalizeWhatsapp(body.whatsapp || '');
    const password = String(body.password || '');
    const role = String(body.role || 'Staff Marketing').trim();
    const dept = String(body.dept || '').trim();
    const av = String(body.av || initials(name)).trim().slice(0, 3).toUpperCase();
    const avatarDataUrl = String(body.avatarDataUrl || '');
    let avatarUrl = String(body.avatarUrl || '').trim();
    if (!validateName(name)) return send(res, 400, { error: 'Nama harus 2–100 karakter' });
    if (!validateUsername(username)) return send(res, 400, { error: 'Username harus 3–50 karakter, hanya huruf kecil, angka, titik, underscore, atau strip (a-z 0-9 . _ -)' });
    if (!validateEmail(email)) return send(res, 400, { error: 'Format email tidak valid' });
    if (!updateId && !validatePassword(password)) return send(res, 400, { error: 'Password minimal 6 karakter' });
    if (password && !validatePassword(password)) return send(res, 400, { error: 'Password minimal 6 karakter' });
    try {
      let id = updateId;
      let beforeUserRecord = null;
      if (updateId) {
        const current = await sql`SELECT name, username, email, role, dept, whatsapp, av, avatar_url, active, password_hash FROM users WHERE id = ${updateId}`;
        if (!current[0]) return send(res, 404, { error: 'User tidak ditemukan' });
        beforeUserRecord = current[0];
        if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, updateId);
        if (!avatarUrl) avatarUrl = current[0].avatar_url || '';
        await sql`UPDATE users SET name=${name}, username=${username}, email=${email}, whatsapp=${whatsapp}, password_hash=${password ? await hashPassword(password) : current[0].password_hash}, role=${role}, dept=${dept}, av=${av}, avatar_url=${avatarUrl}, updated_at=now() WHERE id=${updateId}`;
      } else {
        id = crypto.randomBytes(8).toString('base64url');
        if (avatarDataUrl) avatarUrl = await uploadAvatarDataUrl(avatarDataUrl, id);
        await sql`INSERT INTO users (id, name, username, email, whatsapp, password_hash, role, dept, av, avatar_url) VALUES (${id}, ${name}, ${username}, ${email}, ${whatsapp}, ${await hashPassword(password)}, ${role}, ${dept}, ${av}, ${avatarUrl})`;
      }
      const rows = await sql`SELECT id, name, username, email, role, dept, whatsapp, av, avatar_url, active FROM users WHERE id=${id}`;
      const afterUser = normalizedUser(rows[0]);
      if (updateId) {
        const beforeUser = normalizedUser(beforeUserRecord);
        const diff = auditDiff(beforeUser, afterUser, ['name', 'username', 'email', 'whatsapp', 'role', 'dept', 'av', 'avatarUrl', 'active']);
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
    const beforeRows = await sql`SELECT name, username, email, role, dept, whatsapp, av, avatar_url, active FROM users WHERE id=${id}`;
    await sql`UPDATE users SET active=false, updated_at=now() WHERE id=${id}`;
    await sql`DELETE FROM sessions WHERE user_id=${id}`;
    await audit(actor, 'delete', 'user', id, { before: normalizedUser(beforeRows[0]) });
    await touchAppStateMarker(sql);
    const loaded = await loadState();
    return send(res, 200, { ok: true, state: loaded.state, updatedAt: loaded.updatedAt });
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
    const rawPermissions = Array.isArray(body.permissions) ? body.permissions.map(String) : [];
    const adminRoleTarget = SUPER_ADMIN_ROLES.has(name) || (oldName && SUPER_ADMIN_ROLES.has(oldName));
    const permissions = [...new Set(['dashboard', ...rawPermissions.filter(page => adminRoleTarget || !ADMIN_ONLY_PAGES.has(page))])];
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
    await touchAppStateMarker(sql);
    await audit(actor, 'delete', 'role', name, { before: beforeRows[0] || { name } });
    const loaded = await loadState();
    return send(res, 200, { ok: true, state: loaded.state, updatedAt: loaded.updatedAt });
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
        const mode = String(payload.mode || 'document');
        if (mode === 'avatar') {
          const filename = String(payload.filename || 'profile-photo').trim();
          const contentType = String(payload.contentType || '');
          const size = Number(payload.size || 0);
          if (!/^image\/(png|jpe?g|webp)$/.test(contentType)) throw new Error('Foto harus PNG, JPG, atau WebP');
          if (size > 15 * 1024 * 1024) throw new Error('Ukuran foto profil maksimal 15 MB');
          return {
            tokenPayload: JSON.stringify({
              mode,
              filename,
              contentType,
              size,
              userId: user.id,
              userName: user.name,
              userRole: user.role
            })
          };
        }
        const id = String(payload.id || '').trim();
        const filename = String(payload.filename || '').trim();
        const contentType = String(payload.contentType || 'application/octet-stream');
        const size = Number(payload.size || 0);
        const folder = String(payload.folder || 'Dokumen Resmi').trim() || 'Dokumen Resmi';
        const visibility = String(payload.visibility || 'public') === 'important' ? 'important' : 'public';
        const pin = String(payload.pin || '');
        const mirrorDrive = payload.mirrorDrive !== false;
        if (!id || !filename) throw new Error('id dan filename wajib diisi');
        if (visibility === 'important' && !canManageImportantDocuments(user)) throw new Error('Hanya Super Admin/Admin yang boleh membuat dokumen penting');
        if (visibility === 'important' && pin.length < 4) throw new Error('PIN dokumen penting minimal 4 digit/karakter');
        return {
          tokenPayload: JSON.stringify({
            id,
            filename,
            contentType,
            size,
            folder,
            visibility,
            mirrorDrive,
            pinHash: visibility === 'important' ? await hashPassword(pin) : '',
            userId: user.id,
            userName: user.name,
            userRole: user.role
          })
        };
      },
      onUploadCompleted: async ({ blob, tokenPayload }) => {
        const payload = JSON.parse(tokenPayload || '{}');
        if (payload.mode === 'avatar') return;
        const actor = { id: payload.userId, name: payload.userName, role: payload.userRole };
        const previous = await sql`SELECT filename, content_type, blob_url, blob_access, visibility, folder, size, uploaded_by, google_drive_file_id, google_drive_url FROM documents WHERE id=${payload.id}`;
        const access = blob.url && blob.url.includes('.private.blob.vercel-storage.com') ? 'private' : 'public';
        let driveFile = null;
        let driveError = '';
        if (payload.mirrorDrive !== false) {
          try {
            driveFile = await mirrorDocumentToGoogleDrive({
              blobUrl: blob.url,
              blobAccess: access,
              filename: payload.filename,
              contentType: payload.contentType || blob.contentType || 'application/octet-stream',
              folder: payload.folder,
              documentId: payload.id,
              visibility: payload.visibility || 'public'
            });
          } catch (err) {
            driveError = err.message || 'Mirror Google Drive gagal';
            console.warn('google drive mirror gagal', driveError);
          }
        }
        await sql`INSERT INTO documents (id, filename, content_type, blob_url, blob_access, visibility, pin_hash, folder, size, uploaded_by, google_drive_file_id, google_drive_url, uploaded_at) VALUES (${payload.id}, ${payload.filename}, ${payload.contentType || blob.contentType || 'application/octet-stream'}, ${blob.url}, ${access}, ${payload.visibility || 'public'}, ${payload.pinHash || ''}, ${payload.folder || 'Dokumen Resmi'}, ${payload.size || 0}, ${payload.userId}, ${driveFile?.id || ''}, ${driveFile?.webViewLink || ''}, now()) ON CONFLICT (id) DO UPDATE SET filename=EXCLUDED.filename, content_type=EXCLUDED.content_type, blob_url=EXCLUDED.blob_url, blob_access=EXCLUDED.blob_access, visibility=EXCLUDED.visibility, pin_hash=EXCLUDED.pin_hash, folder=EXCLUDED.folder, size=EXCLUDED.size, uploaded_by=EXCLUDED.uploaded_by, google_drive_file_id=EXCLUDED.google_drive_file_id, google_drive_url=EXCLUDED.google_drive_url, ai_summary='', ai_summary_at=NULL, ai_summary_model='', uploaded_at=now()`;
        await audit(actor, previous[0] ? 'replace' : 'upload', 'document', payload.id, { before: previous[0] || null, after: { filename: payload.filename, contentType: payload.contentType || blob.contentType, size: payload.size, folder: payload.folder || 'Dokumen Resmi', visibility: payload.visibility || 'public', blobAccess: access, pinProtected: payload.visibility === 'important', googleDrive: payload.mirrorDrive === false ? 'skipped' : driveFile ? 'mirrored' : (isGoogleDriveConfigured() ? 'mirror_failed' : 'not_configured'), googleDriveFileId: driveFile?.id || '', googleDriveError: driveError } });
      }
    });
    return send(res, 200, jsonResponse);
  }

  if (path === '/documents/drive-status' && method === 'GET') {
    const user = await requireAdmin(req, res);
    if (!user) return;
    try {
      return send(res, 200, await googleDriveStatus());
    } catch (err) {
      return send(res, 200, {
        ready: false,
        state: 'error',
        folderId: process.env.GOOGLE_DRIVE_FOLDER_ID || '',
        serviceAccountEmail: '',
        message: err.message || 'Status Google Drive belum bisa dicek'
      });
    }
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
    const folder = String(body.folder || 'Dokumen Resmi').trim() || 'Dokumen Resmi';
    const visibility = String(body.visibility || 'public').trim() === 'important' ? 'important' : 'public';
    const pin = String(body.pin || '');
    const mirrorDrive = body.mirrorDrive !== false;
    if (!id || !filename || !dataUrl.includes(',')) return send(res, 400, { error: 'id, filename, dan dataUrl wajib diisi' });
    if (visibility === 'important' && !canManageImportantDocuments(user)) return send(res, 403, { error: 'Hanya Super Admin/Admin yang boleh membuat dokumen penting' });
    if (visibility === 'important' && pin.length < 4) return send(res, 400, { error: 'PIN dokumen penting minimal 4 digit/karakter' });
    const buffer = Buffer.from(dataUrl.split(',', 2)[1], 'base64');
    const blobAccess = process.env.DOCUMENT_BLOB_ACCESS || process.env.BLOB_ACCESS || 'public';
    const blob = await put(`grcc/${id}_${filename.replace(/[^A-Za-z0-9._-]+/g, '_')}`, buffer, {
      access: blobAccess === 'private' ? 'private' : 'public',
      contentType
    });
    const previous = await sql`SELECT filename, content_type, blob_url, blob_access, visibility, folder, size, uploaded_by, google_drive_file_id, google_drive_url FROM documents WHERE id=${id}`;
    const pinHash = visibility === 'important' ? await hashPassword(pin) : '';
    let driveFile = null;
    let driveError = '';
    if (mirrorDrive) {
      try {
        driveFile = await mirrorDocumentToGoogleDrive({
          buffer,
          filename,
          contentType,
          folder,
          documentId: id,
          visibility
        });
      } catch (err) {
        driveError = err.message || 'Mirror Google Drive gagal';
        console.warn('google drive mirror gagal', driveError);
      }
    }
    await sql`INSERT INTO documents (id, filename, content_type, blob_url, blob_access, visibility, pin_hash, folder, size, uploaded_by, google_drive_file_id, google_drive_url, uploaded_at) VALUES (${id}, ${filename}, ${contentType}, ${blob.url}, ${blobAccess === 'private' ? 'private' : 'public'}, ${visibility}, ${pinHash}, ${folder}, ${buffer.length}, ${user.id}, ${driveFile?.id || ''}, ${driveFile?.webViewLink || ''}, now()) ON CONFLICT (id) DO UPDATE SET filename=EXCLUDED.filename, content_type=EXCLUDED.content_type, blob_url=EXCLUDED.blob_url, blob_access=EXCLUDED.blob_access, visibility=EXCLUDED.visibility, pin_hash=EXCLUDED.pin_hash, folder=EXCLUDED.folder, size=EXCLUDED.size, uploaded_by=EXCLUDED.uploaded_by, google_drive_file_id=EXCLUDED.google_drive_file_id, google_drive_url=EXCLUDED.google_drive_url, uploaded_at=now()`;
    await audit(user, previous[0] ? 'replace' : 'upload', 'document', id, { before: previous[0] || null, after: { filename, contentType, size: buffer.length, folder, visibility, blobAccess: blobAccess === 'private' ? 'private' : 'public', pinProtected: visibility === 'important', googleDrive: mirrorDrive ? driveFile ? 'mirrored' : (isGoogleDriveConfigured() ? 'mirror_failed' : 'not_configured') : 'skipped', googleDriveFileId: driveFile?.id || '', googleDriveError: driveError } });
    return send(res, 200, { ok: true, downloadUrl: `/api/documents/${encodeURIComponent(id)}/download`, size: buffer.length, googleDriveUrl: driveFile?.webViewLink || '', googleDriveFileId: driveFile?.id || '' });
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
      if (!doc.pin_hash || !await verifyPassword(suppliedPin, doc.pin_hash)) {
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
      const downloadName = safeDownloadName(doc.filename);
      res.setHeader('Content-Type', downloadContentType(doc.filename, blob.contentType, doc.content_type));
      res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"; filename*=UTF-8''${encodeURIComponent(downloadName)}`);
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
    if (!rateLimit(`summary:${user.id}`, 5, 60_000)) {
      return send(res, 429, { error: 'Terlalu banyak permintaan AI summary. Coba lagi dalam 1 menit.' });
    }
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
      if (!doc.pin_hash || !await verifyPassword(suppliedPin, doc.pin_hash)) {
        await audit(user, 'denied', 'document_ai_summary', id, { filename: doc.filename, reason: 'pin_invalid', visibility: doc.visibility });
        return send(res, 403, { error: 'PIN dokumen penting salah' });
      }
    }
    if (doc.ai_summary && !body.refresh) {
      return send(res, 200, { ok: true, summary: doc.ai_summary, model: doc.ai_summary_model || 'cached', cached: true, summarizedAt: doc.ai_summary_at });
    }
    const MAX_SUMMARY_SIZE = 15 * 1024 * 1024; // 15 MB
    if (doc.size && doc.size > MAX_SUMMARY_SIZE) {
      return send(res, 413, { error: 'Ukuran file terlalu besar untuk AI summary (maks 15 MB)' });
    }
    const access = doc.blob_access === 'private' || doc.blob_url.includes('.private.blob.vercel-storage.com') ? 'private' : 'public';
    const blob = await get(doc.blob_url, { access });
    if (!blob || blob.statusCode !== 200 || !blob.stream) return send(res, 404, { error: 'Dokumen tidak ditemukan' });
    const buffer = await streamToBuffer(blob.stream);
    const text = await readableDocumentText(buffer, doc.filename, blob.contentType || doc.content_type);
    if (text.length < 80) return send(res, 422, { error: 'CUK AI belum bisa membaca cukup teks dari dokumen ini. Coba file PDF teks, DOCX teks, TXT, CSV, atau dokumen yang tidak berupa scan gambar.' });
    const result = await summarizeWithCukAI(doc.filename, text);
    await sql`UPDATE documents SET ai_summary=${result.summary}, ai_summary_at=now(), ai_summary_model=${result.model} WHERE id=${id}`;
    await audit(user, 'ai_summary', 'document', id, { filename: doc.filename, model: result.model, visibility: doc.visibility || 'public', textLength: text.length });
    return send(res, 200, { ok: true, summary: result.summary, model: result.model, cached: false, summarizedAt: new Date().toISOString() });
  }

  if (path === '/audit' && method === 'GET') {
    if (!await requireAdmin(req, res)) return;
    const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 200);
    const cursorRaw = url.searchParams.get('cursor');
    const cursor = cursorRaw ? Number(cursorRaw) : null;
    const auditRows = cursor
      ? await sql`SELECT id, actor_id, actor_name, action, entity_type, entity_id, details, created_at FROM audit_log WHERE id < ${cursor} ORDER BY id DESC LIMIT ${limit + 1}`
      : await sql`SELECT id, actor_id, actor_name, action, entity_type, entity_id, details, created_at FROM audit_log ORDER BY id DESC LIMIT ${limit + 1}`;
    const hasMore = auditRows.length > limit;
    const items = hasMore ? auditRows.slice(0, limit) : auditRows;
    const nextCursor = hasMore ? String(items[items.length - 1].id) : null;
    return send(res, 200, { audit: items, hasMore, nextCursor });
  }

  return send(res, 404, { error: 'Endpoint tidak ditemukan' });
}

module.exports = async (req, res) => {
  try {
    await handle(req, res);
  } catch (err) {
    console.error(err);
    const status = err.statusCode === 413 ? 413 : 500;
    send(res, status, { error: err.message || 'Server error' });
  }
};
