#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "grcc.sqlite3"
UPLOAD_DIR = DATA_DIR / "uploads"
BACKUP_DIR = DATA_DIR / "backups"
MAX_BODY = 50 * 1024 * 1024
SESSION_DAYS = 7
MODULE_TABLES = {
    "tasks": "tasks",
    "schedules": "schedules",
    "expenses": "expenses",
    "programs": "programs",
    "dailyProgresses": "daily_progresses",
    "notifications": "notifications",
}

DEFAULT_PERMS = {
    "Super Admin + Manager": ["dashboard", "tasks", "daily_progress", "schedule", "programs", "finance", "documents", "settings"],
    "Program Admin + Kepala Marketing/Kreatif": ["dashboard", "tasks", "daily_progress", "schedule", "programs", "documents"],
    "Staff Kreatif": ["dashboard", "tasks", "daily_progress", "documents"],
    "Staff Marketing": ["dashboard", "tasks", "daily_progress", "schedule", "documents"],
    "Finance": ["dashboard", "daily_progress", "finance"],
    "Staff Finance + Dokumen": ["dashboard", "daily_progress", "finance", "documents"],
    "Kepala Trainer": ["dashboard", "daily_progress", "schedule", "programs", "documents"],
}
DEFAULT_ROLE_COLORS = {
    "Super Admin + Manager": "#F97316",
    "Program Admin + Kepala Marketing/Kreatif": "#22C55E",
    "Staff Kreatif": "#22C55E",
    "Staff Marketing": "#22C55E",
    "Staff Finance + Dokumen": "#7C3AED",
    "Kepala Trainer": "#7C3AED",
    "Finance": "#34D399",
}
SUPER_ADMIN_ROLES = {"Super Admin", "Super Admin + Manager"}
IMPORTANT_DOC_ROLES = {"Super Admin", "Super Admin + Manager", "Program Admin", "Program Admin + Kepala Marketing/Kreatif"}
LEGACY_ROLE_MIGRATIONS = {
    "Super Admin": "Super Admin + Manager",
    "Program Admin": "Program Admin + Kepala Marketing/Kreatif",
    "Trainer": "Kepala Trainer",
    "Staff": "Staff Marketing",
}
EMPTY_STATE = {
    "userId": None,
    "page": "dashboard",
    "tasks": [],
    "schedules": [],
    "expenses": [],
    "programs": [],
    "docs": [],
    "taskDetail": None,
    "progDetail": None,
    "calMonth": "2026-04-01T00:00:00.000Z",
    "filterTaskStatus": "Semua",
    "filterTaskUser": "Semua",
    "searchTask": "",
    "filterExpStatus": "Semua",
    "filterExpType": "Semua",
    "searchDoc": "",
    "folderDoc": "Semua",
    "notifEmail": True,
    "notifDeadline": True,
    "dailyProgresses": [],
    "filterProgressUser": "Semua",
    "filterProgressStatus": "Semua",
    "filterProgressDate": "",
    "notifications": [],
    "deadlineReminderLog": {},
    "emailIntegration": {
        "enabled": False,
        "provider": "emailjs",
        "serviceId": "",
        "templateId": "",
        "publicKey": "",
        "fallbackTo": "",
        "fromName": "GRCC Dashboard",
    },
}


def now_ts():
    return int(time.time())


def hash_password(password, salt=None, iterations=260_000):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(derived).decode()}"


def verify_password(password, stored):
    try:
        alg, iterations, salt_b64, hash_b64 = stored.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def connect_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            name TEXT PRIMARY KEY,
            permissions TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT '#6B7280',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL REFERENCES roles(name) ON UPDATE CASCADE,
            dept TEXT NOT NULL DEFAULT '',
            av TEXT NOT NULL DEFAULT 'U',
            avatar_url TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    try:
        conn.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError as exc:
        if "duplicate column name" not in str(exc).lower():
            raise
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    ensure_module_tables(conn)
    ensure_documents_table(conn)
    ensure_audit_table(conn)
    seed_defaults(conn)
    migrate_legacy_state_modules(conn)
    conn.commit()
    return conn


def ensure_module_tables(conn):
    for table in MODULE_TABLES.values():
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table} (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def ensure_audit_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id TEXT,
            actor_name TEXT,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def ensure_documents_table(conn):
    existing = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='documents'").fetchone()
    if existing:
        cols = [row["name"] for row in conn.execute("PRAGMA table_info(documents)").fetchall()]
        if "content" in cols:
            migrate_legacy_documents(conn)
            return
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_by TEXT,
            visibility TEXT NOT NULL DEFAULT 'public',
            pin_hash TEXT NOT NULL DEFAULT '',
            ai_summary TEXT NOT NULL DEFAULT '',
            ai_summary_at TEXT,
            ai_summary_model TEXT NOT NULL DEFAULT '',
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cols = [row["name"] for row in conn.execute("PRAGMA table_info(documents)").fetchall()]
    if "visibility" not in cols:
        conn.execute("ALTER TABLE documents ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'")
    if "pin_hash" not in cols:
        conn.execute("ALTER TABLE documents ADD COLUMN pin_hash TEXT NOT NULL DEFAULT ''")
    if "ai_summary" not in cols:
        conn.execute("ALTER TABLE documents ADD COLUMN ai_summary TEXT NOT NULL DEFAULT ''")
    if "ai_summary_at" not in cols:
        conn.execute("ALTER TABLE documents ADD COLUMN ai_summary_at TEXT")
    if "ai_summary_model" not in cols:
        conn.execute("ALTER TABLE documents ADD COLUMN ai_summary_model TEXT NOT NULL DEFAULT ''")


def migrate_legacy_documents(conn):
    old_rows = conn.execute("SELECT id, filename, content_type, content, size, uploaded_at FROM documents").fetchall()
    conn.execute("ALTER TABLE documents RENAME TO documents_legacy_blob")
    conn.execute(
        """
        CREATE TABLE documents (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_by TEXT,
            visibility TEXT NOT NULL DEFAULT 'public',
            pin_hash TEXT NOT NULL DEFAULT '',
            ai_summary TEXT NOT NULL DEFAULT '',
            ai_summary_at TEXT,
            ai_summary_model TEXT NOT NULL DEFAULT '',
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    for row in old_rows:
        path = document_storage_path(row["id"], row["filename"])
        path.write_bytes(row["content"])
        conn.execute(
            """
            INSERT INTO documents (id, filename, content_type, storage_path, size, uploaded_by, visibility, pin_hash, uploaded_at)
            VALUES (?, ?, ?, ?, ?, NULL, 'public', '', ?)
            """,
            (row["id"], row["filename"], row["content_type"], str(path.relative_to(ROOT)), row["size"], row["uploaded_at"]),
        )
    conn.execute("DROP TABLE documents_legacy_blob")


def seed_defaults(conn):
    for role, perms in DEFAULT_PERMS.items():
        conn.execute(
            """
            INSERT INTO roles (name, permissions, color)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                permissions=excluded.permissions,
                color=excluded.color,
                updated_at=CURRENT_TIMESTAMP
            """,
            (role, json.dumps(perms), DEFAULT_ROLE_COLORS.get(role, "#6B7280")),
        )
    for old_role, new_role in LEGACY_ROLE_MIGRATIONS.items():
        conn.execute("UPDATE users SET role=?, updated_at=CURRENT_TIMESTAMP WHERE role=?", (new_role, old_role))
        conn.execute(
            "DELETE FROM roles WHERE name=? AND NOT EXISTS (SELECT 1 FROM users WHERE role=?)",
            (old_role, old_role),
        )
    row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row["c"] == 0:
        conn.execute(
            """
            INSERT INTO users (id, name, username, email, password_hash, role, dept, av)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "owner",
                "Administrator GRCC",
                "admin",
                "admin@grcc.id",
                hash_password(os.environ.get("ADMIN_INITIAL_PASSWORD", "admin12345")),
                "Super Admin + Manager",
                "Manajemen",
                "AG",
            ),
        )
    row = conn.execute("SELECT id FROM app_state WHERE id = 1").fetchone()
    if not row:
        conn.execute(
            "INSERT INTO app_state (id, payload, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)",
            (json.dumps(EMPTY_STATE, ensure_ascii=False),),
        )


def migrate_legacy_state_modules(conn):
    row = conn.execute("SELECT payload FROM app_state WHERE id = 1").fetchone()
    if not row:
        return
    try:
        state = json.loads(row["payload"])
    except json.JSONDecodeError:
        return
    if not isinstance(state, dict):
        return
    has_module_data = any(isinstance(state.get(key), list) and state.get(key) for key in MODULE_TABLES)
    if not has_module_data:
        return
    any_existing = any(conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"] for table in MODULE_TABLES.values())
    if any_existing:
        return
    sync_module_tables(conn, state)
    cleaned = clean_state_for_storage(state)
    conn.execute("UPDATE app_state SET payload = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1", (json.dumps(cleaned, ensure_ascii=False),))


def public_user(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "dept": row["dept"],
        "av": row["av"],
        "avatarUrl": row["avatar_url"] if "avatar_url" in row.keys() else "",
        "active": bool(row["active"]),
    }


def list_users(conn):
    rows = conn.execute(
        "SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE active = 1 ORDER BY name"
    ).fetchall()
    return [public_user(row) for row in rows]


def list_roles(conn):
    rows = conn.execute("SELECT name, permissions, color FROM roles ORDER BY name").fetchall()
    roles = {}
    colors = {}
    for row in rows:
        try:
            roles[row["name"]] = json.loads(row["permissions"])
        except json.JSONDecodeError:
            roles[row["name"]] = ["dashboard"]
        colors[row["name"]] = row["color"]
    return roles, colors


def sync_module_tables(conn, state):
    for state_key, table in MODULE_TABLES.items():
        items = state.get(state_key, [])
        if not isinstance(items, list):
            continue
        incoming_ids = []
        for item in items:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or secrets.token_urlsafe(8))
            item["id"] = item_id
            incoming_ids.append(item_id)
            conn.execute(
                f"""
                INSERT INTO {table} (id, payload, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = CURRENT_TIMESTAMP
                """,
                (item_id, json.dumps(item, ensure_ascii=False)),
            )
        if incoming_ids:
            placeholders = ",".join("?" for _ in incoming_ids)
            conn.execute(f"DELETE FROM {table} WHERE id NOT IN ({placeholders})", incoming_ids)
        else:
            conn.execute(f"DELETE FROM {table}")


def load_module_items(conn, table):
    rows = conn.execute(f"SELECT payload FROM {table} ORDER BY updated_at DESC").fetchall()
    items = []
    for row in rows:
        try:
            item = json.loads(row["payload"])
            if isinstance(item, dict):
                items.append(item)
        except json.JSONDecodeError:
            continue
    return items


def load_state(conn):
    row = conn.execute("SELECT payload, updated_at FROM app_state WHERE id = 1").fetchone()
    state = dict(EMPTY_STATE)
    updated_at = None
    if row:
        updated_at = row["updated_at"]
        try:
            loaded = json.loads(row["payload"])
            if isinstance(loaded, dict):
                state.update(loaded)
        except json.JSONDecodeError:
            pass
    state.pop("accounts", None)
    state.pop("permissions", None)
    state.pop("roleColors", None)
    for state_key, table in MODULE_TABLES.items():
        state[state_key] = load_module_items(conn, table)
    state["accounts"] = list_users(conn)
    roles, colors = list_roles(conn)
    state["permissions"] = roles
    state["roleColors"] = colors
    return state, updated_at


def clean_state_for_storage(state):
    cleaned = dict(state)
    cleaned.pop("accounts", None)
    cleaned.pop("permissions", None)
    cleaned.pop("roleColors", None)
    cleaned.pop("user", None)
    for state_key in MODULE_TABLES:
        cleaned.pop(state_key, None)
    cleaned["serverSavedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return cleaned


def audit(conn, actor, action, entity_type, entity_id=None, details=None):
    conn.execute(
        """
        INSERT INTO audit_log (actor_id, actor_name, action, entity_type, entity_id, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor.get("id") if actor else None,
            actor.get("name") if actor else None,
            action,
            entity_type,
            entity_id,
            json.dumps(details or {}, ensure_ascii=False),
        ),
    )


def normalized_user(row):
    if not row:
        return None
    return {
        "name": row["name"] or "",
        "username": row["username"] or "",
        "email": row["email"] or "",
        "role": row["role"] or "",
        "dept": row["dept"] or "",
        "av": row["av"] or "",
        "avatarUrl": row["avatar_url"] or "",
        "active": bool(row["active"]),
    }


def audit_diff(before, after, fields):
    before = before or {}
    after = after or {}
    before_diff = {}
    after_diff = {}
    for field in fields:
        if before.get(field) != after.get(field):
            before_diff[field] = before.get(field)
            after_diff[field] = after.get(field)
    return {"before": before_diff, "after": after_diff}


def role_snapshot(row):
    if not row:
        return None
    permissions = row["permissions"]
    if isinstance(permissions, str):
        try:
            permissions = json.loads(permissions)
        except json.JSONDecodeError:
            permissions = []
    return {"name": row["name"], "permissions": permissions, "color": row["color"]}


def can_manage_important_documents(user):
    return (user or {}).get("role") in IMPORTANT_DOC_ROLES


def readable_document_text(content, filename, content_type):
    name = str(filename or "").lower()
    ctype = str(content_type or "").lower()
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    if not (ctype.startswith("text/") or re.search(r"\.(txt|md|csv|json|html|xml)$", name)):
        text = re.sub(r"[^\t\n\r -~\u00A0-\uFFFF]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:18000]


def fallback_summary(filename, text):
    sentences = [s.strip() for s in re.findall(r"[^.!?\n]+[.!?]*", text) if len(s.strip()) > 35][:5]
    if not sentences:
        sentences = [text[:450]]
    points = "\n".join(f"{idx + 1}. {sentence[:280]}" for idx, sentence in enumerate(sentences))
    return (
        f'CUK AI membaca dokumen "{filename}" dan membuat ringkasan cepat otomatis.\n\n'
        f"Poin utama:\n{points}\n\n"
        "Catatan: ringkasan ini dibuat dengan mode lokal. Untuk AI penuh, pasang OPENAI_API_KEY di Vercel."
    )


def safe_filename(filename):
    name = Path(filename or "file").name
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "file"


def document_storage_path(doc_id, filename):
    return UPLOAD_DIR / f"{safe_filename(doc_id)}_{safe_filename(filename)}"


def backup_database(reason="daily"):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d")
    path = BACKUP_DIR / f"grcc-{stamp}-{reason}.sqlite3"
    if path.exists():
        return path
    with sqlite3.connect(DB_PATH) as source, sqlite3.connect(path) as target:
        source.backup(target)
    return path


def start_backup_scheduler():
    def worker():
        while True:
            try:
                backup_database("auto")
            except Exception as exc:
                print(f"Backup otomatis gagal: {exc}")
            time.sleep(24 * 60 * 60)

    threading.Thread(target=worker, daemon=True).start()


def json_response(handler, status, payload, cookies=None):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Cache-Control", "no-store")
    if cookies:
        for cookie in cookies:
            handler.send_header("Set-Cookie", cookie)
    handler.end_headers()
    handler.wfile.write(body)


class GRCCHandler(SimpleHTTPRequestHandler):
    server_version = "GRCCBackend/2.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC_DIR), **kwargs)

    def end_headers(self):
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            return json_response(self, HTTPStatus.OK, {"ok": True, "db": str(DB_PATH)})
        if parsed.path == "/api/auth/me":
            return self.auth_me()
        if parsed.path == "/api/state":
            if not self.require_user():
                return
            return self.get_state()
        if parsed.path == "/api/users":
            if not self.require_admin():
                return
            return self.get_users()
        if parsed.path == "/api/roles":
            if not self.require_admin():
                return
            return self.get_roles()
        if parsed.path == "/api/audit":
            if not self.require_admin():
                return
            return self.get_audit()
        if parsed.path.startswith("/api/documents/") and parsed.path.endswith("/download"):
            if not self.require_user():
                return
            return self.download_document(parsed.path)
        return super().do_GET()

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/profile":
            if not self.require_user():
                return
            return self.put_profile()
        if parsed.path == "/api/state":
            if not self.require_user():
                return
            return self.put_state()
        if parsed.path.startswith("/api/users/"):
            if not self.require_admin():
                return
            return self.put_user(parsed.path)
        if parsed.path.startswith("/api/roles/"):
            if not self.require_admin():
                return
            return self.put_role(parsed.path)
        return json_response(self, HTTPStatus.NOT_FOUND, {"error": "Endpoint tidak ditemukan"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/login":
            return self.login()
        if parsed.path == "/api/auth/logout":
            return self.logout()
        if parsed.path == "/api/state":
            if not self.require_user():
                return
            return self.put_state()
        if parsed.path == "/api/documents":
            if not self.require_user():
                return
            return self.post_document()
        if parsed.path.startswith("/api/documents/") and parsed.path.endswith("/summary"):
            if not self.require_user():
                return
            return self.summarize_document(parsed.path)
        if parsed.path == "/api/users":
            if not self.require_admin():
                return
            return self.post_user()
        if parsed.path == "/api/roles":
            if not self.require_admin():
                return
            return self.post_role()
        return json_response(self, HTTPStatus.NOT_FOUND, {"error": "Endpoint tidak ditemukan"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/users/"):
            if not self.require_admin():
                return
            return self.delete_user(parsed.path)
        if parsed.path.startswith("/api/roles/"):
            if not self.require_admin():
                return
            return self.delete_role(parsed.path)
        return json_response(self, HTTPStatus.NOT_FOUND, {"error": "Endpoint tidak ditemukan"})

    def get_cookie_token(self):
        raw = self.headers.get("Cookie", "")
        cookie = SimpleCookie(raw)
        morsel = cookie.get("grcc_session")
        return morsel.value if morsel else None

    def current_user(self):
        token = self.get_cookie_token()
        if not token:
            return None
        with connect_db() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_ts(),))
            row = conn.execute(
                """
                SELECT u.id, u.name, u.username, u.email, u.role, u.dept, u.av, u.avatar_url, u.active
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = ? AND s.expires_at >= ? AND u.active = 1
                """,
                (token, now_ts()),
            ).fetchone()
            conn.commit()
        return public_user(row) if row else None

    def require_user(self):
        self.user = self.current_user()
        if self.user:
            return True
        json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "Sesi tidak valid, silakan login ulang"})
        return False

    def require_admin(self):
        if not self.require_user():
            return False
        if self.user["role"] in SUPER_ADMIN_ROLES:
            return True
        json_response(self, HTTPStatus.FORBIDDEN, {"error": "Hanya Super Admin yang boleh mengakses fitur ini"})
        return False

    def session_cookie(self, token, max_age):
        secure = " Secure;" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return f"grcc_session={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax;{secure}"

    def login(self):
        payload = self.read_json_body()
        if payload is None:
            return
        identifier = str(payload.get("identifier") or "").strip().lower()
        password = str(payload.get("password") or "")
        if not identifier or not password:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Username/email dan password wajib diisi"})
        with connect_db() as conn:
            row = conn.execute(
                """
                SELECT id, name, username, email, password_hash, role, dept, av, active
                FROM users
                WHERE active = 1 AND (lower(username) = ? OR lower(email) = ?)
                """,
                (identifier, identifier),
            ).fetchone()
            if not row or not verify_password(password, row["password_hash"]):
                return json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "Username/email atau password salah"})
            token = secrets.token_urlsafe(32)
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, row["id"], now_ts() + SESSION_DAYS * 86400),
            )
            audit(conn, public_user(row), "login", "session", row["id"])
            state, updated_at = load_state(conn)
            conn.commit()
        user = public_user(row)
        state["userId"] = user["id"]
        return json_response(
            self,
            HTTPStatus.OK,
            {"ok": True, "user": user, "state": state, "updatedAt": updated_at},
            [self.session_cookie(token, SESSION_DAYS * 86400)],
        )

    def logout(self):
        token = self.get_cookie_token()
        with connect_db() as conn:
            if token:
                user = self.current_user()
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                audit(conn, user, "logout", "session", user["id"] if user else None)
            conn.commit()
        return json_response(self, HTTPStatus.OK, {"ok": True}, [self.session_cookie("", 0)])

    def auth_me(self):
        user = self.current_user()
        if not user:
            return json_response(self, HTTPStatus.UNAUTHORIZED, {"error": "Belum login"})
        return json_response(self, HTTPStatus.OK, {"user": user})

    def get_state(self):
        with connect_db() as conn:
            state, updated_at = load_state(conn)
        return json_response(self, HTTPStatus.OK, {"state": state, "updatedAt": updated_at})

    def put_state(self):
        payload = self.read_json_body()
        if payload is None:
            return
        state = payload.get("state")
        if not isinstance(state, dict):
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Field state wajib berupa object"})
        state = clean_state_for_storage(state)
        with connect_db() as conn:
            sync_module_tables(conn, payload.get("state"))
            conn.execute(
                """
                INSERT INTO app_state (id, payload, updated_at)
                VALUES (1, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = CURRENT_TIMESTAMP
                """,
                (json.dumps(state, ensure_ascii=False),),
            )
            audit(conn, self.user, "update", "app_state", "1", {"modules": list(MODULE_TABLES.keys())})
            conn.commit()
        return json_response(self, HTTPStatus.OK, {"ok": True, "savedAt": state["serverSavedAt"]})

    def get_users(self):
        with connect_db() as conn:
            users = list_users(conn)
        return json_response(self, HTTPStatus.OK, {"users": users})

    def post_user(self):
        return self.save_user()

    def put_user(self, path):
        return self.save_user(unquote(path.rsplit("/", 1)[-1]))

    def put_profile(self):
        payload = self.read_json_body()
        if payload is None:
            return
        name = str(payload.get("name") or "").strip()
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        avatar_url = str(payload.get("avatarDataUrl") or payload.get("avatarUrl") or "").strip()
        if not name or not email:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Nama dan email wajib diisi"})
        if avatar_url and not (avatar_url.startswith("data:image/") or avatar_url.startswith("http://") or avatar_url.startswith("https://")):
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Format foto profil tidak valid"})
        if avatar_url.startswith("data:image/") and len(avatar_url) > 2_200_000:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Ukuran foto profil maksimal 1.5 MB"})
        with connect_db() as conn:
            try:
                row = conn.execute("SELECT id, name, username, email, role, dept, av, avatar_url, active, password_hash FROM users WHERE id = ?", (self.user["id"],)).fetchone()
                if not row:
                    return json_response(self, HTTPStatus.NOT_FOUND, {"error": "User tidak ditemukan"})
                before_user = normalized_user(row)
                password_hash = hash_password(password) if password else row["password_hash"]
                if not avatar_url:
                    avatar_url = row["avatar_url"]
                av = initials(name)
                conn.execute(
                    """
                    UPDATE users
                    SET name=?, email=?, password_hash=?, av=?, avatar_url=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (name, email, password_hash, av, avatar_url, self.user["id"]),
                )
                user = conn.execute(
                    "SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE id=?",
                    (self.user["id"],),
                ).fetchone()
                after_user = normalized_user(user)
                diff = audit_diff(before_user, after_user, ["name", "email", "av", "avatarUrl"])
                audit(conn, self.user, "update", "profile", self.user["id"], {**diff, "changed": list(diff["after"].keys()), "passwordChanged": bool(password), "avatarUpdated": bool(payload.get("avatarDataUrl"))})
                conn.commit()
            except sqlite3.IntegrityError:
                return json_response(self, HTTPStatus.CONFLICT, {"error": "Email mungkin sudah digunakan akun lain"})
        return json_response(self, HTTPStatus.OK, {"ok": True, "user": public_user(user)})

    def save_user(self, user_id=None):
        payload = self.read_json_body()
        if payload is None:
            return
        name = str(payload.get("name") or "").strip()
        username = str(payload.get("username") or "").strip().lower()
        email = str(payload.get("email") or "").strip().lower()
        password = str(payload.get("password") or "")
        role = str(payload.get("role") or "Staff Marketing").strip()
        dept = str(payload.get("dept") or "").strip()
        av = str(payload.get("av") or initials(name)).strip()[:3].upper()
        avatar_url = str(payload.get("avatarDataUrl") or payload.get("avatarUrl") or "").strip()
        if avatar_url and not (avatar_url.startswith("data:image/") or avatar_url.startswith("http://") or avatar_url.startswith("https://")):
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Format foto profil tidak valid"})
        if avatar_url.startswith("data:image/") and len(avatar_url) > 2_200_000:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Ukuran foto profil maksimal 1.5 MB"})
        if not name or not username or not email:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Nama, username, dan email wajib diisi"})
        if not user_id and len(password) < 6:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Password minimal 6 karakter"})
        with connect_db() as conn:
            if not conn.execute("SELECT name FROM roles WHERE name = ?", (role,)).fetchone():
                return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Role tidak ditemukan"})
            try:
                if user_id:
                    row = conn.execute("SELECT id, name, username, email, role, dept, av, avatar_url, active, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
                    if not row:
                        return json_response(self, HTTPStatus.NOT_FOUND, {"error": "User tidak ditemukan"})
                    before_user = normalized_user(row)
                    password_hash = hash_password(password) if password else row["password_hash"]
                    if not avatar_url:
                        avatar_url = row["avatar_url"]
                    conn.execute(
                        """
                        UPDATE users
                        SET name=?, username=?, email=?, password_hash=?, role=?, dept=?, av=?, avatar_url=?, updated_at=CURRENT_TIMESTAMP
                        WHERE id=?
                        """,
                        (name, username, email, password_hash, role, dept, av, avatar_url, user_id),
                    )
                else:
                    user_id = secrets.token_urlsafe(8)
                    before_user = None
                    conn.execute(
                        """
                        INSERT INTO users (id, name, username, email, password_hash, role, dept, av, avatar_url)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (user_id, name, username, email, hash_password(password), role, dept, av, avatar_url),
                    )
                row = conn.execute(
                    "SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE id=?",
                    (user_id,),
                ).fetchone()
                after_user = normalized_user(row)
                if before_user:
                    diff = audit_diff(before_user, after_user, ["name", "username", "email", "role", "dept", "av", "avatarUrl", "active"])
                    audit(conn, self.user, "update", "user", user_id, {**diff, "changed": list(diff["after"].keys()), "passwordChanged": bool(password), "avatarUpdated": bool(payload.get("avatarDataUrl"))})
                else:
                    audit(conn, self.user, "create", "user", user_id, {"after": after_user, "passwordSet": True, "avatarUpdated": bool(payload.get("avatarDataUrl"))})
                conn.commit()
            except sqlite3.IntegrityError:
                return json_response(self, HTTPStatus.CONFLICT, {"error": "Username atau email sudah digunakan"})
        return json_response(self, HTTPStatus.OK, {"ok": True, "user": public_user(row)})

    def delete_user(self, path):
        user_id = unquote(path.rsplit("/", 1)[-1])
        if user_id == self.user["id"]:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Tidak bisa menghapus akun sendiri"})
        with connect_db() as conn:
            before = conn.execute("SELECT id, name, username, email, role, dept, av, avatar_url, active FROM users WHERE id = ?", (user_id,)).fetchone()
            conn.execute("UPDATE users SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            audit(conn, self.user, "delete", "user", user_id, {"before": normalized_user(before)})
            conn.commit()
        return json_response(self, HTTPStatus.OK, {"ok": True})

    def get_roles(self):
        with connect_db() as conn:
            roles, colors = list_roles(conn)
        return json_response(self, HTTPStatus.OK, {"permissions": roles, "roleColors": colors})

    def get_audit(self):
        with connect_db() as conn:
            rows = conn.execute(
                """
                SELECT id, actor_id, actor_name, action, entity_type, entity_id, details, created_at
                FROM audit_log
                ORDER BY id DESC
                LIMIT 200
                """
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item["details"] or "{}")
            except json.JSONDecodeError:
                item["details"] = {}
            items.append(item)
        return json_response(self, HTTPStatus.OK, {"audit": items})

    def post_role(self):
        return self.save_role()

    def put_role(self, path):
        return self.save_role(unquote(path.rsplit("/", 1)[-1]))

    def save_role(self, old_name=None):
        payload = self.read_json_body()
        if payload is None:
            return
        name = str(payload.get("name") or "").strip()
        permissions = payload.get("permissions") or ["dashboard"]
        color = str(payload.get("color") or "#6B7280").strip()
        if not name:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Nama role wajib diisi"})
        if not isinstance(permissions, list):
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Permissions wajib berupa array"})
        permissions = list(dict.fromkeys(["dashboard", *[str(p) for p in permissions]]))
        with connect_db() as conn:
            try:
                if old_name and old_name != name:
                    if old_name in SUPER_ADMIN_ROLES:
                        return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Role Super Admin tidak boleh diganti nama"})
                    before_role = role_snapshot(conn.execute("SELECT name, permissions, color FROM roles WHERE name = ?", (old_name,)).fetchone())
                    conn.execute("UPDATE roles SET name=?, permissions=?, color=?, updated_at=CURRENT_TIMESTAMP WHERE name=?", (name, json.dumps(permissions), color, old_name))
                    audit(conn, self.user, "rename", "role", name, {"before": before_role or {"name": old_name}, "after": {"name": name, "permissions": permissions, "color": color}, "oldName": old_name})
                else:
                    before_role = role_snapshot(conn.execute("SELECT name, permissions, color FROM roles WHERE name = ?", (name,)).fetchone())
                    conn.execute(
                        """
                        INSERT INTO roles (name, permissions, color, updated_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(name) DO UPDATE SET
                            permissions=excluded.permissions,
                            color=excluded.color,
                            updated_at=CURRENT_TIMESTAMP
                        """,
                        (name, json.dumps(permissions), color),
                    )
                    after_role = {"name": name, "permissions": permissions, "color": color}
                    if before_role:
                        diff = audit_diff(before_role, after_role, ["name", "permissions", "color"])
                        audit(conn, self.user, "update", "role", name, {**diff, "changed": list(diff["after"].keys())})
                    else:
                        audit(conn, self.user, "create", "role", name, {"after": after_role, "changed": list(after_role.keys())})
                conn.commit()
            except sqlite3.IntegrityError:
                return json_response(self, HTTPStatus.CONFLICT, {"error": "Role tidak bisa disimpan"})
        return json_response(self, HTTPStatus.OK, {"ok": True})

    def delete_role(self, path):
        name = unquote(path.rsplit("/", 1)[-1])
        if name in SUPER_ADMIN_ROLES:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Role Super Admin tidak boleh dihapus"})
        with connect_db() as conn:
            if conn.execute("SELECT id FROM users WHERE role = ? AND active = 1 LIMIT 1", (name,)).fetchone():
                return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Role masih dipakai user"})
            before_role = role_snapshot(conn.execute("SELECT name, permissions, color FROM roles WHERE name = ?", (name,)).fetchone())
            conn.execute("DELETE FROM roles WHERE name = ?", (name,))
            audit(conn, self.user, "delete", "role", name, {"before": before_role or {"name": name}})
            conn.commit()
        return json_response(self, HTTPStatus.OK, {"ok": True})

    def post_document(self):
        payload = self.read_json_body()
        if payload is None:
            return
        doc_id = str(payload.get("id") or "").strip()
        filename = str(payload.get("filename") or "").strip()
        content_type = str(payload.get("contentType") or "application/octet-stream").strip()
        data_url = str(payload.get("dataUrl") or "")
        visibility = "important" if str(payload.get("visibility") or "public").strip() == "important" else "public"
        pin = str(payload.get("pin") or "")
        if not doc_id or not filename or "," not in data_url:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "id, filename, dan dataUrl wajib diisi"})
        if visibility == "important" and not can_manage_important_documents(self.user):
            return json_response(self, HTTPStatus.FORBIDDEN, {"error": "Hanya Super Admin/Admin yang boleh membuat dokumen penting"})
        if visibility == "important" and len(pin) < 4:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "PIN dokumen penting minimal 4 digit/karakter"})
        try:
            content = base64.b64decode(data_url.split(",", 1)[1], validate=True)
        except Exception:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "dataUrl tidak valid"})
        storage_path = document_storage_path(doc_id, filename)
        storage_path.write_bytes(content)
        with connect_db() as conn:
            previous = conn.execute("SELECT filename, content_type AS contentType, storage_path, size, uploaded_by, visibility FROM documents WHERE id = ?", (doc_id,)).fetchone()
            conn.execute(
                """
                INSERT INTO documents (id, filename, content_type, storage_path, size, uploaded_by, visibility, pin_hash, uploaded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    filename = excluded.filename,
                    content_type = excluded.content_type,
                    storage_path = excluded.storage_path,
                    size = excluded.size,
                    uploaded_by = excluded.uploaded_by,
                    visibility = excluded.visibility,
                    pin_hash = excluded.pin_hash,
                    uploaded_at = CURRENT_TIMESTAMP
                """,
                (doc_id, filename, content_type, str(storage_path.relative_to(ROOT)), len(content), self.user["id"], visibility, hash_password(pin) if visibility == "important" else ""),
            )
            before_doc = dict(previous) if previous else None
            audit(conn, self.user, "replace" if previous else "upload", "document", doc_id, {"before": before_doc, "after": {"filename": filename, "contentType": content_type, "size": len(content), "visibility": visibility, "blobAccess": "local-private", "pinProtected": visibility == "important"}})
            conn.commit()
        return json_response(self, HTTPStatus.OK, {"ok": True, "downloadUrl": f"/api/documents/{doc_id}/download", "size": len(content)})

    def download_document(self, path):
        doc_id = unquote(path.removeprefix("/api/documents/").removesuffix("/download"))
        with connect_db() as conn:
            row = conn.execute("SELECT filename, content_type, storage_path, size, visibility, pin_hash FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not row:
            return json_response(self, HTTPStatus.NOT_FOUND, {"error": "Dokumen tidak ditemukan"})
        if row["visibility"] == "important":
            pin = self.headers.get("X-Document-Pin") or parse_qs(urlparse(self.path).query).get("pin", [""])[0]
            if not can_manage_important_documents(self.user):
                with connect_db() as conn:
                    audit(conn, self.user, "denied", "document", doc_id, {"filename": row["filename"], "reason": "role_not_allowed", "visibility": row["visibility"]})
                    conn.commit()
                return json_response(self, HTTPStatus.FORBIDDEN, {"error": "Dokumen penting hanya bisa diakses Super Admin/Admin"})
            if not row["pin_hash"] or not verify_password(pin, row["pin_hash"]):
                with connect_db() as conn:
                    audit(conn, self.user, "denied", "document", doc_id, {"filename": row["filename"], "reason": "pin_invalid", "visibility": row["visibility"]})
                    conn.commit()
                return json_response(self, HTTPStatus.FORBIDDEN, {"error": "PIN dokumen penting salah"})
        file_path = ROOT / row["storage_path"]
        if not file_path.exists():
            return json_response(self, HTTPStatus.NOT_FOUND, {"error": "File dokumen tidak ditemukan di storage"})
        content_type = row["content_type"] or mimetypes.guess_type(row["filename"])[0] or "application/octet-stream"
        with connect_db() as conn:
            audit(conn, self.user, "download", "document", doc_id, {"filename": row["filename"], "size": row["size"], "visibility": row["visibility"], "accessChecked": True})
            conn.commit()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(row["size"]))
        self.send_header("Content-Disposition", f'attachment; filename="{row["filename"]}"')
        self.end_headers()
        with file_path.open("rb") as f:
            shutil.copyfileobj(f, self.wfile)

    def summarize_document(self, path):
        doc_id = unquote(path.removeprefix("/api/documents/").removesuffix("/summary"))
        payload = self.read_json_body()
        if payload is None:
            return
        refresh = bool(payload.get("refresh"))
        pin = str(payload.get("pin") or self.headers.get("X-Document-Pin") or "")
        with connect_db() as conn:
            row = conn.execute(
                "SELECT filename, content_type, storage_path, size, visibility, pin_hash, ai_summary, ai_summary_at, ai_summary_model FROM documents WHERE id = ?",
                (doc_id,),
            ).fetchone()
            if not row:
                return json_response(self, HTTPStatus.NOT_FOUND, {"error": "Dokumen tidak ditemukan"})
            if row["visibility"] == "important":
                if not can_manage_important_documents(self.user):
                    audit(conn, self.user, "denied", "document_ai_summary", doc_id, {"filename": row["filename"], "reason": "role_not_allowed", "visibility": row["visibility"]})
                    conn.commit()
                    return json_response(self, HTTPStatus.FORBIDDEN, {"error": "Dokumen penting hanya bisa diringkas Super Admin/Admin"})
                if not row["pin_hash"] or not verify_password(pin, row["pin_hash"]):
                    audit(conn, self.user, "denied", "document_ai_summary", doc_id, {"filename": row["filename"], "reason": "pin_invalid", "visibility": row["visibility"]})
                    conn.commit()
                    return json_response(self, HTTPStatus.FORBIDDEN, {"error": "PIN dokumen penting salah"})
            if row["ai_summary"] and not refresh:
                return json_response(self, HTTPStatus.OK, {"ok": True, "summary": row["ai_summary"], "model": row["ai_summary_model"] or "cached", "cached": True, "summarizedAt": row["ai_summary_at"]})
            file_path = ROOT / row["storage_path"]
            if not file_path.exists():
                return json_response(self, HTTPStatus.NOT_FOUND, {"error": "File dokumen tidak ditemukan di storage"})
            text = readable_document_text(file_path.read_bytes(), row["filename"], row["content_type"])
            if len(text) < 80:
                return json_response(self, HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "CUK AI belum bisa membaca cukup teks dari dokumen ini."})
            summary = fallback_summary(row["filename"], text)
            conn.execute(
                "UPDATE documents SET ai_summary=?, ai_summary_at=CURRENT_TIMESTAMP, ai_summary_model=? WHERE id=?",
                (summary, "cuk-ai-local", doc_id),
            )
            audit(conn, self.user, "ai_summary", "document", doc_id, {"filename": row["filename"], "model": "cuk-ai-local", "visibility": row["visibility"], "textLength": len(text)})
            conn.commit()
        return json_response(self, HTTPStatus.OK, {"ok": True, "summary": summary, "model": "cuk-ai-local", "cached": False, "summarizedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Content-Length tidak valid"})
        if length <= 0 or length > MAX_BODY:
            return json_response(self, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Payload terlalu besar"})
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            json_response(self, HTTPStatus.BAD_REQUEST, {"error": "JSON tidak valid"})
            return None


def initials(name):
    letters = [part[0] for part in str(name or "User").split() if part]
    return "".join(letters)[:2].upper() or "U"


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    connect_db().close()
    backup_database("startup")
    start_backup_scheduler()
    server = ThreadingHTTPServer((host, port), GRCCHandler)
    print(f"GRCC dashboard berjalan di http://{host}:{port}")
    print(f"Database: {DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
