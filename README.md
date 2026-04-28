# GRCC Dashboard Backend

Backend untuk dashboard GRCC. Data tidak lagi hanya tersimpan di browser, tetapi disimpan ke SQLite di `data/grcc.sqlite3`, dengan login backend, password hash, audit log, backup otomatis, dan storage dokumen berbasis file.

## Menjalankan

```bash
python3 server.py
```

Buka:

```text
http://127.0.0.1:8000
```

Untuk server/VPS:

```bash
HOST=0.0.0.0 PORT=8000 ADMIN_INITIAL_PASSWORD="ganti-password-kuat" python3 server.py
```

## Deploy Sementara ke Vercel

Paket Vercel sudah disiapkan:

- `vercel.json`
- `package.json`
- `api/index.js`
- `.env.example`
- `docs/VERCEL_DEPLOYMENT.md`

Vercel tidak memakai SQLite lokal. Untuk Vercel, siapkan:

- `DATABASE_URL` dari Neon/Postgres
- `BLOB_READ_WRITE_TOKEN` dari Vercel Blob
- `ADMIN_INITIAL_PASSWORD`

Lihat panduan lengkap di `docs/VERCEL_DEPLOYMENT.md`.

## Endpoint

- `GET /api/health` cek server dan database.
- `GET /api/state` ambil state dashboard dari SQLite.
- `PUT /api/state` simpan state dashboard.
- `POST /api/documents` simpan file upload ke `data/uploads`.
- `GET /api/documents/:id/download` unduh file.
- `POST /api/auth/login` login dan membuat session cookie HttpOnly.
- `POST /api/auth/logout` logout.
- `GET/POST/PUT/DELETE /api/users` manajemen akun Super Admin.
- `GET/POST/PUT/DELETE /api/roles` manajemen role Super Admin.
- `GET /api/audit` melihat 200 audit log terbaru.

## Struktur Database

Tabel utama:

- `users` akun user aktif/nonaktif, password dalam bentuk hash.
- `roles` role dan daftar akses halaman.
- `sessions` sesi login HttpOnly.
- `tasks`, `schedules`, `expenses`, `programs`, `daily_progresses`, `notifications` data per modul.
- `documents` metadata dokumen; file fisik berada di `data/uploads`.
- `audit_log` catatan aksi penting.
- `app_state` preferensi/filter dashboard dan state non-modul.

## Backup

Server membuat backup otomatis harian ke:

```text
data/backups
```

Backup manual:

```bash
python3 scripts/backup_database.py
```

## Reset Database

Untuk mengosongkan data dan kembali ke akun Super Admin awal:

```bash
python3 scripts/reset_database.py
```

Catatan: untuk hosting publik, tetap jalankan di balik HTTPS/reverse proxy dan ganti password admin awal segera.
