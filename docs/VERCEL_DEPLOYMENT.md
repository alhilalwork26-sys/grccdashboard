# Deploy GRCC Dashboard ke Vercel

Vercel cocok untuk frontend dan serverless API, tetapi tidak cocok untuk SQLite lokal dan folder upload lokal. Paket ini menambahkan API serverless di `api/index.js` yang memakai:

- Neon/Postgres melalui `DATABASE_URL`
- Vercel Blob melalui `BLOB_READ_WRITE_TOKEN`

## Langkah Deploy

1. Buat project di Vercel dari folder/repo ini.
2. Di Vercel, buka tab **Storage**.
3. Tambahkan database Postgres dari Marketplace, disarankan Neon.
4. Tambahkan Blob store.
5. Pastikan Environment Variables tersedia:
   - `DATABASE_URL`
   - `BLOB_READ_WRITE_TOKEN`
   - `ADMIN_INITIAL_PASSWORD`
   - `BLOB_ACCESS=public`
6. Deploy.

## Login Awal

- Username: `admin`
- Password: nilai `ADMIN_INITIAL_PASSWORD`

Segera ganti password setelah login.

## Catatan Upload

Upload melalui serverless function punya batas ukuran request. Untuk sementara gunakan file kecil/menengah. Untuk file besar, langkah berikutnya adalah direct client upload ke Vercel Blob.

## Local vs Vercel

- Local: `python3 server.py`, database SQLite, upload di `data/uploads`.
- Vercel: API serverless, Postgres, Vercel Blob.

Jangan membuka `file://.../public/index.html` untuk penggunaan sungguhan. Gunakan URL Vercel atau `http://127.0.0.1:8000/`.
