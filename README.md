# 🔐 SecureVault — Smart Secure Document Vault with Dynamic QR Code Authentication

A full-featured Flask web application for securely storing, organizing, and accessing personal documents via QR code authentication.

---

## ✨ Features

- **Upload any document** — Aadhaar, PAN, Passport, Driving License, Certificates, Medical Records, and more
- **Supported formats**: PDF, JPG, JPEG, PNG (up to 16 MB each)
- **Drag & drop upload** with real-time progress bars
- **Password-protected vaults** with bcrypt hashing
- **Dynamic QR Code** — scan from any device, enter password, access documents
- **Document preview** — images shown inline, PDFs viewable in browser
- **Download individual files** or **combined PDF** of all documents
- **Manage vault** — add or delete documents at any time (QR stays the same)
- **Mobile-friendly** responsive design

---

## 🛠️ Technology Stack

| Layer      | Technology                              |
|------------|----------------------------------------|
| Frontend   | HTML5, CSS3, JavaScript (vanilla)      |
| Backend    | Python 3.10+ / Flask 3.x               |
| Storage    | PostgreSQL                              |
| Libraries  | qrcode, Pillow, ReportLab, Werkzeug    |

---

## 🚀 Quick Start (Local)

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Set up PostgreSQL

Create a local database (or use a free hosted one — see below):

```bash
createdb securevault
```

Then set the `DATABASE_URL` environment variable (copy `.env.example` to `.env`
and edit it, or export directly):

```bash
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/securevault
```

### 3. Run the application

```bash
python app.py
```

Tables are created automatically on first run — no manual schema step needed.

### 4. Open in browser

```
http://localhost:5000
```

---

## 📁 Project Structure

```
vault_project/
├── app.py                  ← Flask application (all routes & logic)
├── db.py                   ← PostgreSQL connection + schema creation
├── migrate_json_to_postgres.py  ← One-time import of old JSON data
├── requirements.txt        ← Python dependencies
├── schema.sql              ← PostgreSQL schema (for reference; auto-run by db.py)
├── .env.example            ← Environment variable template (DATABASE_URL, etc.)
├── README.md               ← This file
├── instance/
│   └── secret.key          ← Local-dev fallback session key (auto-created)
├── static/
│   ├── css/
│   │   └── style.css       ← Complete stylesheet
│   ├── js/
│   │   ├── main.js         ← Shared utilities
│   │   └── upload.js       ← Upload page logic
│   ├── uploads/            ← Stored documents (auto-created)
│   └── qrcodes/            ← Generated QR images (auto-created)
└── templates/
    ├── base.html           ← Base layout
    ├── index.html          ← Home/landing page
    ├── create.html         ← Create vault + upload
    ├── created.html        ← Success + QR code display
    ├── gate.html           ← Password verification page
    ├── vault.html          ← Document vault view
    └── manage.html         ← Add/delete documents
```

---

## 🔒 Security Features

- **Password hashing** — Werkzeug PBKDF2/SHA256 (industry standard)
- **Unique Vault IDs** — `secrets.token_urlsafe(16)` (cryptographically random)
- **No direct file access** — files served through authenticated Flask routes only
- **Session-based auth** — vault unlocks stay valid for the browser session
- **File type validation** — both extension and content checks
- **File size limits** — 16 MB per file
- **SQL injection prevention** — parameterized (`%s`) queries throughout
- **Input sanitization** — `secure_filename()` on all uploads

---

## 🔑 Google Sign-In Setup

Login also supports "Continue with Google" (Google Identity Services) next
to the normal email/password form — either one logs into the same account.

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
   create an **OAuth 2.0 Client ID** of type **Web application**.
2. Under **Authorized JavaScript origins**, add every origin you'll load the
   site from, e.g. `http://localhost:5000` and your production domain.
   (No redirect URI or client secret is needed — this uses the token-based
   Sign In With Google flow, not the redirect-based OAuth code flow.)
3. Copy the generated **Client ID** into `.env`:
   ```
   GOOGLE_CLIENT_ID=xxxxxxxxxx.apps.googleusercontent.com
   ```
4. Restart the app. If `GOOGLE_CLIENT_ID` is unset, the button is simply
   hidden and email/password login works exactly as before.

**How it works:** the browser gets a signed ID token straight from Google
via the `accounts.google.com/gsi/client` script — SecureVault's server
never sees or stores a Google password. That token is POSTed to
`/auth/google`, where `google-auth`'s `verify_oauth2_token()` checks its
signature, audience, issuer and expiry against Google's public keys before
any session is created. First-time Google sign-in creates a `users` row
with `password_hash = NULL` and `auth_provider = 'google'`; signing in
with Google using an email that already has a password account links the
Google ID to that same row instead of creating a duplicate.



1. **Create Vault** → Set name (optional) + password, upload documents
2. **Get QR Code** → Download or save the PNG QR code
3. **Share QR** → Anyone can scan it, but only you know the password
4. **Scan & Authenticate** → Enter password to unlock vault
5. **Access Documents** → View, download individually, or download combined PDF
6. **Manage** → Add or delete documents anytime; QR code never changes

---

## 🗄️ PostgreSQL Setup

The app reads its connection string from the `DATABASE_URL` environment
variable. Tables are created automatically on startup (`db.py: init_db()`),
so there's no manual schema step for a fresh install — `schema.sql` is kept
only as a reference.

Free hosted Postgres options that work well for this app: Render Postgres,
Railway Postgres, Supabase, and Neon. Copy the connection string they give
you into `DATABASE_URL`.

### Migrating existing data from the old JSON file

If you have an existing `instance/vault_data.json` from a previous version
of this app, run the one-time migration script:

```bash
export DATABASE_URL=postgresql://user:pass@host:5432/dbname
python migrate_json_to_postgres.py
```

This copies over users, vaults, and document metadata rows. The actual
uploaded files (in `static/uploads/`) and QR code images (in
`static/qrcodes/`) are files on disk, not database rows — copy those
folders separately to wherever your persistent storage lives.

---

## ☁️ Deployment (Internet)

### Option A: Render.com (free)

1. Push code to GitHub
2. Create a Render Postgres database, copy its connection string
3. Create new Web Service on render.com, point it at the repo
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `gunicorn app:app`
6. Set environment variables: `DATABASE_URL=<your Postgres connection string>` and `FLASK_SECRET_KEY=your-random-key`
7. Attach a persistent disk mounted at `static/uploads` and `static/qrcodes` (or migrate those to object storage) so uploaded files survive redeploys

### Option B: PythonAnywhere

1. Upload project files
2. Set up a WSGI app pointing to `app.py`
3. Install requirements in the console

### Option C: Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]
```

> **Important:** After deployment, regenerate QR codes if the domain changes using the `/vault/<id>/manage` page.

---

## 📋 Database Schema

```
users       → email (PK), name, password_hash, created_at
vaults      → vault_id (PK), vault_name, owner_email (FK → users.email), qr_path, created_at, updated_at
documents   → doc_id (PK), vault_id (FK → vaults.vault_id), filename, stored_name, file_type, file_size, upload_date
```

---

## 📱 QR Code Usage

- The QR code encodes the URL: `https://your-domain.com/vault/<vault_id>`
- Scanning opens the **password gate page**
- No documents are visible until the correct password is entered
- The same QR code works even after adding/deleting documents

---

## 🧑‍💻 Developer Notes

- Change `app.secret_key` in production (use environment variable)
- Set `debug=False` in production
- Use a reverse proxy (nginx/Caddy) for HTTPS
- Store uploaded files on cloud storage (S3) for scalability
