"""
PostgreSQL connection layer for SecureVault.

Reads the connection string from the DATABASE_URL environment variable.
Works out of the box with Render, Railway, Supabase, Neon, ElephantSQL,
or a local Postgres instance.

Example DATABASE_URL:
    postgresql://user:password@host:5432/dbname
"""
import os
import sys
from datetime import datetime

import psycopg2
import psycopg2.extras
from flask import g

try:
    from dotenv import load_dotenv
    load_dotenv()  # reads a .env file in the project folder, if present
except ImportError:
    pass  # python-dotenv not installed; DATABASE_URL must be set another way

DATABASE_URL = os.environ.get('DATABASE_URL')

if not DATABASE_URL:
    print(
        "\n"
        "ERROR: DATABASE_URL is not set.\n"
        "Fix: copy .env.example to .env in this same folder, then edit .env\n"
        "and set DATABASE_URL to your real Postgres connection string.\n"
        "Example: DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/securevault\n",
        file=sys.stderr
    )
    sys.exit(1)

# Render/Railway/Heroku-style URLs sometimes start with "postgres://",
# but psycopg2 requires "postgresql://".
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)


def get_db():
    """Return a request-scoped connection, opening one if needed."""
    if 'db' not in g:
        g.db = psycopg2.connect(
            DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
    return g.db


def close_db(app):
    """Register teardown so the connection closes at the end of each request."""
    @app.teardown_appcontext
    def _close(exception=None):
        db = g.pop('db', None)
        if db is not None:
            if exception is None:
                db.commit()
            else:
                db.rollback()
            db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email               TEXT PRIMARY KEY,
    name                TEXT,
    password_hash       TEXT,
    google_id           TEXT UNIQUE,
    profile_picture     TEXT,
    auth_provider       TEXT NOT NULL DEFAULT 'local',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vaults (
    vault_id     TEXT PRIMARY KEY,
    vault_name   TEXT NOT NULL,
    owner_email  TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    qr_path      TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS documents (
    doc_id       TEXT PRIMARY KEY,
    vault_id     TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    stored_name  TEXT NOT NULL,
    file_type    TEXT NOT NULL,
    file_size    BIGINT NOT NULL DEFAULT 0,
    upload_date  TIMESTAMPTZ NOT NULL DEFAULT now(),
    access_type  TEXT NOT NULL DEFAULT 'public',
    access_code  TEXT,
    expires_at   TIMESTAMPTZ,
    view_limit   INTEGER,
    view_count   INTEGER NOT NULL DEFAULT 0,
    qr_path      TEXT
);

CREATE INDEX IF NOT EXISTS idx_vaults_owner    ON vaults(owner_email);
CREATE INDEX IF NOT EXISTS idx_documents_vault ON documents(vault_id);
"""


def init_db():
    """Create tables if they don't exist yet. Safe to call on every startup."""
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    except psycopg2.OperationalError as e:
        print(
            "\n"
            "ERROR: Could not connect to PostgreSQL.\n"
            f"DATABASE_URL currently points to: {DATABASE_URL}\n"
            "Common fixes:\n"
            "  - Wrong password/username -> check the DATABASE_URL value in your .env file\n"
            "  - Postgres isn't running -> start the PostgreSQL service\n"
            "  - Database doesn't exist yet -> create it (e.g. `createdb securevault`)\n"
            f"\nOriginal error: {e}",
            file=sys.stderr
        )
        sys.exit(1)
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
            
            # Run ALTER TABLE commands to migrate existing database setups
            # Folder Master Password feature removed — drop the column (and
            # any stored hashes) from databases created before this change.
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='vault_password_hash'")
            if cur.fetchone():
                cur.execute("ALTER TABLE users DROP COLUMN vault_password_hash")

            # Google Sign-In support: password_hash must become optional
            # (Google-only accounts have none), plus the new identity columns.
            cur.execute("""
                SELECT is_nullable FROM information_schema.columns
                WHERE table_name='users' AND column_name='password_hash'
            """)
            row = cur.fetchone()
            if row and row['is_nullable'] == 'NO':
                cur.execute("ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL")

            user_columns_to_add = [
                ('google_id', 'TEXT'),
                ('profile_picture', 'TEXT'),
                ('auth_provider', "TEXT NOT NULL DEFAULT 'local'"),
                # Records when the user agreed to the Terms of Service /
                # Privacy Policy at registration, and which version they
                # accepted, for consent record-keeping.
                ('terms_accepted_at', 'TIMESTAMPTZ'),
                ('terms_version', 'TEXT'),
            ]
            for col_name, col_def in user_columns_to_add:
                cur.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='{col_name}'")
                if not cur.fetchone():
                    cur.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

            cur.execute("""
                SELECT indexname FROM pg_indexes
                WHERE tablename='users' AND indexname='users_google_id_key'
            """)
            if not cur.fetchone():
                cur.execute("ALTER TABLE users ADD CONSTRAINT users_google_id_key UNIQUE (google_id)")
                
            columns_to_add = [
                ('access_type', "TEXT NOT NULL DEFAULT 'public'"),
                ('access_code', 'TEXT'),
                ('expires_at', 'TIMESTAMPTZ'),
                ('view_limit', 'INTEGER'),
                ('view_count', 'INTEGER NOT NULL DEFAULT 0'),
                ('qr_path', 'TEXT'),
                ('folder_name', 'TEXT DEFAULT NULL')
            ]
            for col_name, col_def in columns_to_add:
                cur.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name='documents' AND column_name='{col_name}'")
                if not cur.fetchone():
                    cur.execute(f"ALTER TABLE documents ADD COLUMN {col_name} {col_def}")
            
            # Create shared_links
            cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_links (
                share_id        TEXT PRIMARY KEY,
                vault_id        TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
                password_hash   TEXT DEFAULT NULL,
                allow_download  BOOLEAN NOT NULL DEFAULT TRUE,
                allow_printing  BOOLEAN NOT NULL DEFAULT TRUE,
                view_limit      INTEGER DEFAULT NULL,
                view_count      INTEGER NOT NULL DEFAULT 0,
                expires_at      TIMESTAMPTZ DEFAULT NULL,
                qr_path         TEXT,
                is_revoked      BOOLEAN NOT NULL DEFAULT FALSE,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """)

            # Create shared_items
            cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_items (
                id              SERIAL PRIMARY KEY,
                share_id        TEXT NOT NULL REFERENCES shared_links(share_id) ON DELETE CASCADE,
                doc_id          TEXT REFERENCES documents(doc_id) ON DELETE CASCADE,
                folder_name     TEXT DEFAULT NULL
            );
            """)

            # ── Migration: fix shared_items if it was created with composite PK
            #    and NOT NULL constraints on doc_id / folder_name
            # ----------------------------------------------------------------
            # Check if the id column exists
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'shared_items' AND column_name = 'id'
            """)
            if not cur.fetchone():
                # Old schema: composite PK (share_id, doc_id, folder_name), no id column.
                # We need to recreate the table with nullable doc_id/folder_name.
                cur.execute("ALTER TABLE shared_items DROP CONSTRAINT IF EXISTS shared_items_pkey CASCADE")
                cur.execute("ALTER TABLE shared_items DROP CONSTRAINT IF EXISTS shared_items_doc_id_not_null CASCADE")
                cur.execute("ALTER TABLE shared_items DROP CONSTRAINT IF EXISTS shared_items_folder_name_not_null CASCADE")
                cur.execute("ALTER TABLE shared_items ALTER COLUMN doc_id DROP NOT NULL")
                cur.execute("ALTER TABLE shared_items ALTER COLUMN folder_name DROP NOT NULL")
                cur.execute("ALTER TABLE shared_items ADD COLUMN IF NOT EXISTS id SERIAL")
                cur.execute("ALTER TABLE shared_items ADD PRIMARY KEY (id)")
            else:
                # id column exists; ensure doc_id and folder_name allow NULLs
                cur.execute("ALTER TABLE shared_items ALTER COLUMN doc_id DROP NOT NULL")
                cur.execute("ALTER TABLE shared_items ALTER COLUMN folder_name DROP NOT NULL")

            # Create share_logs
            cur.execute("""
            CREATE TABLE IF NOT EXISTS share_logs (
                log_id          SERIAL PRIMARY KEY,
                share_id        TEXT NOT NULL REFERENCES shared_links(share_id) ON DELETE CASCADE,
                scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                ip_address      TEXT,
                user_agent      TEXT,
                action          TEXT NOT NULL,
                details         TEXT
            );
            """)

            # General security/audit log — separate from share_logs (which is
            # specifically share-link activity shown to the vault owner).
            # This one is operator-facing: login, Google login, register,
            # logout, upload, delete, share creation, account deletion, etc.
            # NEVER given document contents, passwords, or raw tokens — see
            # log_audit_event() in app.py, which is the only writer.
            cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id          SERIAL PRIMARY KEY,
                event_type  TEXT NOT NULL,
                actor_email TEXT,
                ip_address  TEXT,
                user_agent  TEXT,
                details     TEXT,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_type ON audit_logs(event_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_email)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)")

            # Vault AI — Private AI Knowledge Tables
            # NOTE: chunk_text/parent_text plaintext columns removed — all RAG text
            # is stored encrypted via chunk_ciphertext/parent_ciphertext (AES-256-GCM).
            cur.execute("""
CREATE TABLE IF NOT EXISTS document_chunks (
    id                SERIAL PRIMARY KEY,
    doc_id            TEXT NOT NULL REFERENCES documents(doc_id) ON DELETE CASCADE,
    vault_id          TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    owner_email       TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    chunk_index       INTEGER NOT NULL,
    embedding         TEXT,
    parent_index      INTEGER,
    chunk_ciphertext  TEXT,
    parent_ciphertext TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

            CREATE TABLE IF NOT EXISTS document_indexing_status (
                doc_id        TEXT PRIMARY KEY REFERENCES documents(doc_id) ON DELETE CASCADE,
                status        TEXT NOT NULL DEFAULT 'pending',
                error_message TEXT,
                updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            -- ai_queries: sensitive question/answer stored in encrypted columns.
            -- question/answer/source_documents legacy NOT NULL columns kept for
            -- installs that predate encryption; migrate_encrypt_ai_history.py clears them.
            CREATE TABLE IF NOT EXISTS ai_queries (
                id                  SERIAL PRIMARY KEY,
                owner_email         TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
                question            TEXT NOT NULL DEFAULT '',
                answer              TEXT NOT NULL DEFAULT '',
                source_documents    TEXT DEFAULT '[]',
                question_ciphertext TEXT,
                answer_ciphertext   TEXT,
                sources_ciphertext  TEXT,
                created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE INDEX IF NOT EXISTS idx_chunks_owner    ON document_chunks(owner_email);
            CREATE INDEX IF NOT EXISTS idx_chunks_doc      ON document_chunks(doc_id);
            CREATE INDEX IF NOT EXISTS idx_ai_queries_owner ON ai_queries(owner_email);
            """)

            # Ensure encrypted RAG columns exist (idempotent ADD COLUMN IF NOT EXISTS).
            # chunk_text/parent_text plaintext columns have been dropped; only
            # the encrypted ciphertext columns are maintained.
            for col_name, col_def in [
                ('parent_index',      'INTEGER'),
                ('chunk_ciphertext',  'TEXT'),
                ('parent_ciphertext', 'TEXT'),
            ]:
                cur.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='document_chunks' AND column_name=%s",
                    (col_name,)
                )
                if not cur.fetchone():
                    cur.execute(f"ALTER TABLE document_chunks ADD COLUMN {col_name} {col_def}")

            # Ensure ai_queries encrypted columns exist.
            for col_name, col_def in [
                ('question_ciphertext', 'TEXT'),
                ('answer_ciphertext',   'TEXT'),
                ('sources_ciphertext',  'TEXT'),
            ]:
                cur.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='ai_queries' AND column_name=%s",
                    (col_name,)
                )
                if not cur.fetchone():
                    cur.execute(f"ALTER TABLE ai_queries ADD COLUMN {col_name} {col_def}")


            # ── Password reset codes (Forgot Password flow) ─────────────
            cur.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_codes (
                id          SERIAL PRIMARY KEY,
                email       TEXT NOT NULL,
                code_hash   TEXT NOT NULL,
                expires_at  TIMESTAMPTZ NOT NULL,
                attempts    INTEGER NOT NULL DEFAULT 0,
                used        BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_prc_email ON password_reset_codes(email)"
            )

            # ── User Email Verification Migration & Table ───────────────
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name='users' AND column_name='email_verified'
            """)
            if not cur.fetchone():
                cur.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT TRUE")

            cur.execute("""
            CREATE TABLE IF NOT EXISTS email_verification_codes (
                id          SERIAL PRIMARY KEY,
                email       TEXT NOT NULL,
                code_hash   TEXT NOT NULL,
                expires_at  TIMESTAMPTZ NOT NULL,
                attempts    INTEGER NOT NULL DEFAULT 0,
                used        BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_evc_email ON email_verification_codes(email)"
            )

        conn.commit()
    finally:
        conn.close()



def to_iso(row):
    """Convert a RealDictRow's datetime fields to ISO strings (templates
    expect plain strings, e.g. vault.created_at[:10])."""
    if row is None:
        return None
    row = dict(row)
    for k, v in row.items():
        if isinstance(v, datetime):
            row[k] = v.isoformat()
    return row


def to_iso_all(rows):
    return [to_iso(r) for r in rows]
