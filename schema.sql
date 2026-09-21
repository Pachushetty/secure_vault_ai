-- ============================================================
--  SecureVault — PostgreSQL Schema
--  This runs automatically on app startup (see db.py: init_db()).
--  Kept here for reference / manual setup if you ever need it.
--
--  NOTE: this file must stay in sync with the SCHEMA string and the
--  CREATE TABLE / ALTER TABLE statements inside db.py's init_db().
--  init_db() is the source of truth (it also runs migrations for
--  existing databases); this file is a plain from-scratch mirror of
--  what a brand-new database ends up looking like after init_db()
--  finishes, for anyone who wants to set up the schema by hand.
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    email               TEXT PRIMARY KEY,
    name                TEXT,
    password_hash       TEXT,               -- nullable: Google-only accounts have none
    vault_password_hash TEXT,
    google_id           TEXT UNIQUE,        -- set for accounts linked to Google Sign-In
    profile_picture     TEXT,
    auth_provider       TEXT NOT NULL DEFAULT 'local',
    email_verified      BOOLEAN NOT NULL DEFAULT TRUE,
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
    qr_path      TEXT,
    folder_name  TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_vaults_owner    ON vaults(owner_email);
CREATE INDEX IF NOT EXISTS idx_documents_vault ON documents(vault_id);

-- Sharing
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

-- doc_id / folder_name are both nullable: a row references EITHER a single
-- document OR an entire folder being shared, never both required at once.
CREATE TABLE IF NOT EXISTS shared_items (
    id              SERIAL PRIMARY KEY,
    share_id        TEXT NOT NULL REFERENCES shared_links(share_id) ON DELETE CASCADE,
    doc_id          TEXT REFERENCES documents(doc_id) ON DELETE CASCADE,
    folder_name     TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS share_logs (
    log_id          SERIAL PRIMARY KEY,
    share_id        TEXT NOT NULL REFERENCES shared_links(share_id) ON DELETE CASCADE,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address      TEXT,
    user_agent      TEXT,
    action          TEXT NOT NULL,
    details         TEXT
);

-- General security/audit log — separate from share_logs (which is
-- specifically share-link activity shown to the vault owner). This one is
-- operator-facing: login, Google login, register, logout, upload, delete,
-- share creation, account deletion, etc. NEVER given document contents,
-- passwords, or raw tokens — see log_audit_event() in app.py, which is the
-- only writer.
CREATE TABLE IF NOT EXISTS audit_logs (
    id          SERIAL PRIMARY KEY,
    event_type  TEXT NOT NULL,
    actor_email TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    details     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_type    ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor   ON audit_logs(actor_email);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- Vault AI — Private AI Knowledge Tables
-- All RAG text is stored AES-256-GCM encrypted in chunk_ciphertext / parent_ciphertext.
-- Plaintext chunk_text / parent_text columns have been removed.
-- Key: DOCUMENT_TEXT_ENCRYPTION_KEY env var. See services/crypto_utils.py.
CREATE TABLE IF NOT EXISTS document_chunks (
    id                SERIAL PRIMARY KEY,
    doc_id            TEXT NOT NULL REFERENCES documents(doc_id) ON DELETE CASCADE,
    vault_id          TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    owner_email       TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    chunk_index       INTEGER NOT NULL,
    embedding         TEXT,
    -- parent_index groups child chunks that share one parent section so
    -- results can be de-duplicated per parent before building the LLM prompt.
    parent_index      INTEGER,
    -- AES-256-GCM authenticated-encryption blobs.
    -- Format: base64url( nonce[12] + ciphertext + GCM-tag[16] ).
    -- chunk_ciphertext  = small child chunk used for TF-IDF similarity matching.
    -- parent_ciphertext = larger structural section provided as LLM context.
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

-- AI query history — question and answer stored encrypted.
-- question/answer legacy NOT NULL columns kept with DEFAULT '' for backward compat;
-- production rows use question_ciphertext / answer_ciphertext exclusively.
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


CREATE INDEX IF NOT EXISTS idx_chunks_owner     ON document_chunks(owner_email);
CREATE INDEX IF NOT EXISTS idx_chunks_doc       ON document_chunks(doc_id);
CREATE INDEX IF NOT EXISTS idx_ai_queries_owner ON ai_queries(owner_email);

-- Password reset codes (Forgot Password flow)
CREATE TABLE IF NOT EXISTS password_reset_codes (
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_prc_email ON password_reset_codes(email);

-- Registration Email Verification codes
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evc_email ON email_verification_codes(email);
