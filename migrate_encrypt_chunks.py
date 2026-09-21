"""
migrate_encrypt_chunks.py — Backfill AES-256-GCM encryption for existing
document_chunks rows that were indexed before DOCUMENT_TEXT_ENCRYPTION_KEY
was introduced.

Usage:
    python migrate_encrypt_chunks.py

Requirements:
    - DOCUMENT_TEXT_ENCRYPTION_KEY must be set in the environment (or .env).
    - DATABASE_URL must be set.
    - Run this ONCE after deploying the new crypto_utils.py / vector_search.py.
    - Safe to re-run: already-encrypted rows (chunk_ciphertext IS NOT NULL) are skipped.

Security contract:
    - Plaintext chunk content is NEVER printed to stdout/stderr or written to logs.
    - Only row counts and record IDs are emitted.
    - The encryption key is never printed.

Pagination:
    Uses keyset pagination (WHERE id > last_processed_id ORDER BY id LIMIT N)
    rather than OFFSET to avoid the classic OFFSET-skip-under-modification bug.

Transaction contract per batch:
    BEGIN
      → read plaintext
      → encrypt in-memory
      → UPDATE: write ciphertext, verify it exists, clear plaintext
    COMMIT   (only if every row in the batch succeeded)
    ROLLBACK (if any row in the batch failed — plaintext preserved for retry)

    Plaintext is NEVER cleared before the ciphertext column has been verified
    to contain the encrypted value.

NOTE: chunk_text / parent_text columns may have already been dropped.
      If those columns do not exist in the current schema this script will
      report "nothing to migrate" and exit cleanly.
"""

import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import psycopg2
import psycopg2.extras

from services.crypto_utils import encrypt_text, TEXT_ENCRYPTION_AVAILABLE
from db import DATABASE_URL

BATCH_SIZE = 100


def _columns_exist(conn, table: str, *col_names: str) -> bool:
    """Return True only if ALL specified columns exist on the table."""
    cur = conn.cursor()
    cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = %s",
        (table,)
    )
    existing = {r['column_name'] for r in cur.fetchall()}
    cur.close()
    return all(c in existing for c in col_names)


def run_migration():
    if not TEXT_ENCRYPTION_AVAILABLE:
        print(
            "[ERROR] DOCUMENT_TEXT_ENCRYPTION_KEY is not set or invalid.\n"
            "        Set the variable and re-run this script.\n"
            "        Generate a key with:\n"
            "          python -c \"import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())\""
        )
        sys.exit(1)

    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = False   # explicit transaction control for each batch

    # Check whether plaintext columns still exist (they may have been dropped).
    if not _columns_exist(conn, 'document_chunks', 'chunk_text'):
        print(
            "[OK] chunk_text column does not exist — plaintext columns already removed.\n"
            "     Nothing to migrate."
        )
        conn.close()
        return

    cur = conn.cursor()

    # Count rows that still need migration.
    cur.execute("""
        SELECT COUNT(*) AS total
        FROM document_chunks
        WHERE chunk_ciphertext IS NULL
          AND chunk_text IS NOT NULL
          AND chunk_text <> ''
    """)
    total = cur.fetchone()['total']

    if total == 0:
        print("[OK] No plaintext chunks found — nothing to migrate.")
        print("     (All rows are already encrypted or have no text content.)")
        conn.close()
        return

    print(f"[INFO] Found {total} chunk row(s) with plaintext to encrypt.")
    print(f"[INFO] Processing in batches of {BATCH_SIZE} using keyset pagination...")
    print()

    migrated    = 0
    failed_rows = 0
    last_id     = 0   # keyset cursor

    while True:
        # ── Read next batch (keyset pagination — safe under concurrent writes) ──
        cur.execute("""
            SELECT id, chunk_text, parent_text
            FROM document_chunks
            WHERE chunk_ciphertext IS NULL
              AND chunk_text IS NOT NULL
              AND chunk_text <> ''
              AND id > %s
            ORDER BY id
            LIMIT %s
        """, (last_id, BATCH_SIZE))
        batch = cur.fetchall()
        if not batch:
            break

        # ── Encrypt each row in-memory before touching the DB ──────────────────
        updates = []
        batch_failed = 0
        for row in batch:
            chunk_id     = row['id']
            chunk_plain  = row['chunk_text']
            parent_plain = row.get('parent_text')

            try:
                chunk_cipher  = encrypt_text(chunk_plain)
                parent_cipher = encrypt_text(parent_plain) if parent_plain else None
                updates.append((chunk_cipher, parent_cipher, chunk_id))
                last_id = chunk_id
            except Exception as exc:
                # Log only chunk_id and exception type — NEVER the plaintext.
                print(f"[WARN] Encryption failed for chunk_id={chunk_id}: {type(exc).__name__} — skipping row.")
                last_id = chunk_id
                batch_failed += 1

        if not updates:
            failed_rows += batch_failed
            continue

        # ── Single transaction: write ciphertext + verify + clear plaintext ────
        try:
            for chunk_cipher, parent_cipher, chunk_id in updates:
                cur.execute("""
                    UPDATE document_chunks
                    SET chunk_ciphertext  = %s,
                        parent_ciphertext = %s,
                        chunk_text        = '',
                        parent_text       = ''
                    WHERE id = %s
                """, (chunk_cipher, parent_cipher, chunk_id))

                # Verify the ciphertext was written before we clear plaintext.
                cur.execute(
                    "SELECT chunk_ciphertext FROM document_chunks WHERE id = %s",
                    (chunk_id,)
                )
                verify = cur.fetchone()
                if not verify or not verify['chunk_ciphertext']:
                    raise RuntimeError(
                        f"Verification failed for chunk_id={chunk_id}: "
                        "chunk_ciphertext is NULL after UPDATE."
                    )

            conn.commit()
            migrated     += len(updates)
            failed_rows  += batch_failed
            print(f"       ...encrypted {migrated}/{total} rows")

        except Exception as exc:
            conn.rollback()
            # Log only exception type — rollback preserves plaintext for retry.
            print(
                f"[ERROR] Batch transaction rolled back: {type(exc).__name__}.\n"
                "        Plaintext preserved — re-run this script to retry."
            )
            failed_rows += len(updates) + batch_failed
            # Advance last_id to skip past this batch (avoid infinite loop).
            if updates:
                last_id = updates[-1][2]

    conn.close()

    print()
    print("─" * 55)
    print("Migration complete.")
    print(f"  Encrypted successfully : {migrated}")
    print(f"  Failed / skipped       : {failed_rows}")
    print()

    if failed_rows > 0:
        print("[WARN] Some rows could not be encrypted — re-run this script to retry.")
    else:
        print("[OK] All plaintext chunks encrypted successfully.")
        print()
        print("Next step: drop the now-empty legacy plaintext columns:")
        print("  python -c \"")
        print("    from db import DATABASE_URL; import psycopg2")
        print("    conn = psycopg2.connect(DATABASE_URL)")
        print("    cur = conn.cursor()")
        print("    cur.execute('ALTER TABLE document_chunks DROP COLUMN chunk_text')")
        print("    cur.execute('ALTER TABLE document_chunks DROP COLUMN parent_text')")
        print("    conn.commit()")
        print("  \"")


if __name__ == '__main__':
    run_migration()
