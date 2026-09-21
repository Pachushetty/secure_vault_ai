"""
One-time migration: copies existing data from instance/vault_data.json
into PostgreSQL (set DATABASE_URL first).

Usage:
    export DATABASE_URL=postgresql://user:pass@host:5432/dbname
    python migrate_json_to_postgres.py
"""
import json
import os
import re

import psycopg2

from db import DATABASE_URL, init_db

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'instance', 'vault_data.json')


def _redact_db_url(url):
    """Never print a DB connection string with its password in the clear —
    this script's output can end up in terminal scrollback or copy/pasted
    into a ticket/chat log."""
    if not url:
        return url
    return re.sub(r'(://[^:/@]+:)[^@]+(@)', r'\1***\2', url)


def main():
    if not os.path.exists(DATA_FILE):
        print(f"No {DATA_FILE} found — nothing to migrate.")
        return

    with open(DATA_FILE) as f:
        data = json.load(f)

    users  = data.get('users', {})
    vaults = data.get('vaults', {})

    print(f"Found {len(users)} user(s) and {len(vaults)} vault(s) to migrate.")
    print(f"Target database: {_redact_db_url(DATABASE_URL)}")
    confirm = input("Proceed? [y/N] ").strip().lower()
    if confirm != 'y':
        print("Aborted.")
        return

    init_db()  # make sure tables exist

    conn = psycopg2.connect(DATABASE_URL)
    cur  = conn.cursor()

    for email, u in users.items():
        cur.execute(
            """INSERT INTO users (email, name, password_hash, created_at)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (email) DO NOTHING""",
            (email, u.get('name'), u['password_hash'], u.get('created_at'))
        )

    for vault_id, v in vaults.items():
        cur.execute(
            """INSERT INTO vaults (vault_id, vault_name, owner_email, qr_path,
                                    created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (vault_id) DO NOTHING""",
            (vault_id, v['vault_name'], v['owner_email'], v.get('qr_path'),
             v.get('created_at'), v.get('updated_at'))
        )
        for doc in v.get('documents', []):
            cur.execute(
                """INSERT INTO documents (doc_id, vault_id, filename, stored_name,
                                           file_type, file_size, upload_date)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (doc_id) DO NOTHING""",
                (doc['doc_id'], vault_id, doc['filename'], doc['stored_name'],
                 doc['file_type'], doc.get('file_size', 0), doc.get('upload_date'))
            )

    conn.commit()
    cur.close()
    conn.close()
    print("Migration complete.")
    print("NOTE: file contents themselves (in static/uploads/ and static/qrcodes/) "
          "still need to be copied to wherever the app's persistent storage lives "
          "— this script only migrates the database rows, not the files on disk.")


if __name__ == '__main__':
    main()
