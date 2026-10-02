"""
Re-index all image documents for a user using the improved Groq Vision OCR.
This will re-run OCR on all JPEG/PNG documents and update the stored chunks.

Usage:
    python reindex_images.py [owner_email]
    
If owner_email is not provided, re-indexes ALL image documents for ALL users.
"""
import os, sys, logging
sys.path.insert(0, r'c:\Users\hemal\Downloads\secure_vault_ai\vault')

# Load .env
with open(r'c:\Users\hemal\Downloads\secure_vault_ai\vault\.env') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ[k] = v

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

import psycopg2
import psycopg2.extras

from services.indexer import index_document

conn = psycopg2.connect(os.environ['DATABASE_URL'], cursor_factory=psycopg2.extras.RealDictCursor)
cur = conn.cursor()

# Find all image documents
image_types = ('jpg', 'jpeg', 'png', 'bmp', 'webp', 'tiff', 'jfif')
placeholders = ','.join(['%s'] * len(image_types))

owner_filter = sys.argv[1] if len(sys.argv) > 1 else None

if owner_filter:
    cur.execute(f"""
        SELECT d.doc_id, d.vault_id, d.filename, v.owner_email
        FROM documents d
        JOIN vaults v ON d.vault_id = v.vault_id
        WHERE LOWER(d.file_type) IN ({placeholders})
        AND v.owner_email = %s
        ORDER BY d.upload_date DESC
    """, image_types + (owner_filter,))
else:
    cur.execute(f"""
        SELECT d.doc_id, d.vault_id, d.filename, v.owner_email
        FROM documents d
        JOIN vaults v ON d.vault_id = v.vault_id
        WHERE LOWER(d.file_type) IN ({placeholders})
        ORDER BY d.upload_date DESC
    """, image_types)

docs = cur.fetchall()
cur.close()
conn.close()

print(f'Found {len(docs)} image documents to re-index')
for d in docs:
    print(f'  - {d["filename"]} (doc_id={d["doc_id"]}, owner={d["owner_email"]})')

print()

success = 0
failed = 0
for d in docs:
    print(f'\n[RE-INDEXING] {d["filename"]} (doc_id={d["doc_id"]})...')
    ok = index_document(d['doc_id'], d['vault_id'], d['owner_email'])
    if ok:
        print(f'  SUCCESS')
        success += 1
    else:
        print(f'  FAILED')
        failed += 1

print(f'\n\nDone: {success} succeeded, {failed} failed out of {len(docs)} documents.')
