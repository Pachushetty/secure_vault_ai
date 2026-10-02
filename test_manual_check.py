import os, uuid, sys
from app import app
from db import get_db, init_db
from services.blob_storage import blob_put
from services.crypto_utils import encrypt_bytes
from services.indexer import index_document
from services.ai_service import ask_vault_ai, expand_query
from services.vector_search import query_similar_chunks

sys.stdout.reconfigure(encoding='utf-8')

test_email = 'test_pu_bca@securevault.ai'
vault_id = 'v_' + uuid.uuid4().hex[:8]
bca_id = uuid.uuid4().hex
pu_id = uuid.uuid4().hex

with app.app_context():
    init_db()
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM users WHERE email = %s', (test_email,))
    cur.execute('INSERT INTO users (email, name, password_hash, email_verified) VALUES (%s, %s, %s, TRUE)',
                (test_email, 'Tester', 'hash'))
    cur.execute('INSERT INTO vaults (vault_id, vault_name, owner_email, qr_path) VALUES (%s, %s, %s, %s)',
                (vault_id, 'Docs', test_email, '/static/test.png'))
    with open(r'c:\Users\hemal\Downloads\BCA.jpeg', 'rb') as f:
        bca_bytes = f.read()
    with open(r'c:\Users\hemal\Downloads\PU.jpeg', 'rb') as f:
        pu_bytes = f.read()
    blob_put(f'uploads/{vault_id}/bca.jpeg', encrypt_bytes(bca_bytes))
    blob_put(f'uploads/{vault_id}/pu.jpeg', encrypt_bytes(pu_bytes))
    cur.execute('''
        INSERT INTO documents (doc_id, vault_id, filename, stored_name, file_type, file_size, access_type)
        VALUES (%s, %s, 'BCA.jpeg', 'bca.jpeg', 'jpeg', %s, 'public'),
               (%s, %s, 'PU.jpeg', 'pu.jpeg', 'jpeg', %s, 'public')
    ''', (bca_id, vault_id, len(bca_bytes), pu_id, vault_id, len(pu_bytes)))
    db.commit()

    print('Indexing BCA...')
    index_document(bca_id, vault_id, test_email)
    print('Indexing PU...')
    index_document(pu_id, vault_id, test_email)

    for q in ['bca marks', 'pu total marks', 'total marks']:
        ans, grounded, sources = ask_vault_ai(test_email, q)
        print(f'=== Q: {q} ===')
        print(f'Grounded: {grounded}')
        print(f'Sources: {[s["filename"] for s in sources]}')
        print(f'Answer:\n{ans}\n')
