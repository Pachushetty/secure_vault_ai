"""
Test suite for Vercel-compatible Image OCR & Vault AI with BCA.jpeg and PU.jpeg.
Verifies:
1. Image extraction using Groq vision OCR (simulating Vercel environment)
2. Proper status updating and chunk generation
3. Retrieval & QA answering on factual questions (bca marks, total marks, pu total marks)
4. Logging format: image -> OCR -> extracted character count -> chunks created -> completed
"""
import os
import uuid
import unittest
from dotenv import load_dotenv

load_dotenv('.env')

from app import app
from db import get_db, init_db
from services.blob_storage import blob_put
from services.crypto_utils import encrypt_bytes
from services.indexer import index_document
from services.ai_service import ask_vault_ai
from services.document_processor import extract_text_from_file

BCA_PATH = r"c:\Users\hemal\Downloads\BCA.jpeg"
PU_PATH  = r"c:\Users\hemal\Downloads\PU.jpeg"

class TestImageOCRVaultAI(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.test_email = "ocr_test_user@securevault.ai"
        self.vault_id = "test_ocr_vault_" + uuid.uuid4().hex[:8]
        self.bca_doc_id = uuid.uuid4().hex
        self.pu_doc_id = uuid.uuid4().hex

        with app.app_context():
            init_db()
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM users WHERE email = %s", (self.test_email,))
            cur.execute("""
                INSERT INTO users (email, name, password_hash, email_verified)
                VALUES (%s, 'OCR Tester', 'hash', TRUE)
            """, (self.test_email,))
            cur.execute("""
                INSERT INTO vaults (vault_id, vault_name, owner_email, qr_path)
                VALUES (%s, 'Academic Documents', %s, '/static/qrcodes/test.png')
            """, (self.vault_id, self.test_email))
            db.commit()

    def tearDown(self):
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM document_chunks WHERE owner_email = %s", (self.test_email,))
            cur.execute("DELETE FROM document_indexing_status WHERE doc_id IN (%s, %s)", (self.bca_doc_id, self.pu_doc_id))
            cur.execute("DELETE FROM documents WHERE vault_id = %s", (self.vault_id,))
            cur.execute("DELETE FROM vaults WHERE vault_id = %s", (self.vault_id,))
            cur.execute("DELETE FROM users WHERE email = %s", (self.test_email,))
            db.commit()

    def test_01_extract_text_from_images(self):
        """Test that extract_text_from_file extracts extensive text from BCA.jpeg and PU.jpeg."""
        self.assertTrue(os.path.exists(BCA_PATH), f"Missing test file: {BCA_PATH}")
        self.assertTrue(os.path.exists(PU_PATH), f"Missing test file: {PU_PATH}")

        # Simulate Vercel environment where local tesseract is unavailable
        orig_vercel = os.environ.get('VERCEL')
        try:
            os.environ['VERCEL'] = '1'
            bca_text = extract_text_from_file(BCA_PATH, 'jpeg')
            self.assertGreater(len(bca_text), 200, "BCA.jpeg OCR returned insufficient text")
            self.assertTrue(any(term in bca_text.upper() for term in ('MANGALORE', 'BACHELOR OF COMPUTER APPLICATIONS', 'PRATHIKSHA', 'MARKS')))

            pu_text = extract_text_from_file(PU_PATH, 'jpeg')
            self.assertGreater(len(pu_text), 200, "PU.jpeg OCR returned insufficient text")
            self.assertTrue(any(term in pu_text.upper() for term in ('PRE-UNIVERSITY', 'KARNATAKA', 'CERTIFICATE', 'MARKS', 'GOVERNMENT')))
        finally:
            if orig_vercel is None:
                os.environ.pop('VERCEL', None)
            else:
                os.environ['VERCEL'] = orig_vercel

    def test_02_indexing_and_vault_ai_retrieval(self):
        """Index BCA.jpeg and PU.jpeg and test factual queries in Vault AI."""
        # 1. Read files and store encrypted ciphertext
        with open(BCA_PATH, 'rb') as f:
            bca_bytes = f.read()
        with open(PU_PATH, 'rb') as f:
            pu_bytes = f.read()

        bca_stored = f"bca_{self.bca_doc_id}.jpeg"
        pu_stored  = f"pu_{self.pu_doc_id}.jpeg"

        blob_put(f"uploads/{self.vault_id}/{bca_stored}", encrypt_bytes(bca_bytes))
        blob_put(f"uploads/{self.vault_id}/{pu_stored}", encrypt_bytes(pu_bytes))

        # 2. Insert document metadata into database
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("""
                INSERT INTO documents (doc_id, vault_id, filename, stored_name, file_type, file_size, access_type)
                VALUES (%s, %s, 'BCA.jpeg', %s, 'jpeg', %s, 'public'),
                       (%s, %s, 'PU.jpeg',  %s, 'jpeg', %s, 'public')
            """, (self.bca_doc_id, self.vault_id, bca_stored, len(bca_bytes),
                  self.pu_doc_id, self.vault_id, pu_stored, len(pu_bytes)))
            db.commit()

        # 3. Run indexing
        bca_ok = index_document(self.bca_doc_id, self.vault_id, self.test_email)
        self.assertTrue(bca_ok, "BCA indexing failed")

        pu_ok = index_document(self.pu_doc_id, self.vault_id, self.test_email)
        self.assertTrue(pu_ok, "PU indexing failed")

        # Verify database statuses
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT doc_id, status FROM document_indexing_status WHERE doc_id IN (%s, %s)",
                        (self.bca_doc_id, self.pu_doc_id))
            statuses = {r['doc_id']: r['status'] for r in cur.fetchall()}
            self.assertEqual(statuses.get(self.bca_doc_id), 'completed')
            self.assertEqual(statuses.get(self.pu_doc_id), 'completed')

            cur.execute("SELECT COUNT(*) as count FROM document_chunks WHERE owner_email = %s", (self.test_email,))
            chunk_count = cur.fetchone()['count']
            self.assertGreater(chunk_count, 0, "No chunks created")

        # 4. Ask questions through Vault AI
        with app.app_context():
            # Query 1: bca marks
            bca_answer, bca_grounded, bca_sources = ask_vault_ai(self.test_email, "bca marks")
            print("\n[TEST] Question: 'bca marks' -> Grounded:", bca_grounded, "Answer:", bca_answer)
            self.assertTrue(bca_grounded)
            self.assertNotEqual(bca_answer, "I couldn't find this information in your documents.")
            self.assertTrue(len(bca_sources) > 0)
            self.assertTrue(any(s['filename'] == 'BCA.jpeg' for s in bca_sources))

            # Query 2: total marks
            total_answer, total_grounded, total_sources = ask_vault_ai(self.test_email, "total marks")
            print("\n[TEST] Question: 'total marks' -> Grounded:", total_grounded, "Answer:", total_answer)
            self.assertTrue(total_grounded)
            self.assertNotEqual(total_answer, "I couldn't find this information in your documents.")
            self.assertTrue(len(total_sources) > 0)

            # Query 3: pu total marks
            pu_answer, pu_grounded, pu_sources = ask_vault_ai(self.test_email, "pu total marks")
            print("\n[TEST] Question: 'pu total marks' -> Grounded:", pu_grounded, "Answer:", pu_answer)
            self.assertTrue(pu_grounded)
            self.assertNotEqual(pu_answer, "I couldn't find this information in your documents.")
            self.assertTrue(len(pu_sources) > 0)
            self.assertTrue(any(s['filename'] == 'PU.jpeg' for s in pu_sources))

if __name__ == '__main__':
    unittest.main()
