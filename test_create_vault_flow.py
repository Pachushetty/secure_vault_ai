"""
Comprehensive test for POST /create flow:
1. Validates files (PDF & image)
2. Encrypts document stream to bytes
3. Uploads ciphertext to Blob storage
4. Saves metadata in PostgreSQL
5. Generates QR paths in memory
6. Commits transaction
7. Redirects to /vault/<vault_id>/view
8. Dynamically serves QR code PNG from in-memory generator
"""
import io
import unittest
from unittest.mock import patch
from app import app
from db import get_db, init_db
from services.blob_storage import blob_get, blob_exists

class TestCreateVaultFlow(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.test_email = "vaultcreator@securevault.ai"
        
        with app.app_context():
            init_db()
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM users WHERE email = %s", (self.test_email,))
            cur.execute("""
                INSERT INTO users (email, name, password_hash, email_verified)
                VALUES (%s, 'Vault Creator', 'dummyhash', TRUE)
            """, (self.test_email,))
            db.commit()

    def tearDown(self):
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM document_chunks WHERE owner_email = %s", (self.test_email,))
            cur.execute("DELETE FROM documents WHERE vault_id IN (SELECT vault_id FROM vaults WHERE owner_email = %s)", (self.test_email,))
            cur.execute("DELETE FROM vaults WHERE owner_email = %s", (self.test_email,))
            cur.execute("DELETE FROM users WHERE email = %s", (self.test_email,))
            db.commit()

    def test_post_create_complete_flow(self):
        # 1. Establish session
        with self.client.session_transaction() as sess:
            sess['user_email'] = self.test_email
            sess['user_name']  = 'Vault Creator'

        # 2. Prepare sample files (PDF magic bytes and PNG magic bytes)
        pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
        png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"

        data = {
            'vault_name': 'Confidential Financial Vault',
            'documents': [
                (io.BytesIO(pdf_content), 'financial_report.pdf'),
                (io.BytesIO(png_content), 'id_badge.png'),
            ],
            'access_type_0': 'public',
            'access_type_1': 'password',
            'access_code_1': 'secret99',
            'folder_name_0': 'Reports',
            'folder_name_1': 'Badges',
        }

        # 3. Submit POST /create
        res = self.client.post('/create', data=data, content_type='multipart/form-data', follow_redirects=False)

        # 4. Verify HTTP 302 redirect
        self.assertEqual(res.status_code, 302, f"Expected 302 redirect, got {res.status_code}")
        redirect_url = res.headers.get('Location', '')
        self.assertIn('/view', redirect_url)
        vault_id = redirect_url.split('/vault/')[1].split('/view')[0]
        self.assertTrue(len(vault_id) > 0)

        # 5. Verify PostgreSQL database records
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("SELECT * FROM vaults WHERE vault_id = %s", (vault_id,))
            vault = cur.fetchone()
            self.assertIsNotNone(vault)
            self.assertEqual(vault['vault_name'], 'Confidential Financial Vault')
            self.assertEqual(vault['owner_email'], self.test_email)
            self.assertTrue(vault['qr_path'].startswith('/static/qrcodes/'))

            cur.execute("SELECT * FROM documents WHERE vault_id = %s ORDER BY filename", (vault_id,))
            docs = cur.fetchall()
            self.assertEqual(len(docs), 2)
            
            pdf_doc = [d for d in docs if d['filename'] == 'financial_report.pdf'][0]
            png_doc = [d for d in docs if d['filename'] == 'id_badge.png'][0]

            self.assertEqual(pdf_doc['file_type'], 'pdf')
            self.assertEqual(pdf_doc['folder_name'], 'Reports')
            self.assertEqual(png_doc['file_type'], 'png')
            self.assertEqual(png_doc['folder_name'], 'Badges')

            # 6. Verify encrypted ciphertext was stored in Blob/storage
            blob_key_pdf = f"uploads/{vault_id}/{pdf_doc['stored_name']}"
            blob_key_png = f"uploads/{vault_id}/{png_doc['stored_name']}"

            self.assertTrue(blob_exists(blob_key_pdf))
            self.assertTrue(blob_exists(blob_key_png))

            ciphertext = blob_get(blob_key_pdf)
            # Ensure it is encrypted, not raw plaintext
            self.assertNotEqual(ciphertext, pdf_content)

        # 7. Verify dynamic QR image generation via HTTP GET /static/qrcodes/...
        qr_url = vault['qr_path']
        qr_res = self.client.get(qr_url)
        self.assertEqual(qr_res.status_code, 200)
        self.assertEqual(qr_res.mimetype, 'image/png')
        self.assertTrue(qr_res.data.startswith(b'\x89PNG\r\n\x1a\n'))

        # 8. Verify document-specific QR image
        doc_qr_url = pdf_doc['qr_path']
        doc_qr_res = self.client.get(doc_qr_url)
        self.assertEqual(doc_qr_res.status_code, 200)
        self.assertEqual(doc_qr_res.mimetype, 'image/png')
        self.assertTrue(doc_qr_res.data.startswith(b'\x89PNG\r\n\x1a\n'))

        # 9. Verify navigating to vault view succeeds
        view_res = self.client.get(f'/vault/{vault_id}/view')
        self.assertEqual(view_res.status_code, 200)
        self.assertIn(b'Confidential Financial Vault', view_res.data)
        self.assertIn(b'financial_report.pdf', view_res.data)
        self.assertIn(b'id_badge.png', view_res.data)

    @patch('vercel.blob.put')
    def test_post_create_on_vercel_with_blob_sdk(self, mock_blob_put):
        """Simulates Vercel environment with BLOB_READ_WRITE_TOKEN set, ensuring vercel.blob.put is invoked correctly."""
        import os
        mock_blob_put.return_value = {"url": "https://fake.blob.vercel-storage.com/file"}

        with patch.dict(os.environ, {
            'VERCEL': '1',
            'BLOB_READ_WRITE_TOKEN': 'vercel_blob_rw_testtoken123_abc456',
            'STORAGE_BACKEND': 'blob',
            'FILE_ENCRYPTION_KEY': 'some_arbitrary_user_key_phrase'
        }, clear=False):
            with self.client.session_transaction() as sess:
                sess['user_email'] = self.test_email
                sess['user_name']  = 'Vault Creator'

            pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
            data = {
                'vault_name': 'Vercel Cloud Vault',
                'documents': [
                    (io.BytesIO(pdf_content), 'cloud_doc.pdf'),
                ],
            }

            res = self.client.post('/create', data=data, content_type='multipart/form-data', follow_redirects=False)
            self.assertEqual(res.status_code, 302)
            # Verify vercel.blob.put was called with the ciphertext
            self.assertTrue(mock_blob_put.called)
            call_args, call_kwargs = mock_blob_put.call_args
            self.assertTrue(call_args[0].startswith('uploads/'))
            self.assertTrue(call_args[0].endswith('_cloud_doc.pdf'))
            self.assertEqual(call_kwargs.get('access'), 'private')
            self.assertEqual(call_kwargs.get('token'), 'vercel_blob_rw_testtoken123_abc456')

if __name__ == '__main__':
    unittest.main()
