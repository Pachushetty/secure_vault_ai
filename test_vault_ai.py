"""
Test Suite for Vault AI - Secure Document Vault AI Assistant.
Tests document processing, user isolation, non-hallucination, and clean deletion.
"""

import uuid
import json
import unittest
from app import app
from db import get_db, init_db
from services.document_processor import chunk_text
from services.embedding_service import generate_embedding
from services.vector_search import query_similar_chunks
from services.ai_service import ask_vault_ai
from services.crypto_utils import encrypt_text

class TestVaultAI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Establish Flask app context
        cls.app_context = app.app_context()
        cls.app_context.push()
        
        # Ensure database tables are created/migrated
        init_db()
        
        # Test users
        cls.user_a = "usera@example.com"
        cls.user_b = "userb@example.com"
        
        db = get_db()
        cur = db.cursor()
        
        # Create users if they don't exist
        for email, name in [(cls.user_a, "User A"), (cls.user_b, "User B")]:
            cur.execute("""
                INSERT INTO users (email, name, password_hash)
                VALUES (%s, %s, 'test_hash')
                ON CONFLICT (email) DO NOTHING
            """, (email, name))
        db.commit()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()

    def setUp(self):
        self.db = get_db()
        self.cur = self.db.cursor()
        
        # Unique vault per test run
        self.vault_a = "vault_a_" + uuid.uuid4().hex[:6]
        self.vault_b = "vault_b_" + uuid.uuid4().hex[:6]
        
        for v_id, owner in [(self.vault_a, self.user_a), (self.vault_b, self.user_b)]:
            self.cur.execute("""
                INSERT INTO vaults (vault_id, owner_email, vault_name)
                VALUES (%s, %s, 'Test Vault')
            """, (v_id, owner))
        self.db.commit()

    def tearDown(self):
        # Clean up vaults for these users
        self.cur.execute("DELETE FROM vaults WHERE vault_id IN (%s, %s)", (self.vault_a, self.vault_b))
        self.db.commit()

    def test_01_chunking_overlap(self):
        """Test document chunking with character overlap."""
        text = "1234567890" * 20  # 200 chars
        chunks = chunk_text(text, max_chunk_size=100, overlap=10)
        self.assertTrue(len(chunks) > 1)
        # Check overlap
        self.assertEqual(chunks[0][-10:], chunks[1][:10])

    def test_02_vector_search_relevance(self):
        """Test vector similarity and scoring matching."""
        doc_id = "doc_" + uuid.uuid4().hex[:6]
        self.cur.execute("""
            INSERT INTO documents (doc_id, vault_id, filename, stored_name, file_type)
            VALUES (%s, %s, 'Report.txt', 'stored_report.txt', 'txt')
        """, (doc_id, self.vault_a))
        
        text1 = "The Aadhaar card number is 1234-5678-9012 for identification."
        text2 = "Marks scored in Computer Science exam: 95 out of 100."
        
        e1 = json.dumps(generate_embedding(text1))
        e2 = json.dumps(generate_embedding(text2))
        
        c1_cipher = encrypt_text(text1)
        c2_cipher = encrypt_text(text2)

        self.cur.execute("""
            INSERT INTO document_chunks (doc_id, vault_id, owner_email, chunk_index, embedding, chunk_ciphertext)
            VALUES (%s, %s, %s, 0, %s, %s)
        """, (doc_id, self.vault_a, self.user_a, e1, c1_cipher))
        
        self.cur.execute("""
            INSERT INTO document_chunks (doc_id, vault_id, owner_email, chunk_index, embedding, chunk_ciphertext)
            VALUES (%s, %s, %s, 1, %s, %s)
        """, (doc_id, self.vault_a, self.user_a, e2, c2_cipher))
        self.db.commit()
        
        # Test Query 1: Aadhaar
        results = query_similar_chunks(self.user_a, "What is my Aadhaar card number?", top_k=1)
        self.assertTrue(len(results) > 0)
        self.assertIn("1234-5678-9012", results[0]['chunk_text'])
        
        # Test Query 2: Marks
        results = query_similar_chunks(self.user_a, "Computer Science marks", top_k=1)
        self.assertTrue(len(results) > 0)
        self.assertIn("95 out of 100", results[0]['chunk_text'])

    def test_03_user_isolation(self):
        """Test that User A cannot search or retrieve User B's documents."""
        # 1. Insert documents for User A and User B
        doc_a_id = "doc_a_" + uuid.uuid4().hex[:6]
        doc_b_id = "doc_b_" + uuid.uuid4().hex[:6]
        
        # Twin Filenames Test: Both named "Resume.pdf"
        self.cur.execute("""
            INSERT INTO documents (doc_id, vault_id, filename, stored_name, file_type)
            VALUES (%s, %s, 'Resume.pdf', 'stored_a.pdf', 'pdf')
        """, (doc_a_id, self.vault_a))
        
        self.cur.execute("""
            INSERT INTO documents (doc_id, vault_id, filename, stored_name, file_type)
            VALUES (%s, %s, 'Resume.pdf', 'stored_b.pdf', 'pdf')
        """, (doc_b_id, self.vault_b))
        
        # Insert chunks
        text_a = "User A has 5 years experience in Python coding."
        text_b = "User B has 10 years experience in Java coding."
        embedding_a = json.dumps(generate_embedding(text_a))
        embedding_b = json.dumps(generate_embedding(text_b))
        
        self.cur.execute("""
            INSERT INTO document_chunks (doc_id, vault_id, owner_email, chunk_index, embedding, chunk_ciphertext)
            VALUES (%s, %s, %s, 0, %s, %s)
        """, (doc_a_id, self.vault_a, self.user_a, embedding_a, encrypt_text(text_a)))
        
        self.cur.execute("""
            INSERT INTO document_chunks (doc_id, vault_id, owner_email, chunk_index, embedding, chunk_ciphertext)
            VALUES (%s, %s, %s, 0, %s, %s)
        """, (doc_b_id, self.vault_b, self.user_b, embedding_b, encrypt_text(text_b)))
        
        self.db.commit()
        
        # 2. Query as User A
        chunks_a = query_similar_chunks(self.user_a, "experience in Python or Java coding", top_k=5)
        
        # Verify that User A only gets User A's chunk
        for chunk in chunks_a:
            self.assertEqual(chunk['vault_id'], self.vault_a)
            self.assertEqual(chunk['filename'], 'Resume.pdf')
            self.assertIn("User A", chunk['chunk_text'])
            self.assertNotIn("User B", chunk['chunk_text'])

    def test_04_strict_non_hallucination(self):
        """Test that ask_vault_ai returns exactly the fallback message if query has no evidence."""
        # Query for something completely unrelated to any uploaded content
        answer, found, sources = ask_vault_ai(self.user_a, "What is the capital of France?")
        self.assertFalse(found)
        self.assertEqual(answer, "I couldn't find this information in your documents.")

    def test_05_document_deletion_cleanup(self):
        """Test that deleting a document cascaded-removes chunks and invalidates AI context."""
        doc_id = "doc_del_" + uuid.uuid4().hex[:6]
        
        self.cur.execute("""
            INSERT INTO documents (doc_id, vault_id, filename, stored_name, file_type)
            VALUES (%s, %s, 'Temp.txt', 'stored_temp.txt', 'txt')
        """, (doc_id, self.vault_a))
        
        text = "User has experience in degree and PUC."
        embedding = json.dumps(generate_embedding(text))
        
        self.cur.execute("""
            INSERT INTO document_chunks (doc_id, vault_id, owner_email, chunk_index, embedding, chunk_ciphertext)
            VALUES (%s, %s, %s, 0, %s, %s)
        """, (doc_id, self.vault_a, self.user_a, embedding, encrypt_text(text)))
        
        self.db.commit()
        
        # Query before deletion
        chunks_before = query_similar_chunks(self.user_a, "experience", top_k=5)
        self.assertTrue(len(chunks_before) > 0)
        
        # Delete document
        self.cur.execute("DELETE FROM documents WHERE doc_id = %s", (doc_id,))
        self.db.commit()
        
        # Query after deletion
        chunks_after = query_similar_chunks(self.user_a, "experience", top_k=5)
        self.assertEqual(len(chunks_after), 0)

if __name__ == '__main__':
    unittest.main()
