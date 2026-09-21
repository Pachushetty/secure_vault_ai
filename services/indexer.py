"""
Document indexing service for Vault AI.
Extracts, chunks, embeds, and stores document content in PostgreSQL.
Supports async background threading to keep upload requests fast.

All extracted text is encrypted with AES-256-GCM (DOCUMENT_TEXT_ENCRYPTION_KEY)
before being written to PostgreSQL — plaintext never touches the database.
"""

import os
import logging
import threading
import psycopg2
import psycopg2.extras
from db import DATABASE_URL
from services.document_processor import extract_text_from_file, chunk_text_parent_child
from services.embedding_service import generate_embedding, serialize_vector
from services.crypto_utils import decrypted_temp_copy, encrypt_text, TEXT_ENCRYPTION_AVAILABLE

logger = logging.getLogger(__name__)

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'private_storage', 'uploads')

def get_direct_conn():
    """Get a fresh, standalone database connection for background threads."""
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor
    )


def index_document(doc_id, vault_id, owner_email):
    """
    Synchronously extracts text, chunks, embeds, and saves document to vector store.
    Updates document_indexing_status table accordingly.
    """
    if not TEXT_ENCRYPTION_AVAILABLE:
        logger.error(
            "index_document: DOCUMENT_TEXT_ENCRYPTION_KEY is not set — "
            "refusing to index doc_id=%s to avoid storing plaintext in the database. "
            "Set the environment variable and restart.", doc_id
        )
        conn = get_direct_conn()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO document_indexing_status (doc_id, status, error_message, updated_at)
                VALUES (%s, 'failed', 'DOCUMENT_TEXT_ENCRYPTION_KEY not configured', now())
                ON CONFLICT (doc_id) DO UPDATE
                    SET status = 'failed',
                        error_message = 'DOCUMENT_TEXT_ENCRYPTION_KEY not configured',
                        updated_at = now()
            """, (doc_id,))
            conn.commit()
        finally:
            cur.close()
            conn.close()
        return False

    conn = get_direct_conn()
    cur = conn.cursor()
    
    try:
        # 1. Update status to 'processing'
        cur.execute("""
            INSERT INTO document_indexing_status (doc_id, status, updated_at)
            VALUES (%s, 'processing', now())
            ON CONFLICT (doc_id) DO UPDATE SET status = 'processing', updated_at = now()
        """, (doc_id,))
        conn.commit()

        # 2. Get document metadata
        cur.execute("SELECT filename, stored_name, file_type FROM documents WHERE doc_id = %s", (doc_id,))
        doc = cur.fetchone()
        if not doc:
            raise ValueError(f"Document {doc_id} not found in database.")

        # 3. Resolve path and extract text. Documents are encrypted at rest
        # (see services/crypto_utils.py), so decrypt into a private temp
        # file for the extraction libraries (which need a real path) and
        # remove it as soon as extraction finishes.
        file_path = os.path.join(UPLOAD_DIR, vault_id, doc['stored_name'])
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found on disk: {file_path}")

        ext = f".{doc['file_type']}" if doc['file_type'] else ''
        with decrypted_temp_copy(file_path, suffix=ext) as tmp_path:
            text = extract_text_from_file(tmp_path, doc['file_type'])
        if not text.strip():
            # Create an empty index status to denote it's finished but has no text content
            cur.execute("""
                UPDATE document_indexing_status
                SET status = 'completed', error_message = 'No extractable text', updated_at = now()
                WHERE doc_id = %s
            """, (doc_id,))
            conn.commit()
            return True

        # 4. Chunk text — parent/child: `chunks[i]['child_text']` is what
        # gets embedded and matched against a query; `parent_text` is the
        # larger structural section it belongs to, stored alongside it so
        # retrieval can hand the LLM richer context than the short match
        # alone (see services/document_processor.py chunk_text_parent_child).
        chunks = chunk_text_parent_child(text)
        
        # Clear existing chunks if any to avoid duplication (e.g. during replacement or re-index)
        cur.execute("DELETE FROM document_chunks WHERE doc_id = %s", (doc_id,))

        # 5. Embed, encrypt, and save chunks.
        # The plaintext of each chunk is encrypted with AES-256-GCM before
        # it is written to the database. Plaintext chunk_text/parent_text
        # columns have been removed completely.
        for idx, chunk in enumerate(chunks):
            prepended_chunk = f"Document: {doc['filename']}\n{chunk['child_text']}"
            embedding = generate_embedding(prepended_chunk)
            embedding_json = serialize_vector(embedding)

            # Encrypt — encrypt_text() raises RuntimeError if key unavailable
            # (already checked at the top of this function, but guard anyway).
            chunk_cipher  = encrypt_text(prepended_chunk)
            parent_cipher = encrypt_text(chunk['parent_text']) if chunk.get('parent_text') else None
            
            cur.execute("""
                INSERT INTO document_chunks
                    (doc_id, vault_id, owner_email, chunk_index,
                     embedding, parent_index,
                     chunk_ciphertext, parent_ciphertext)
                VALUES (%s, %s, %s, %s,
                        %s, %s,
                        %s, %s)
            """, (doc_id, vault_id, owner_email, idx,
                  embedding_json, chunk['parent_index'],
                  chunk_cipher, parent_cipher))

        # 6. Mark completed
        cur.execute("""
            UPDATE document_indexing_status
            SET status = 'completed', error_message = NULL, updated_at = now()
            WHERE doc_id = %s
        """, (doc_id,))
        conn.commit()
        return True

    except Exception as e:
        logger.error("Failed to index document %s: %s", doc_id, type(e).__name__)
        try:
            cur.execute("""
                INSERT INTO document_indexing_status (doc_id, status, error_message, updated_at)
                VALUES (%s, 'failed', %s, now())
                ON CONFLICT (doc_id) DO UPDATE SET status = 'failed', error_message = %s, updated_at = now()
            """, (doc_id, str(e), str(e)))
            conn.commit()
        except Exception as db_err:
            logger.error("Could not update status to failed for %s: %s", doc_id, type(db_err).__name__)
        return False
    finally:
        cur.close()
        conn.close()


def index_document_async(doc_id, vault_id, owner_email):
    """Start indexing in a non-blocking background thread."""
    thread = threading.Thread(
        target=index_document,
        args=(doc_id, vault_id, owner_email),
        daemon=True
    )
    thread.start()
    return thread


def index_all_user_documents(owner_email):
    """
    Finds any existing documents for the user that are not yet indexed (or failed/pending),
    and triggers indexing for them in background.
    """
    conn = get_direct_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT d.doc_id, d.vault_id
            FROM documents d
            JOIN vaults v ON d.vault_id = v.vault_id
            LEFT JOIN document_indexing_status s ON d.doc_id = s.doc_id
            WHERE v.owner_email = %s AND (s.status IS NULL OR s.status = 'pending')
        """, (owner_email,))
        unindexed = cur.fetchall()
        
        for doc in unindexed:
            index_document_async(doc['doc_id'], doc['vault_id'], owner_email)
    except Exception as e:
        logger.error("Error starting sync indexing: %s", type(e).__name__)
    finally:
        cur.close()
        conn.close()
