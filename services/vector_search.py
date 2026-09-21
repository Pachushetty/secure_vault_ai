"""
Vector search service for Vault AI.

Security model:
  - All chunk text is stored AES-256-GCM encrypted in document_chunks.
  - chunk_text and parent_text plaintext columns have been dropped.
  - The only valid path is:  chunk_ciphertext → decrypt_text() → plaintext
  - Authorization: SQL-level owner_email check runs BEFORE any decryption.
  - Decryption scope: user's corpus is decrypted in-memory for TF-IDF;
    plaintext is never persisted, logged, or returned beyond top-K results.

Fail-closed behaviour:
  - If DOCUMENT_TEXT_ENCRYPTION_KEY is not set → refuse to search (RuntimeError).
  - If a chunk's ciphertext fails AES-GCM authentication → skip that chunk
    and log only its ID (no plaintext, no key material in the log).
  - Never silently return corrupted plaintext.
"""

import logging
from db import get_db
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
from services.crypto_utils import decrypt_text, TEXT_ENCRYPTION_AVAILABLE
from services.embedding_service import generate_embedding, deserialize_vector, cosine_similarity_score

logger = logging.getLogger(__name__)

# Performance note (why this file was slow):
# ---------------------------------------------------------------------------
# The previous version of this function decrypted EVERY chunk the user has
# ever uploaded and re-fit a brand-new TfidfVectorizer over that whole
# decrypted corpus on every single question. That cost grows with the size
# of the user's vault, not with the question, so a vault with many
# documents (mark cards, certificates, IDs, resume, ...) got slower and
# slower to query over time — this was the main cause of "AI agent taking
# so long".
#
# services/indexer.py already computes and stores a lightweight embedding
# for every chunk at UPLOAD time (see the `embedding` column), but nothing
# ever read it back for search — it was pure dead weight.
#
# Fix: use that stored embedding as a cheap first-pass filter (no
# decryption needed — embeddings don't reveal document text) to narrow the
# whole vault down to a small, bounded candidate pool. Only THEN decrypt
# and run the original precise per-corpus TF-IDF re-rank — but over the
# small candidate pool instead of the entire vault. Final ranking/quality
# is unchanged for the normal case; only the amount of work scales down.
CANDIDATE_POOL_SIZE = 40


def query_similar_chunks(owner_email, question_text, top_k=5, min_score=0.005):
    """
    Find the most relevant document chunks for owner_email's query.

    Authorization: both c.owner_email and v.owner_email must equal the caller —
    the SQL JOIN enforces this at the database level before any decryption.

    Returns a list of dicts with keys:
      chunk_id, doc_id, vault_id, chunk_index, parent_index, filename,
      score, chunk_text (decrypted), context_text (decrypted parent).

    Raises RuntimeError if DOCUMENT_TEXT_ENCRYPTION_KEY is not loaded.
    """
    if not TEXT_ENCRYPTION_AVAILABLE:
        raise RuntimeError(
            "query_similar_chunks: DOCUMENT_TEXT_ENCRYPTION_KEY is not loaded. "
            "Cannot decrypt RAG chunks — refusing to search."
        )

    db = get_db()
    cur = db.cursor()

    # 1. Retrieve only this user's chunks (authorization at SQL level).
    #    chunk_text/parent_text columns have been dropped — select only ciphertext.
    #    Also select the precomputed `embedding` column (plain floats, not
    #    sensitive — no document text is recoverable from it) for the
    #    cheap pre-filter below.
    cur.execute("""
        SELECT c.id AS chunk_id, c.doc_id, c.vault_id, c.chunk_index,
               c.chunk_ciphertext, c.parent_ciphertext,
               c.parent_index, c.embedding, d.filename
        FROM document_chunks c
        JOIN documents d ON c.doc_id = d.doc_id
        JOIN vaults v ON d.vault_id = v.vault_id
        WHERE c.owner_email = %s AND v.owner_email = %s
    """, (owner_email, owner_email))

    rows = cur.fetchall()
    if not rows:
        return []

    # 1b. Cheap pre-filter using the stored embeddings — bounds how many
    # rows we ever need to decrypt/vectorize below, regardless of how many
    # documents are in the vault. Rows without a stored embedding (e.g.
    # legacy rows indexed before this column existed) are always kept as
    # candidates so nothing is silently dropped from search.
    if len(rows) > CANDIDATE_POOL_SIZE:
        q_embedding = generate_embedding(question_text)
        scored_rows = []
        legacy_rows = []
        for row in rows:
            emb_str = row.get('embedding')
            if emb_str:
                vec = deserialize_vector(emb_str)
                pre_score = cosine_similarity_score(q_embedding, vec) if vec else 0.0
                scored_rows.append((pre_score, row))
            else:
                legacy_rows.append(row)
        scored_rows.sort(key=lambda x: x[0], reverse=True)
        rows = [r for _, r in scored_rows[:CANDIDATE_POOL_SIZE]] + legacy_rows

    # 2. Decrypt candidate set in-memory for TF-IDF (transient — never persisted or logged).
    chunks = []
    skipped = 0
    for row in rows:
        cipher_blob = row.get('chunk_ciphertext')
        if not cipher_blob:
            # Row has no ciphertext — should not occur in the current schema.
            logger.warning(
                "vector_search: chunk_id=%s has no chunk_ciphertext — skipping.",
                row['chunk_id']
            )
            skipped += 1
            continue

        try:
            chunk_plain = decrypt_text(cipher_blob)
        except ValueError:
            # AES-GCM authentication failed — possible tamper or key mismatch.
            # Log only the chunk ID, never the ciphertext or any plaintext.
            logger.warning(
                "vector_search: AES-GCM authentication failed for chunk_id=%s "
                "— possible tamper or key mismatch. Skipping.",
                row['chunk_id']
            )
            skipped += 1
            continue

        parent_plain = None
        parent_blob = row.get('parent_ciphertext')
        if parent_blob:
            try:
                parent_plain = decrypt_text(parent_blob)
            except ValueError:
                # Parent decryption failure: fall back to child chunk as context
                # rather than skipping the whole chunk. Log the ID only.
                logger.warning(
                    "vector_search: parent_ciphertext auth failed for chunk_id=%s "
                    "— using child chunk as context fallback.",
                    row['chunk_id']
                )
                parent_plain = chunk_plain

        item = dict(row)
        item['_chunk_plain']  = chunk_plain
        item['_parent_plain'] = parent_plain or chunk_plain
        chunks.append(item)

    if skipped > 0:
        logger.warning(
            "vector_search: skipped %d/%d chunks (decryption errors or missing ciphertext)",
            skipped, len(rows)
        )

    if not chunks:
        return []

    texts = [c['_chunk_plain'] for c in chunks]

    # 3. Fit TF-IDF on user's corpus + query to capture the full vocabulary.
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        token_pattern=r'(?u)\b\w+\b'  # match all words and numbers (grades, IDs, etc.)
    )

    try:
        vectorizer.fit(texts + [question_text])

        query_vec  = vectorizer.transform([question_text]).toarray()[0]
        chunk_vecs = vectorizer.transform(texts).toarray()

        q_norm = np.linalg.norm(query_vec)
        if q_norm == 0:
            return []

        scored_chunks = []
        for idx, chunk in enumerate(chunks):
            c_vec  = chunk_vecs[idx]
            c_norm = np.linalg.norm(c_vec)
            score  = float(np.dot(query_vec, c_vec) / (q_norm * c_norm)) if c_norm > 0 else 0.0

            if score >= min_score:
                item = {k: v for k, v in chunk.items() if not k.startswith('_')}
                item['score']        = score
                # Expose decrypted text under the keys ai_service.py expects.
                item['chunk_text']   = chunk['_chunk_plain']
                item['context_text'] = chunk['_parent_plain']
                scored_chunks.append(item)

        scored_chunks.sort(key=lambda x: x['score'], reverse=True)

        # De-duplicate by parent section: keep only the best child hit per parent.
        seen_parents = set()
        deduped = []
        for item in scored_chunks:
            key = (item['doc_id'], item['parent_index']) if item['parent_index'] is not None else None
            if key is not None:
                if key in seen_parents:
                    continue
                seen_parents.add(key)
            deduped.append(item)

        return deduped[:top_k]

    except Exception as e:
        logger.error("vector_search: TF-IDF error: %s", type(e).__name__)
        return []
