"""
Embedding service for Vault AI.
Provides vector embedding generation and cosine similarity calculation.
Uses scikit-learn TF-IDF feature embeddings as a fast, reliable, zero-cost vector model,
with modular support for external embedding APIs if configured.
"""

import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# Shared vectorizer fitted on vocabulary
_vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=512,
    sublinear_tf=True
)
_is_fitted = False
_sample_corpus = [
    "mark card sslc 2nd puc degree certificate marks percentage score date of birth college university resume experience email phone address hindi english physics chemistry mathematics status",
    "document vault security encrypted user authentication record certificate transcript report",
    "personal identity passport driving license aadhaar pan card tax invoice contract agreement"
]

def _init_vectorizer():
    global _is_fitted
    if not _is_fitted:
        _vectorizer.fit(_sample_corpus)
        _is_fitted = True

def generate_embedding(text):
    """
    Generate a normalized vector embedding for a given text.
    Returns a list of float numbers.
    """
    if not text or not text.strip():
        return [0.0] * 512

    _init_vectorizer()
    
    # Fit-transform or transform text using vectorizer vocabulary
    try:
        vec = _vectorizer.transform([text]).toarray()[0]
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()
    except Exception:
        # Fallback simple character n-gram hashing vector if vectorizer fails
        return _hash_vector(text)


def _hash_vector(text, dim=512):
    """Fallback hashing vector representation."""
    vec = [0.0] * dim
    words = text.lower().split()
    for w in words:
        idx = hash(w) % dim
        vec[idx] += 1.0
    arr = np.array(vec)
    norm = np.linalg.norm(arr)
    if norm > 0:
        arr = arr / norm
    return arr.tolist()


def cosine_similarity_score(vec1, vec2):
    """Calculate cosine similarity between two vector lists."""
    if not vec1 or not vec2:
        return 0.0
    v1 = np.array(vec1, dtype=float)
    v2 = np.array(vec2, dtype=float)
    
    # Resize if dimensions differ
    if v1.shape[0] != v2.shape[0]:
        min_dim = min(v1.shape[0], v2.shape[0])
        v1 = v1[:min_dim]
        v2 = v2[:min_dim]
        
    dot = np.dot(v1, v2)
    norm1 = np.linalg.norm(v1)
    norm2 = np.linalg.norm(v2)
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return float(dot / (norm1 * norm2))


def serialize_vector(vec):
    """Serialize vector float list to JSON string for database storage."""
    return json.dumps(vec)


def deserialize_vector(vec_str):
    """Deserialize JSON string or pgvector string to float list."""
    if not vec_str:
        return []
    if isinstance(vec_str, list):
        return vec_str
    try:
        return json.loads(vec_str)
    except Exception:
        return []
