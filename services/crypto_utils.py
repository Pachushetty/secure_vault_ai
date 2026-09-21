"""
Encryption-at-rest for uploaded documents.

Every file written under private_storage/uploads/ is encrypted with a
symmetric Fernet key (AES-128-CBC + HMAC-SHA256, via the `cryptography`
package) before it ever touches disk, and decrypted only in memory when an
authorized route needs to serve/process it.

── Key management ───────────────────────────────────────────────────────────
The key is read from the FILE_ENCRYPTION_KEY environment variable in
production. If it isn't set, a key is generated once and cached in
instance/file_encryption.key — the SAME pattern already used for the Flask
session secret (instance/secret.key) in app.py. That file lives in
instance/, never inside private_storage/uploads/, so the key is never
stored alongside the ciphertext it protects. As with the session secret,
most hosting platforms wipe local disk on redeploy, so set
FILE_ENCRYPTION_KEY as a real environment variable in production —
otherwise every previously-encrypted file becomes unreadable after a
redeploy that loses instance/.

── Backward compatibility ───────────────────────────────────────────────────
Files that were written before this feature existed are plain bytes, not
Fernet tokens. decrypt_bytes() detects this (Fernet tokens are versioned
and always fail InvalidToken on non-Fernet input) and transparently returns
the original bytes unchanged, so already-uploaded documents keep working.
Anything saved from now on is always encrypted.

── Document text encryption (AES-256-GCM) ──────────────────────────────────
Extracted text stored in document_chunks (chunk_ciphertext, parent_ciphertext) is
encrypted with AES-256-GCM using a separate dedicated key loaded from
DOCUMENT_TEXT_ENCRYPTION_KEY. This key is distinct from FILE_ENCRYPTION_KEY
and all other application secrets. The encrypted blob format is:

    base64url( nonce[12 bytes] + ciphertext + GCM-tag[16 bytes] )

packed as a single opaque string stored in the chunk_ciphertext /
parent_ciphertext columns. AES-GCM provides both confidentiality and
integrity authentication — any tamper of the stored ciphertext is detected
at decryption time and raises ValueError rather than silently returning
corrupted plaintext.

The key MUST be set before the application indexes or retrieves any
documents. If absent, TEXT_ENCRYPTION_AVAILABLE is False and indexing/
retrieval will refuse to proceed rather than silently storing plaintext.
"""
import os
import base64
import logging
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_FILE = os.path.join(BASE_DIR, 'instance', 'file_encryption.key')

_fernet = None


def _load_or_create_key():
    env_key = os.environ.get('FILE_ENCRYPTION_KEY')
    if env_key:
        return env_key.encode('utf-8')

    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read().strip()

    key = Fernet.generate_key()
    # 0600: readable/writable by the owning process only.
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(key)
    return key


def get_fernet():
    """Lazily build (and cache) the Fernet instance used for all file I/O."""
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt_bytes(data: bytes) -> bytes:
    return get_fernet().encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    """Decrypt ciphertext written by encrypt_bytes().

    On InvalidToken, the default behaviour is to fall back to returning the
    input unchanged, so files uploaded before encryption-at-rest was added
    still open. That fallback is intentionally noisy now: it can't tell the
    difference between "this is genuinely a legacy plaintext file" and
    "this is a corrupted ciphertext / the wrong key is loaded", and silently
    serving the latter as if it were valid plaintext is exactly the failure
    mode a security audit would flag. So every fallback is logged, and if
    STRICT_FILE_DECRYPTION=true is set (recommended once
    migrate_encrypt_existing_files.py has been run against a deployment),
    the fallback is disabled entirely and a failure raises instead of
    silently returning possibly-garbage bytes.
    """
    try:
        return get_fernet().decrypt(data)
    except InvalidToken:
        if os.environ.get('STRICT_FILE_DECRYPTION', '').lower() in ('1', 'true', 'yes'):
            raise
        logger.warning(
            "decrypt_bytes: InvalidToken — falling back to raw bytes. This "
            "is expected only for files written before encryption-at-rest "
            "was added and not yet migrated (see "
            "migrate_encrypt_existing_files.py). If migration has already "
            "run, this means either a corrupted file or the wrong "
            "FILE_ENCRYPTION_KEY is loaded — treat as an error, not silent "
            "plaintext."
        )
        return data


def encrypt_stream_to_path(file_storage, dest_path: str) -> int:
    """Read an uploaded werkzeug FileStorage stream fully, encrypt it, and
    write the ciphertext to dest_path. Returns the plaintext size in bytes
    (what the app records as file_size / uses for the size limit check)."""
    file_storage.seek(0)
    raw = file_storage.read()
    file_storage.seek(0)
    with open(dest_path, 'wb') as f:
        f.write(encrypt_bytes(raw))
    return len(raw)


def decrypt_path_to_bytes(path: str) -> bytes:
    with open(path, 'rb') as f:
        return decrypt_bytes(f.read())


class decrypted_temp_copy:
    """Context manager: decrypts the file at `path` into a private temp file
    and yields its path, for library code (PyMuPDF, python-docx, PIL, ...)
    that needs a real filesystem path rather than bytes. The temp file is
    created 0600 in the system temp dir and always removed on exit, even
    on error, so plaintext never lingers on disk longer than one request.
    """
    def __init__(self, path, suffix=''):
        self.path = path
        self.suffix = suffix
        self.tmp_path = None

    def __enter__(self):
        import tempfile
        data = decrypt_path_to_bytes(self.path)
        fd, self.tmp_path = tempfile.mkstemp(suffix=self.suffix)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
        except Exception:
            os.close(fd)
            raise
        return self.tmp_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.tmp_path and os.path.exists(self.tmp_path):
            try:
                os.remove(self.tmp_path)
            except OSError:
                pass
        return False


# ── AES-256-GCM text encryption for RAG document chunks ─────────────────────
#
# Separate from the Fernet file-encryption above. Uses its own key
# (DOCUMENT_TEXT_ENCRYPTION_KEY) and the hazmat AESGCM primitive, which
# provides both confidentiality and integrity (authenticated encryption).
#
# Blob wire format (stored as a single base64url string in PostgreSQL):
#   nonce[12] + ciphertext[variable] + GCM-tag[16]
# All three are concatenated before base64 encoding so the database holds
# one opaque column per encrypted field, not three.

_text_key: bytes | None = None          # raw 32-byte key, loaded once
TEXT_ENCRYPTION_AVAILABLE: bool = False  # set True if key loaded successfully

_TEXT_KEY_ENV = 'DOCUMENT_TEXT_ENCRYPTION_KEY'
_NONCE_BYTES  = 12   # 96-bit nonce, recommended for AES-GCM


def _load_text_key() -> None:
    """Load DOCUMENT_TEXT_ENCRYPTION_KEY once at module import time.

    The key must be a base64url-encoded 32-byte value.  If absent or invalid
    the module-level TEXT_ENCRYPTION_AVAILABLE flag stays False and callers
    must refuse to store or read chunk ciphertext rather than silently
    operating on plaintext / corrupt data.
    """
    global _text_key, TEXT_ENCRYPTION_AVAILABLE
    raw_env = os.environ.get(_TEXT_KEY_ENV, '').strip()
    if not raw_env:
        logger.warning(
            "DOCUMENT_TEXT_ENCRYPTION_KEY is not set. "
            "RAG chunk text encryption is DISABLED — document text will NOT "
            "be stored encrypted in PostgreSQL. Set this variable to enable "
            "AES-256-GCM protection of extracted document content."
        )
        return
    try:
        key_bytes = base64.urlsafe_b64decode(raw_env + '==')  # tolerant padding
        if len(key_bytes) != 32:
            raise ValueError(f"Key must be exactly 32 bytes; got {len(key_bytes)}")
        _text_key = key_bytes
        TEXT_ENCRYPTION_AVAILABLE = True
        logger.info("DOCUMENT_TEXT_ENCRYPTION_KEY loaded — AES-256-GCM text encryption active.")
    except Exception as exc:
        logger.error(
            "DOCUMENT_TEXT_ENCRYPTION_KEY is set but invalid: %s. "
            "RAG chunk text encryption is DISABLED.", exc
        )


def encrypt_text(plaintext: str) -> str:
    """Encrypt a plaintext string with AES-256-GCM.

    Returns a base64url-encoded blob: nonce[12] + ciphertext + tag[16].
    A fresh cryptographically random nonce is generated for every call so
    the same plaintext always produces a different ciphertext — nonce reuse
    is impossible with this design.

    Raises RuntimeError if DOCUMENT_TEXT_ENCRYPTION_KEY is not loaded.
    Raises TypeError if plaintext is not a str.
    """
    if not TEXT_ENCRYPTION_AVAILABLE or _text_key is None:
        raise RuntimeError(
            "encrypt_text called but DOCUMENT_TEXT_ENCRYPTION_KEY is not "
            "loaded. Set the environment variable before indexing documents."
        )
    if not isinstance(plaintext, str):
        raise TypeError(f"encrypt_text expects str, got {type(plaintext).__name__}")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(_text_key)
    nonce  = os.urandom(_NONCE_BYTES)
    # AESGCM.encrypt returns ciphertext + 16-byte tag concatenated.
    ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    blob = nonce + ct_and_tag
    return base64.urlsafe_b64encode(blob).decode('ascii')


def decrypt_text(blob: str) -> str:
    """Decrypt a blob produced by encrypt_text().

    Raises RuntimeError  — key not loaded.
    Raises ValueError    — authentication tag mismatch (tamper detected) or
                           blob is malformed / too short.
    Never silently returns corrupted plaintext.
    """
    if not TEXT_ENCRYPTION_AVAILABLE or _text_key is None:
        raise RuntimeError(
            "decrypt_text called but DOCUMENT_TEXT_ENCRYPTION_KEY is not "
            "loaded. The application cannot decrypt RAG chunks without the key."
        )
    if not blob:
        raise ValueError("decrypt_text: empty blob")

    try:
        raw = base64.urlsafe_b64decode(blob + '==')
    except Exception as exc:
        raise ValueError(f"decrypt_text: base64 decode failed: {exc}") from exc

    min_len = _NONCE_BYTES + 16  # nonce + tag (zero-length plaintext is valid)
    if len(raw) < min_len:
        raise ValueError(
            f"decrypt_text: blob too short ({len(raw)} bytes, need >= {min_len})"
        )

    nonce      = raw[:_NONCE_BYTES]
    ct_and_tag = raw[_NONCE_BYTES:]

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        aesgcm    = AESGCM(_text_key)
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
    except Exception as exc:
        # cryptography raises InvalidTag on auth failure — convert to ValueError
        # so callers get a consistent, key-safe exception type.
        raise ValueError(
            "decrypt_text: authentication failed — ciphertext may have been "
            "tampered with or the wrong key is loaded."
        ) from exc

    return plaintext.decode('utf-8')


# Load the text encryption key immediately when the module is imported so
# any misconfiguration is discovered at startup, not mid-request.
_load_text_key()
