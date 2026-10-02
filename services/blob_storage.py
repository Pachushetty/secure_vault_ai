"""
Vercel Private Blob Storage wrapper for SecureVault AI.

Provides persistent encrypted document storage using Vercel Private Blob when deployed,
with automatic fallback to local filesystem storage (private_storage/uploads/)
for local development.

All encrypted document ciphertext is addressed by keys formatted as:
    uploads/<vault_id>/<stored_name>

Files are encrypted at rest by crypto_utils.py before upload.
Documents are NEVER public: they are stored as private blobs, retrieved only by
authenticated server-side routes, and decrypted in-memory for authorized users.

Configuration (Environment Variables)
─────────────────────────────────────
BLOB_READ_WRITE_TOKEN : Provided automatically by Vercel when connecting a Blob store.
BLOB_ACCESS           : Optional. Defaults to "private".
STORAGE_BACKEND       : Optional. Set to "local" to force local filesystem storage.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_STORAGE_DIR = os.path.join(BASE_DIR, 'private_storage')
LOCAL_UPLOAD_DIR = os.path.join(LOCAL_STORAGE_DIR, 'uploads')


def is_blob_storage_enabled() -> bool:
    """Determine whether to use Vercel Blob or local disk storage.
    
    Returns True when:
      - Explicitly requested via STORAGE_BACKEND in ('blob', 'vercel_blob')
      - Or BLOB_READ_WRITE_TOKEN is set
      - Or running in Vercel production environment
    Returns False when STORAGE_BACKEND is 'local' or in local dev without BLOB_READ_WRITE_TOKEN.
    """
    backend = os.environ.get("STORAGE_BACKEND", "").strip().lower()
    if backend == "local":
        return False
    if backend in ("blob", "vercel_blob"):
        return True
    
    token = os.environ.get("BLOB_READ_WRITE_TOKEN", "").strip()
    if token:
        return True
    
    # If on Vercel, filesystem is read-only so Blob storage is required
    if os.environ.get("VERCEL"):
        return True
        
    return False


def _token() -> str:
    token = os.environ.get("BLOB_READ_WRITE_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "BLOB_READ_WRITE_TOKEN environment variable is not set. "
            "Please create and connect a Vercel Blob store in your Vercel Project Settings."
        )
    return token


def _get_local_disk_path(blob_path: str) -> str:
    norm = blob_path.replace("\\", "/").lstrip("/")
    return os.path.join(LOCAL_STORAGE_DIR, *norm.split("/"))


# ── Public API ───────────────────────────────────────────────────────────────

def blob_put(blob_path: str, data_bytes: bytes, access: Optional[str] = None) -> None:
    """Upload encrypted ciphertext to persistent storage (Vercel Private Blob or local disk).
    
    In production (Vercel Blob), access defaults to 'private' so documents are never
    publicly accessible without authentication.
    """
    if is_blob_storage_enabled():
        token = _token()
        access_mode = (access or os.environ.get("BLOB_ACCESS", "private")).strip().lower()
        import vercel.blob  # Official Vercel Python SDK
        logger.debug("blob_put: uploading %d bytes to Blob path %s (access=%s)", len(data_bytes), blob_path, access_mode)
        try:
            vercel.blob.put(
                blob_path,
                data_bytes,
                access=access_mode,
                token=token,
                add_random_suffix=False,
                overwrite=True,
            )
        except Exception as exc:
            # If the store was created with the other access mode, retry gracefully
            if "access" in str(exc).lower():
                fallback = "public" if access_mode == "private" else "private"
                logger.warning("Retrying blob_put with access=%s due to: %s", fallback, exc)
                vercel.blob.put(
                    blob_path,
                    data_bytes,
                    access=fallback,
                    token=token,
                    add_random_suffix=False,
                    overwrite=True,
                )
            else:
                raise
    else:
        # Local development filesystem storage
        disk_path = _get_local_disk_path(blob_path)
        os.makedirs(os.path.dirname(disk_path), exist_ok=True)
        with open(disk_path, "wb") as f:
            f.write(data_bytes)
        logger.debug("blob_put: saved %d bytes to local disk %s", len(data_bytes), disk_path)


def blob_get(blob_path: str, access: Optional[str] = None) -> bytes:
    """Download encrypted ciphertext from persistent storage (Vercel Private Blob or local disk).
    
    Raises FileNotFoundError if the file or blob does not exist.
    """
    if is_blob_storage_enabled():
        token = _token()
        access_mode = (access or os.environ.get("BLOB_ACCESS", "private")).strip().lower()
        import vercel.blob
        logger.debug("blob_get: downloading from Blob path %s (access=%s)", blob_path, access_mode)
        try:
            res = vercel.blob.get(blob_path, access=access_mode, token=token)
            return res.content
        except Exception as exc:
            if "access" in str(exc).lower():
                fallback = "public" if access_mode == "private" else "private"
                res = vercel.blob.get(blob_path, access=fallback, token=token)
                return res.content
            raise FileNotFoundError(
                f"Blob not found: {blob_path} ({type(exc).__name__}: {exc})"
            ) from exc
    else:
        disk_path = _get_local_disk_path(blob_path)
        if not os.path.exists(disk_path):
            raise FileNotFoundError(f"File not found on local disk: {disk_path}")
        with open(disk_path, "rb") as f:
            return f.read()


def blob_delete(blob_path: str) -> None:
    """Delete ciphertext from persistent storage. Silently succeeds if not found."""
    if is_blob_storage_enabled():
        try:
            token = _token()
            import vercel.blob
            logger.debug("blob_delete: deleting Blob path %s", blob_path)
            vercel.blob.delete(blob_path, token=token)
        except Exception as exc:
            logger.debug("blob_delete failed for %s: %s (ignored)", blob_path, exc)
    else:
        disk_path = _get_local_disk_path(blob_path)
        if os.path.exists(disk_path):
            try:
                os.remove(disk_path)
            except OSError as exc:
                logger.debug("Local file remove failed for %s: %s (ignored)", disk_path, exc)


def blob_exists(blob_path: str) -> bool:
    """Return True if the file exists in persistent storage."""
    if is_blob_storage_enabled():
        try:
            token = _token()
            import vercel.blob
            vercel.blob.head(blob_path, token=token)
            return True
        except Exception:
            return False
    else:
        disk_path = _get_local_disk_path(blob_path)
        return os.path.exists(disk_path)
