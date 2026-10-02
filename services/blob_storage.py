"""
Vercel Blob Storage wrapper for SecureVault AI.

Replaces the local private_storage/uploads/ directory with Private Vercel Blob.
All encrypted document ciphertext is stored as blobs keyed by:

    uploads/<vault_id>/<stored_name>

Files are still encrypted at rest by crypto_utils.py before being uploaded
(the blob stores the same ciphertext that used to live on disk), so the
encryption/decryption logic is completely unchanged.

Configuration
─────────────
Set BLOB_READ_WRITE_TOKEN in your environment (Vercel sets this automatically
when you add a Blob store to a project).  The token value must grant both
read and write access to the store.

If the token is absent the module raises a clear RuntimeError at first use
so misconfiguration is caught early rather than at upload time.

API surface (used by app.py and services/indexer.py)
─────────────────────────────────────────────────────
  blob_put(blob_path, data_bytes)  -> None
  blob_get(blob_path)              -> bytes
  blob_delete(blob_path)           -> None
  blob_exists(blob_path)           -> bool
"""

import os
import logging

logger = logging.getLogger(__name__)

# -- lazy import so the rest of the app does not crash if the package is not
#    installed in local dev environments that still use local disk.

_vercel_blob = None


def _get_vercel_blob():
    global _vercel_blob
    if _vercel_blob is None:
        try:
            import vercel_blob  # noqa: PLC0415
            _vercel_blob = vercel_blob
        except ImportError as exc:
            raise ImportError(
                "vercel-blob is not installed. "
                "Add 'vercel-blob' to requirements.txt and redeploy."
            ) from exc
    return _vercel_blob


def _token() -> str:
    token = os.environ.get("BLOB_READ_WRITE_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "BLOB_READ_WRITE_TOKEN environment variable is not set. "
            "Add it to your Vercel project environment variables."
        )
    return token


# -- Public API ---------------------------------------------------------------

def blob_put(blob_path: str, data_bytes: bytes) -> None:
    """Upload data_bytes to the blob store at blob_path.

    blob_path is a slash-separated key such as
    ``uploads/<vault_id>/<stored_name>``.  The store is addressed with
    access='public' at the SDK level but SecureVault never exposes raw blob
    URLs to users -- every download goes through an authenticated Flask route
    that decrypts and re-serves the bytes -- so network-level 'public' here
    is irrelevant to application-level access control.  The data itself is
    always Fernet ciphertext, never plaintext.
    """
    vb = _get_vercel_blob()
    token = _token()
    logger.debug("blob_put: uploading %d bytes to %s", len(data_bytes), blob_path)
    vb.put(
        blob_path,
        data_bytes,
        options={
            "token": token,
            "access": "public",
            "addRandomSuffix": False,
        },
    )


def blob_get(blob_path: str) -> bytes:
    """Download and return the raw bytes stored at blob_path.

    Raises FileNotFoundError if the blob does not exist.
    """
    vb = _get_vercel_blob()
    token = _token()
    logger.debug("blob_get: downloading %s", blob_path)
    try:
        meta = vb.head(blob_path, options={"token": token})
    except Exception as exc:
        raise FileNotFoundError(
            f"Blob not found: {blob_path} ({type(exc).__name__}: {exc})"
        ) from exc

    blob_url = meta.get("url") if isinstance(meta, dict) else getattr(meta, "url", None)
    if not blob_url:
        raise FileNotFoundError(f"Blob URL missing for: {blob_path}")

    import urllib.request
    with urllib.request.urlopen(blob_url) as resp:
        return resp.read()


def blob_delete(blob_path: str) -> None:
    """Delete the blob at blob_path.  Silently succeeds if not found."""
    vb = _get_vercel_blob()
    token = _token()
    logger.debug("blob_delete: deleting %s", blob_path)
    try:
        meta = vb.head(blob_path, options={"token": token})
        blob_url = (
            meta.get("url") if isinstance(meta, dict) else getattr(meta, "url", None)
        )
        if blob_url:
            vb.delete(blob_url, options={"token": token})
    except Exception as exc:
        logger.debug("blob_delete: %s -- %s (ignored)", blob_path, exc)


def blob_exists(blob_path: str) -> bool:
    """Return True if a blob exists at blob_path."""
    vb = _get_vercel_blob()
    token = _token()
    try:
        vb.head(blob_path, options={"token": token})
        return True
    except Exception:
        return False
