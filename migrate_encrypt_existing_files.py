"""
One-time migration: encrypts any documents in private_storage/uploads/ that
were written before encryption-at-rest was added (see
services/crypto_utils.py). New uploads are always encrypted automatically;
this script only needs to run once against an existing deployment's
already-uploaded files.

Safe to re-run: files that are already valid Fernet tokens are detected and
left untouched, so running this twice (or on a directory that's a mix of
old and new files) does the right thing either way.

Usage:
    export DATABASE_URL=postgresql://user:pass@host:5432/dbname
    export FILE_ENCRYPTION_KEY=...        # same key the app will use
    python migrate_encrypt_existing_files.py
"""
import os

from cryptography.fernet import InvalidToken

from services.crypto_utils import get_fernet, encrypt_bytes

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'private_storage', 'uploads')


def is_already_encrypted(data: bytes) -> bool:
    try:
        get_fernet().decrypt(data)
        return True
    except InvalidToken:
        return False


def main():
    if not os.path.isdir(UPLOAD_DIR):
        print(f"No upload directory found at {UPLOAD_DIR} — nothing to do.")
        return

    scanned = encrypted = skipped = 0
    for root, _dirs, files in os.walk(UPLOAD_DIR):
        for name in files:
            path = os.path.join(root, name)
            scanned += 1
            with open(path, 'rb') as f:
                data = f.read()
            if is_already_encrypted(data):
                skipped += 1
                continue
            with open(path, 'wb') as f:
                f.write(encrypt_bytes(data))
            encrypted += 1
            print(f"Encrypted: {os.path.relpath(path, UPLOAD_DIR)}")

    print(f"\nDone. Scanned {scanned} file(s): {encrypted} encrypted, "
          f"{skipped} already encrypted.")


if __name__ == '__main__':
    main()
