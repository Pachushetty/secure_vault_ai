import os
import uuid
import secrets
import re
import shutil
import logging
import resend
from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, send_file, send_from_directory, abort, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
import io
import zipfile
import json
import csv
import bcrypt
from PIL import Image, ImageDraw, ImageFont
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_auth_requests

from db import get_db, close_db, init_db, to_iso, to_iso_all
from services.indexer import index_document_async, index_all_user_documents
from services.ai_service import ask_vault_ai
from services.crypto_utils import (
    encrypt_stream_to_path, decrypt_path_to_bytes, decrypted_temp_copy,
    encrypt_text, decrypt_text, TEXT_ENCRYPTION_AVAILABLE
)
import mimetypes
import hashlib

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Security/audit event logging â€” INFO-level so the vault_ai.audit logger
# (metadata only: hashed user id, chunk counts, doc_ids, outcome â€” never
# full question/answer/document text; see services/ai_service.py) is
# actually emitted. Kept minimal and stdout-based; operators can redirect
# to their own log pipeline without any code changes here.
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)
close_db(app)  # register teardown handler that closes/commits the DB connection
csrf = CSRFProtect(app)  # protects every POST/PUT/PATCH/DELETE route by default

# Rate limiting on password/access-code entry points, keyed by client IP.
# Backed by Redis when RATELIMIT_STORAGE_URI (or REDIS_URL) is set, so
# limits are shared correctly across multiple worker processes in
# production; falls back to in-memory storage otherwise, which only
# enforces limits correctly within a single process â€” fine for local
# dev/college-project use, but multiple gunicorn/uwsgi workers would each
# keep their own independent counters and the effective limit would be
# (configured limit Ã— worker count).
_ratelimit_storage_uri = (
    os.environ.get('RATELIMIT_STORAGE_URI')
    or os.environ.get('REDIS_URL')
    or 'memory://'
)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],  # no blanket limit â€” only the routes below are limited
    storage_uri=_ratelimit_storage_uri,
)

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
# NOTE: deliberately OUTSIDE static/ â€” files here must only ever be served
# through the authenticated/authorized Flask routes below (send_file), never
# via Flask's automatic static-file handler.
UPLOAD_DIR    = os.path.join(BASE_DIR, 'private_storage', 'uploads')
QR_DIR        = os.path.join(BASE_DIR, 'static', 'qrcodes')
SECRET_FILE   = os.path.join(BASE_DIR, 'instance', 'secret.key')

ALLOWED_EXT   = {'pdf', 'jpg', 'jpeg', 'png', 'docx', 'txt', 'bmp', 'webp', 'tiff', 'jfif'}
MAX_FILE_MB   = 16
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024

# Google Sign-In (Google Identity Services). The Client ID is public by
# design â€” it's baked into the page so the browser can talk to Google
# directly â€” but every credential that comes back is still verified
# server-side (see google_signin() below) before anyone is logged in.
GOOGLE_CLIENT_ID   = os.environ.get('GOOGLE_CLIENT_ID', '')
RESEND_API_KEY     = os.environ.get('RESEND_API_KEY', '').strip().strip('"\'')
MAIL_FROM          = (os.environ.get('MAIL_FROM') or 'SecureVault AI <support@securevault.de5.net>').strip().strip('"\'')

# Terms of Service / Privacy Policy — bump TERMS_VERSION whenever the legal
# text materially changes, so we know which version a given user agreed to.
TERMS_VERSION      = '2026-08-17'
LEGAL_UPDATED_DATE  = 'August 17, 2026'

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QR_DIR,     exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)

# Belt-and-suspenders: reject oversized request bodies at the Flask/Werkzeug
# level too, not just the manual MAX_FILE_SIZE check further down.
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# â”€â”€ No-store cache headers on every dynamic response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Without this, hitting the browser Back button after logout can re-show a
# bfcache'd copy of a page like /dashboard or /vault/<id> â€” full of real
# data â€” even though the user is no longer authenticated. Static assets
# (css/js/images) are left cacheable; every HTML/JSON page response is not.
@app.after_request
def add_no_cache_headers(response):
    if response.mimetype not in ('text/css', 'application/javascript', 'image/png',
                                  'image/jpeg', 'image/svg+xml', 'font/woff2'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    return response

# â”€â”€ Baseline security headers on every response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Defense-in-depth for data-in-transit / browser-side protections. HSTS is
# only sent once we know the site is actually being served over HTTPS
# (SESSION_COOKIE_SECURE=true in production) â€” sending it over plain HTTP
# would be a lie and can lock people out of an http-only dev box.
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    return response

@app.context_processor
def inject_globals():
    return {
        'google_client_id': GOOGLE_CLIENT_ID,
        'current_user': get_current_user(),
    }

# â”€â”€ Persistent secret key (survives restarts) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NOTE: on most hosting platforms local disk is wiped on redeploy. Prefer
# setting a FLASK_SECRET_KEY environment variable in production; this file
# is kept only as a convenient local-dev fallback.
if os.environ.get('FLASK_SECRET_KEY'):
    app.secret_key = os.environ['FLASK_SECRET_KEY']
elif os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_FILE, 'w') as f:
        f.write(app.secret_key)

# â”€â”€ Session config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SAMESITE']    = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY']    = True
# Set SESSION_COOKIE_SECURE=true in your environment once you're serving over
# HTTPS in production â€” cookies won't be sent over plain HTTP otherwise.
app.config['SESSION_COOKIE_SECURE']      = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Create tables on startup if they don't exist yet.
init_db()

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# Magic-byte signatures for the extensions we accept. This is a lightweight,
# dependency-free check (no libmagic install required) that catches the
# common "rename malware.exe to document.pdf" trick â€” it's not a full
# content-security scan, but it means the extension can't be trusted blindly
# anymore.
_FILE_SIGNATURES = {
    'pdf':  [b'%PDF-'],
    'png':  [b'\x89PNG\r\n\x1a\n'],
    'jpg':  [b'\xff\xd8\xff'],
    'jpeg': [b'\xff\xd8\xff'],
    'jfif': [b'\xff\xd8\xff'],
    'bmp':  [b'BM'],
    'tiff': [b'II*\x00', b'MM\x00*'],
    'webp': [b'RIFF'],  # full check (bytes 8-11 == 'WEBP') done below
    # .docx is a ZIP container (Office Open XML) â€” PK\x03\x04 rules out
    # anything that isn't a zip archive at all. It can't by itself tell a
    # .docx apart from a renamed .zip/.xlsx, but that's an acceptable
    # limitation for a project this size.
    'docx': [b'PK\x03\x04'],
}

def content_matches_extension(file_storage, ext):
    """Sniff the first bytes of the upload and check them against the
    claimed extension's known file signature. Returns True for extensions
    with no reliable signature (e.g. plain .txt)."""
    ext = ext.lower()
    sigs = _FILE_SIGNATURES.get(ext)
    if not sigs:
        return True  # e.g. .txt â€” no magic bytes to check
    file_storage.seek(0)
    header = file_storage.read(16)
    file_storage.seek(0)
    if ext == 'webp':
        return header[:4] == b'RIFF' and header[8:12] == b'WEBP'
    return any(header.startswith(sig) for sig in sigs)

def _wants_json():
    """True when the caller wants a JSON response instead of a redirect —
    used by actions (like Stop Sharing) that are triggered via fetch() from
    pages like Activity Log, so they can update in place instead of
    bouncing the user to the share-management page."""
    if request.is_json:
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept and 'text/html' not in accept

def send_encrypted_file(disk_path, download_name, as_attachment):
    """Decrypt a document from disk into memory and serve it â€” documents are
    encrypted at rest (services/crypto_utils.py), so nothing ever hands a
    raw ciphertext (or, before this feature, a raw plaintext path) straight
    to send_file(). mimetype is guessed from the real filename so browsers
    still render/download it correctly."""
    data = decrypt_path_to_bytes(disk_path)
    mimetype = mimetypes.guess_type(download_name)[0] or 'application/octet-stream'
    return send_file(
        io.BytesIO(data),
        mimetype=mimetype,
        as_attachment=as_attachment,
        download_name=download_name
    )

def try_consume_view(table, id_column, id_value, limit_value):
    """Atomically grant one 'view' against a view_limit, in a single UPDATE,
    instead of a separate SELECT-check followed by an UPDATE-increment.

    The old check-then-increment pattern (read view_count, compare in Python,
    then run a second UPDATE) has a race: two simultaneous requests can both
    read the count *before* either write lands, both see themselves as under
    the limit, and both increment â€” letting the limit be exceeded by more
    than one visitor at once. Folding the check into the UPDATE's WHERE
    clause makes the database enforce it atomically per-row, so only as many
    concurrent requests as are actually still under the limit can succeed.

    Returns True (and has already incremented view_count) if this view was
    granted, False if the limit was already reached (row left untouched).
    `table`/`id_column` are always fixed literals from the call sites below,
    never request data, so the f-string is safe here.
    """
    db = get_db()
    cur = db.cursor()
    cur.execute(
        f"UPDATE {table} SET view_count = view_count + 1 "
        f"WHERE {id_column} = %s AND view_count < %s RETURNING view_count",
        (id_value, limit_value)
    )
    row = cur.fetchone()
    db.commit()
    return row is not None

def hash_access_code(code):
    """Hash a per-document access code the same way passwords are hashed.
    Returns None if code is falsy so 'no access code set' stays representable."""
    if not code:
        return None
    return bcrypt.hashpw(code.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_access_code(entered, stored_hash):
    if not entered or not stored_hash:
        return False
    try:
        return bcrypt.checkpw(entered.encode('utf-8'), stored_hash.encode('utf-8'))
    except ValueError:
        # stored_hash isn't a valid bcrypt hash (e.g. leftover plaintext from
        # before this fix) â€” treat as no match rather than raising.
        return False

def valid_email(email):
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email))

def safe_next_url(target):
    """Only allow redirecting to a same-site relative path (e.g. '/vault/xyz'),
    never an absolute/external URL â€” prevents open-redirect phishing via
    ?next=https://evil.example.com."""
    if not target:
        return None
    # Must start with a single '/', not '//' (protocol-relative -> external)
    # or '/\' (some browsers treat as protocol-relative too), and must not
    # parse out a netloc/scheme of its own.
    if not target.startswith('/') or target.startswith('//') or target.startswith('/\\'):
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    return target

def generate_vault_id():
    return secrets.token_urlsafe(16)

def log_audit_event(event_type, actor_email=None, details=None):
    """Record a security-relevant event to the audit_logs table.

    NEVER pass document contents, passwords, access codes, share tokens, or
    other secrets in `details` â€” it's metadata only (e.g. a filename, a doc
    count, a failure reason like 'bad_password'). Best-effort: a logging
    failure must never break the request it's describing.
    """
    try:
        db = get_db()
        cur = db.cursor()
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        ua = request.user_agent.string if request.user_agent else 'Unknown'
        cur.execute(
            "INSERT INTO audit_logs (event_type, actor_email, ip_address, user_agent, details) "
            "VALUES (%s, %s, %s, %s, %s)",
            (event_type, actor_email, ip, ua, details)
        )
        db.commit()
    except Exception:
        app.logger.exception("log_audit_event failed for event_type=%s", event_type)

@app.template_filter('friendly_date')
def friendly_date(value):
    """Presentation-only helper: '2026-08-12T10:23:45' -> 'Aug 12, 2026'.
    Used by the simplified document cards / share summaries so non-technical
    users see a plain date instead of a raw ISO timestamp. Falls back to a
    plain YYYY-MM-DD slice if the value can't be parsed."""
    if not value:
        return ''
    try:
        dt = datetime.fromisoformat(str(value)[:19])
        day = dt.strftime('%d').lstrip('0') or '0'
        return f"{dt.strftime('%b')} {day}, {dt.strftime('%Y')}"
    except (ValueError, TypeError):
        return str(value)[:10]

def get_text_size(draw, text, font):
    if hasattr(draw, 'textbbox'):
        bbox = draw.textbbox((0, 0), text, font=font)
        return (bbox[2] - bbox[0], bbox[3] - bbox[1])
    elif hasattr(draw, 'textsize'):
        return draw.textsize(text, font=font)
    return (100, 20)

def _find_font(bold=False):
    """Look for a usable TTF font across Windows/Linux/Mac; None if none found."""
    candidates = [
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

def generate_qr_card(name, url, output_path):
    card_w, card_h = 400, 520
    border_color = (30, 41, 59) # Slate 800
    text_color = (15, 23, 42)    # Slate 900
    muted_color = (100, 116, 139) # Slate 500
    
    img = Image.new("RGBA", (card_w, card_h), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw rounded card body
    draw.rounded_rectangle([5, 5, card_w - 5, card_h - 5], radius=20, fill=(255, 255, 255, 255), outline=border_color, width=4)
    
    # Draw a small decorative accent line
    draw.line([150, 40, 250, 40], fill=muted_color, width=2)
    
    font_path_bold = _find_font(bold=True)
    font_path_reg  = _find_font(bold=False)

    if font_path_bold and font_path_reg:
        font_header = ImageFont.truetype(font_path_bold, 22)
        font_sub    = ImageFont.truetype(font_path_reg, 12)
        font_name   = ImageFont.truetype(font_path_bold, 16)
    else:
        font_header = ImageFont.load_default()
        font_sub    = ImageFont.load_default()
        font_name   = ImageFont.load_default()
        
    # Header Text
    header_text = "SECURE VAULT"
    w, h = get_text_size(draw, header_text, font_header)
    draw.text(((card_w - w) / 2, 55), header_text, fill=text_color, font=font_header)
    
    # Subtitle
    sub_text = "SCAN TO ACCESS DOCUMENT"
    sw, sh = get_text_size(draw, sub_text, font_sub)
    draw.text(((card_w - sw) / 2, 90), sub_text, fill=muted_color, font=font_sub)
    
    # Generate QR Code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=0
    )
    qr.add_data(url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="#0f172a", back_color="white").convert("RGBA")
    
    # Resize QR code to fit card
    qr_size = 260
    qr_img = qr_img.resize((qr_size, qr_size), Image.Resampling.LANCZOS)
    
    # Paste QR code centered
    qr_x = (card_w - qr_size) // 2
    qr_y = 130
    img.paste(qr_img, (qr_x, qr_y), qr_img)
    
    # Draw border around QR code
    draw.rectangle([qr_x - 5, qr_y - 5, qr_x + qr_size + 5, qr_y + qr_size + 5], outline=(226, 232, 240), width=2)
    
    # Document/Vault Name
    display_name = name
    if len(display_name) > 30:
        ext = display_name.rsplit('.', 1)[-1] if '.' in display_name else ''
        base = display_name.rsplit('.', 1)[0] if '.' in display_name else display_name
        display_name = base[:25] + "..." + (f".{ext}" if ext else '')
        
    dw, dh = get_text_size(draw, display_name, font_name)
    draw.text(((card_w - dw) / 2, 430), display_name, fill=text_color, font=font_name)
    
    # Bottom security note
    footer_text = "Encrypted at Rest & Access-Controlled"
    fw, fh = get_text_size(draw, footer_text, font_sub)
    draw.text(((card_w - fw) / 2, 475), footer_text, fill=muted_color, font=font_sub)
    
    img.save(output_path, "PNG")
    return output_path

def generate_clean_qr(url, output_path, box_size=10, border=2):
    """Generate pure clean QR code image without outer frame or text labels."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
        border=border
    )
    qr.add_data(url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="#0f172a", back_color="white").convert("RGBA")
    qr_img.save(output_path, "PNG")
    return output_path

def generate_vault_qr(vault_name, vault_id, base_url):
    vault_url = f"{base_url}/vault/{vault_id}"
    # 1. Clean QR image for display in web UI
    clean_path = os.path.join(QR_DIR, f"{vault_id}.png")
    generate_clean_qr(vault_url, clean_path)
    # 2. Stylized card with title, name & security note for download
    card_path = os.path.join(QR_DIR, f"{vault_id}_card.png")
    generate_qr_card(vault_name, vault_url, card_path)
    return clean_path

def generate_doc_qr(doc_name, doc_id, base_url):
    doc_url = f"{base_url}/document/{doc_id}"
    # 1. Clean QR image for web display
    clean_path = os.path.join(QR_DIR, f"doc_{doc_id}.png")
    generate_clean_qr(doc_url, clean_path)
    # 2. Stylized card for download
    card_path = os.path.join(QR_DIR, f"doc_{doc_id}_card.png")
    generate_qr_card(doc_name, doc_url, card_path)
    return clean_path

def generate_share_qr(display_name, share_id, share_url):
    """Same clean-vs-card split as document/vault QRs: a plain QR (no
    header/footer text) for inline on-screen display, and a separate
    stylized card (with the SecureVault header, name & security footer)
    used only for the downloadable QR file."""
    clean_path = os.path.join(QR_DIR, f"share_{share_id}.png")
    generate_clean_qr(share_url, clean_path)
    card_path = os.path.join(QR_DIR, f"share_{share_id}_card.png")
    generate_qr_card(display_name, share_url, card_path)
    return clean_path

# â”€â”€ Data access helpers (replace old load_db/save_db) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def get_user(email):
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    return to_iso(cur.fetchone())

def get_user_by_google_id(google_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
    return to_iso(cur.fetchone())

def get_vault(vault_id, with_documents=True):
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM vaults WHERE vault_id = %s", (vault_id,))
    vault = to_iso(cur.fetchone())
    if vault and with_documents:
        cur.execute(
            "SELECT * FROM documents WHERE vault_id = %s ORDER BY upload_date",
            (vault_id,)
        )
        vault['documents'] = to_iso_all(cur.fetchall())
    return vault

def get_document(vault_id, doc_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM documents WHERE vault_id = %s AND doc_id = %s",
        (vault_id, doc_id)
    )
    return to_iso(cur.fetchone())

def touch_vault(vault_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE vaults SET updated_at = now() WHERE vault_id = %s", (vault_id,))

def get_current_user():
    """Return user dict if logged in, else None."""
    email = session.get('user_email')
    if not email:
        return None
    return get_user(email)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            flash('Please login to continue.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# â”€â”€ Auth helper for vault routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _auth_vault(vault_id, with_documents=True):
    vault = get_vault(vault_id, with_documents=with_documents)
    if not vault or session.get('user_email') != vault['owner_email']:
        abort(403)
    return vault

def _auth_share(vault_id, share_id):
    """Confirm `share_id` actually belongs to `vault_id` (which the caller
    must already own â€” call _auth_vault first). share_logs has no vault_id
    column of its own, so every route that looks up logs/details by share_id
    alone must go through this check first, or an authenticated user who
    owns *any* vault could read/delete another user's share activity by
    supplying that vault_id alongside a share_id they don't actually own."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM shared_links WHERE share_id = %s AND vault_id = %s", (share_id, vault_id))
    if not cur.fetchone():
        abort(404)

# â”€â”€ Home â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# ── Google Search Console Verification ────────────────────────────────────────
@app.route('/googlebf50c296d7f840e5.html')
def google_verification():
    return send_from_directory(BASE_DIR, 'googlebf50c296d7f840e5.html')


@app.route('/')
def index():
    user = get_current_user()
    return render_template('index.html', user=user)

# â”€â”€ Legal: Terms of Service / Privacy Policy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/terms')
def terms_page():
    return render_template('terms.html', legal_updated_date=LEGAL_UPDATED_DATE)


@app.route('/privacy')
def privacy_page():
    return render_template('privacy.html', legal_updated_date=LEGAL_UPDATED_DATE)


# â”€â”€ Register â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute;50 per hour", methods=["POST"])
def register():
    if get_current_user():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email       = request.form.get('email', '').strip().lower()
        name        = request.form.get('name', '').strip()
        password    = request.form.get('password', '')
        confirm     = request.form.get('confirm_password', '')
        agree_terms = request.form.get('agree_terms') == 'on'

        if not valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html')
        if not name:
            flash('Please enter your name.', 'error')
            return render_template('register.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        if not agree_terms:
            flash('Please agree to the Terms of Service and Privacy Policy to create an account.', 'error')
            return render_template('register.html')

        existing_user = get_user(email)
        db  = get_db()
        cur = db.cursor()

        if existing_user:
            if existing_user.get('email_verified', True):
                flash('An account with this email already exists and is verified. Please log in.', 'error')
                return redirect(url_for('login'))
            else:
                # Update registration details for unverified account
                cur.execute(
                    "UPDATE users SET name=%s, password_hash=%s, terms_accepted_at=%s, terms_version=%s WHERE email=%s",
                    (name, generate_password_hash(password), datetime.utcnow(), TERMS_VERSION, email)
                )
        else:
            # Create user in unverified state
            cur.execute(
                "INSERT INTO users (email, name, password_hash, email_verified, terms_accepted_at, terms_version) "
                "VALUES (%s, %s, %s, FALSE, %s, %s)",
                (email, name, generate_password_hash(password), datetime.utcnow(), TERMS_VERSION)
            )

        # Invalidate any previous unused verification codes
        cur.execute(
            "UPDATE email_verification_codes SET used=TRUE WHERE email=%s AND used=FALSE",
            (email,)
        )

        # Generate 6-digit secure code
        code      = str(secrets.randbelow(900000) + 100000)
        code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()
        from datetime import timezone
        expires   = datetime.now(timezone.utc) + timedelta(minutes=10)

        cur.execute(
            "INSERT INTO email_verification_codes (email, code_hash, expires_at) VALUES (%s, %s, %s)",
            (email, code_hash, expires)
        )

        email_sent = _send_verification_email(email, code)
        if not email_sent:
            db.rollback()
            err_reason = _last_email_error or "Please check your email configuration and try again."
            app.logger.error("Verification email could not be sent to %s: %s", email, err_reason)
            flash(f"Could not send verification email: {err_reason}", "error")
            return redirect(url_for("register"))

        db.commit()
        log_audit_event('registration_initiated', actor_email=email)

        session['verification_email'] = email
        flash('A 6-digit verification code has been sent to your email. Enter it below to activate your account.', 'success')
        return redirect(url_for('verify_email'))

    return render_template('register.html')


# â”€â”€ Verify Email (Registration Activation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/verify-email', methods=['GET', 'POST'])
@limiter.limit('10 per minute;30 per hour', methods=['POST'])
def verify_email():
    if get_current_user():
        return redirect(url_for('dashboard'))

    verification_email = session.get('verification_email')
    if not verification_email:
        flash('No pending registration session found. Please register or log in.', 'error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered = request.form.get('code', '').strip()
        db  = get_db()
        cur = db.cursor()

        cur.execute(
            """
            SELECT id, code_hash, expires_at, attempts
            FROM email_verification_codes
            WHERE email=%s AND used=FALSE
            ORDER BY created_at DESC LIMIT 1
            """,
            (verification_email,)
        )
        row = cur.fetchone()

        if not row:
            flash('No active verification code found. Please request a new code.', 'error')
            return render_template('verify_email.html', email=verification_email)

        if row['attempts'] >= 5:
            cur.execute("UPDATE email_verification_codes SET used=TRUE WHERE id=%s", (row['id'],))
            db.commit()
            flash('Too many incorrect attempts. Please request a new verification code.', 'error')
            return render_template('verify_email.html', email=verification_email)

        from datetime import timezone
        now = datetime.now(timezone.utc)
        exp = row['expires_at']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            cur.execute("UPDATE email_verification_codes SET used=TRUE WHERE id=%s", (row['id'],))
            db.commit()
            flash('This verification code has expired. Please click "Resend Code".', 'error')
            return render_template('verify_email.html', email=verification_email)

        if bcrypt.checkpw(entered.encode(), row['code_hash'].encode()):
            # Mark code used and activate user account
            cur.execute("UPDATE email_verification_codes SET used=TRUE WHERE id=%s", (row['id'],))
            cur.execute("UPDATE users SET email_verified=TRUE WHERE email=%s", (verification_email,))
            db.commit()
            log_audit_event('email_verified', actor_email=verification_email)
            session.pop('verification_email', None)

            flash('Email verified successfully. Your SecureVault account is ready.', 'success')
            return redirect(url_for('login'))
        else:
            cur.execute("UPDATE email_verification_codes SET attempts=attempts+1 WHERE id=%s", (row['id'],))
            db.commit()
            remaining = 4 - row['attempts']
            flash(f'Incorrect verification code. {remaining} attempt{"s" if remaining != 1 else ""} remaining.', 'error')

    return render_template('verify_email.html', email=verification_email)


@app.route('/resend-verification-code', methods=['POST'])
@limiter.limit('3 per minute;6 per hour')
def resend_verification_code():
    verification_email = session.get('verification_email')
    if not verification_email:
        flash('Session expired. Please register again.', 'error')
        return redirect(url_for('register'))

    db  = get_db()
    cur = db.cursor()
    cur.execute("UPDATE email_verification_codes SET used=TRUE WHERE email=%s AND used=FALSE", (verification_email,))
    code      = str(secrets.randbelow(900000) + 100000)
    code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()
    from datetime import timezone
    expires   = datetime.now(timezone.utc) + timedelta(minutes=10)
    cur.execute(
        "INSERT INTO email_verification_codes (email, code_hash, expires_at) VALUES (%s, %s, %s)",
        (verification_email, code_hash, expires)
    )
    email_sent = _send_verification_email(verification_email, code)
    if not email_sent:
        db.rollback()
        err_reason = _last_email_error or "Please try again later."
        app.logger.error("Verification email could not be sent on resend: %s", err_reason)
        flash(f"Could not resend verification email: {err_reason}", "error")
        return redirect(url_for('verify_email'))

    db.commit()
    log_audit_event('verification_code_resend', actor_email=verification_email)

    flash('A fresh verification code has been sent to your email.', 'success')
    return redirect(url_for('verify_email'))


# â”€â”€ Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute;50 per hour", methods=["POST"])
def login():
    if get_current_user():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('login.html')
        if not password:
            flash('Please enter your password.', 'error')
            return render_template('login.html')

        user = get_user(email)

        if not user:
            log_audit_event('login_failed', actor_email=email, details='no_such_account')
            flash('No account found with this email. Please register first.', 'error')
            return render_template('login.html')

        if not user.get('password_hash'):
            flash('This account signs in with Google. Use "Continue with Google" below.', 'error')
            return render_template('login.html')

        if check_password_hash(user['password_hash'], password):
            # Check if email has been verified
            if not user.get('email_verified', True):
                # Resend fresh verification code
                db  = get_db()
                cur = db.cursor()
                cur.execute("UPDATE email_verification_codes SET used=TRUE WHERE email=%s AND used=FALSE", (email,))
                code      = str(secrets.randbelow(900000) + 100000)
                code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()
                from datetime import timezone
                expires   = datetime.now(timezone.utc) + timedelta(minutes=10)
                cur.execute("INSERT INTO email_verification_codes (email, code_hash, expires_at) VALUES (%s, %s, %s)", (email, code_hash, expires))
                email_sent = _send_verification_email(email, code)
                if not email_sent:
                    db.rollback()
                    app.logger.error("Verification email could not be sent during login")
                    flash("We could not send the verification email. Please try again later.", "error")
                    return render_template('login.html')

                db.commit()
                session['verification_email'] = email
                flash('Please verify your email before signing in. A fresh verification code has been sent.', 'error')
                return redirect(url_for('verify_email'))

            session.permanent = True
            session['user_email'] = email
            session['user_name']  = user.get('name', '')
            log_audit_event('login_success', actor_email=email)
            next_page = safe_next_url(request.args.get('next'))
            flash(f"Welcome back, {user.get('name') or email}!", 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            log_audit_event('login_failed', actor_email=email, details='bad_password')
            flash('Incorrect password. Please try again.', 'error')

    return render_template('login.html')


# â”€â”€ Logout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/logout')
def logout():
    email = session.get('user_email')
    if email:
        log_audit_event('logout', actor_email=email)
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


# ── Registration Email Helper ────────────────────────────────────────────────
_last_email_error = ""

def _safe_log_resend_error(exc: Exception, api_key: str = "") -> str:
    """Log Resend error details safely without leaking API keys or secrets."""
    err_type = getattr(exc, 'error_type', type(exc).__name__)
    err_code = getattr(exc, 'code', '')
    err_msg = getattr(exc, 'message', str(exc))
    suggestion = getattr(exc, 'suggested_action', '')

    clean_msg = str(err_msg) if err_msg else type(exc).__name__
    clean_sug = str(suggestion) if suggestion else ""

    # Redact any API keys or credentials if present in message or suggestion
    if api_key and len(api_key) > 4:
        clean_msg = clean_msg.replace(api_key, "[REDACTED_API_KEY]")
        clean_sug = clean_sug.replace(api_key, "[REDACTED_API_KEY]")
    clean_msg = re.sub(r're_[a-zA-Z0-9_]{10,}', '[REDACTED_API_KEY]', clean_msg)
    clean_sug = re.sub(r're_[a-zA-Z0-9_]{10,}', '[REDACTED_API_KEY]', clean_sug)

    log_detail = f"Resend email failed: error_type={err_type}, code={err_code}, message='{clean_msg}'"
    if clean_sug:
        log_detail += f", suggested_action='{clean_sug}'"

    app.logger.error(log_detail)
    return clean_msg

def _send_verification_email(to_email: str, code: str) -> bool:
    """Send a 6-digit registration verification code via Resend HTTPS API."""
    global _last_email_error
    _last_email_error = ""

    api_key = (os.environ.get('RESEND_API_KEY') or RESEND_API_KEY or '').strip().strip('"\'')
    mail_from = (os.environ.get('MAIL_FROM') or MAIL_FROM or '').strip().strip('"\'')
    if not api_key or not mail_from:
        _last_email_error = "RESEND_API_KEY or MAIL_FROM is not configured"
        app.logger.error("RESEND_API_KEY or MAIL_FROM is not configured")
        return False

    # Check for unverified public webmail domains in MAIL_FROM
    mail_from_addr = mail_from.split('<')[-1].replace('>', '').strip().lower()
    if any(mail_from_addr.endswith(f"@{domain}") for domain in ('gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com')):
        app.logger.warning(
            "MAIL_FROM '%s' uses a public webmail domain. Resend requires sending from onboarding@resend.dev "
            "or a custom domain verified in your Resend dashboard (https://resend.com/domains).",
            mail_from
        )

    try:
        resend.api_key = api_key

        text_body = (
            "Hello,\n\n"
            "You requested to create a SecureVault account.\n\n"
            f"Your verification code is: {code}\n\n"
            "This code expires in 10 minutes. Enter it on the SecureVault verification page to complete registration.\n\n"
            "If you did not request this code, you can ignore this email.\n\n"
            "SecureVault AI Support"
        )
        html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="font-family: Arial, sans-serif; font-size: 15px; line-height: 1.6; color: #333333; margin: 0; padding: 20px;">
  <p style="margin: 0 0 16px;">Hello,</p>
  <p style="margin: 0 0 16px;">You requested to create a SecureVault account.</p>
  <p style="margin: 0 0 16px;">Your verification code is: <strong>{code}</strong></p>
  <p style="margin: 0 0 16px;">This code expires in 10 minutes. Enter it on the SecureVault verification page to complete registration.</p>
  <p style="margin: 0 0 16px;">If you did not request this code, you can ignore this email.</p>
  <p style="margin: 0;">SecureVault AI Support</p>
</body>
</html>"""
        res = resend.Emails.send({
            "from": mail_from,
            "to": [to_email.strip().lower()],
            "subject": "Your SecureVault verification code",
            "text": text_body,
            "html": html_body,
        })
        app.logger.info("Resend verification email sent to %s (id: %s)", to_email, getattr(res, 'id', 'ok') if not isinstance(res, dict) else res.get('id', 'ok'))
        return True
    except Exception as exc:
        _last_email_error = _safe_log_resend_error(exc, api_key=api_key)
        return False

# ── Forgot Password / Password Reset ──────────────────────────────────────────
# Email helper — uses Resend HTTPS API. Configure RESEND_API_KEY and MAIL_FROM in .env.
def _send_reset_email(to_email: str, code: str) -> bool:
    """Send a 6-digit reset code via Resend HTTPS API. Returns True on success."""
    global _last_email_error
    _last_email_error = ""

    api_key = (os.environ.get('RESEND_API_KEY') or RESEND_API_KEY or '').strip().strip('"\'')
    mail_from = (os.environ.get('MAIL_FROM') or MAIL_FROM or '').strip().strip('"\'')
    if not api_key or not mail_from:
        _last_email_error = "RESEND_API_KEY or MAIL_FROM is not configured"
        app.logger.error("RESEND_API_KEY or MAIL_FROM is not configured")
        return False

    # Check for unverified public webmail domains in MAIL_FROM
    mail_from_addr = mail_from.split('<')[-1].replace('>', '').strip().lower()
    if any(mail_from_addr.endswith(f"@{domain}") for domain in ('gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com')):
        app.logger.warning(
            "MAIL_FROM '%s' uses a public webmail domain. Resend requires sending from onboarding@resend.dev "
            "or a custom domain verified in your Resend dashboard (https://resend.com/domains).",
            mail_from
        )

    try:
        resend.api_key = api_key

        text_body = (
            f'Your SecureVault password reset code is: {code}\n\n'
            'This code expires in 10 minutes.\n\n'
            'If you did not request a password reset, ignore this email.\n'
            'Never share this code with anyone.\n\n'
            '— SecureVault Security Team'
        )
        html_body = f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#080e16;font-family:'IBM Plex Sans',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#080e16;padding:40px 0;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0"
             style="background:#0d1724;border:1px solid rgba(245,241,232,0.08);
                    border-radius:16px;overflow:hidden;">
        <tr>
          <td style="background:#0d1724;padding:32px 40px 24px;
                     border-bottom:1px solid rgba(245,241,232,0.07);">
            <p style="margin:0;font-size:22px;font-weight:600;color:#f5f1e8;letter-spacing:-0.02em;">
              &#x1F512; SecureVault
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:32px 40px;">
            <p style="margin:0 0 8px;font-size:16px;font-weight:600;color:#f5f1e8;">Password Reset Request</p>
            <p style="margin:0 0 28px;font-size:14px;color:rgba(245,241,232,0.5);line-height:1.6;">
              We received a request to reset your SecureVault password.
              Use the code below to continue. If you didn't request this, ignore this email.
            </p>
            <div style="background:#131f30;border:1px solid rgba(169,130,47,0.3);
                        border-radius:12px;padding:24px;text-align:center;margin-bottom:28px;">
              <p style="margin:0 0 6px;font-size:11px;font-weight:600;
                        letter-spacing:0.1em;text-transform:uppercase;color:#a9822f;">Your Verification Code</p>
              <p style="margin:0;font-size:40px;font-weight:700;letter-spacing:0.12em;
                        color:#f5f1e8;font-family:'Courier New',monospace;">{code}</p>
            </div>
            <div style="background:rgba(169,130,47,0.06);border:1px solid rgba(169,130,47,0.15);
                        border-radius:8px;padding:14px 18px;margin-bottom:24px;">
              <p style="margin:0;font-size:13px;color:rgba(245,241,232,0.6);line-height:1.5;">
                &#x23F0; This code expires in <strong style="color:#f5f1e8;">10 minutes</strong>.
              </p>
            </div>
            <div style="background:rgba(185,28,28,0.06);border:1px solid rgba(185,28,28,0.2);
                        border-radius:8px;padding:14px 18px;">
              <p style="margin:0;font-size:13px;color:rgba(245,241,232,0.55);line-height:1.5;">
                &#x26A0; <strong style="color:#e05c52;">Never share this code</strong> with anyone,
                including SecureVault support. We will never ask for it.
              </p>
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 40px 28px;border-top:1px solid rgba(245,241,232,0.07);">
            <p style="margin:0;font-size:12px;color:rgba(245,241,232,0.28);">
              SecureVault &mdash; your documents, always sealed.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
        res = resend.Emails.send({
            "from": mail_from,
            "to": [to_email.strip().lower()],
            "subject": "SecureVault — Password Reset Code",
            "text": text_body,
            "html": html_body,
        })
        app.logger.info("Resend reset email sent to %s (id: %s)", to_email, getattr(res, 'id', 'ok') if not isinstance(res, dict) else res.get('id', 'ok'))
        return True
    except Exception as exc:
        _last_email_error = _safe_log_resend_error(exc, api_key=api_key)
        return False


@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit('5 per minute;15 per hour', methods=['POST'])
def forgot_password():
    """Step 1 â€” collect email and dispatch a 6-digit reset code."""
    prefill_email = session.get('user_email', '')

    if request.method == 'POST':
        raw_email = request.form.get('email', '').strip().lower()

        if not valid_email(raw_email):
            flash('Please enter a valid email address.', 'error')
            return render_template('forgot_password.html', prefill_email=prefill_email)

        # Always show the same generic message â€” never leak whether the
        # email is registered (account enumeration prevention).
        user = get_user(raw_email)
        if user and user.get('password_hash') and user.get('email_verified', True):
            db  = get_db()
            cur = db.cursor()

            # Invalidate any existing unused codes for this email
            cur.execute(
                "UPDATE password_reset_codes SET used=TRUE WHERE email=%s AND used=FALSE",
                (raw_email,)
            )

            # Generate cryptographically random 6-digit code
            code      = str(secrets.randbelow(900000) + 100000)   # 100000-999999
            code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()
            from datetime import timezone
            expires   = datetime.now(timezone.utc) + timedelta(minutes=10)

            cur.execute(
                """
                INSERT INTO password_reset_codes (email, code_hash, expires_at)
                VALUES (%s, %s, %s)
                """,
                (raw_email, code_hash, expires)
            )
            db.commit()

            _send_reset_email(raw_email, code)
            log_audit_event('password_reset_requested', actor_email=raw_email)

        # Store email in session so verify_code knows which account
        session['reset_email'] = raw_email
        session.pop('reset_verified', None)

        flash(
            'If an account exists for this email, a 6-digit code has been sent. '
            'Check your inbox (and spam folder).',
            'success'
        )
        return redirect(url_for('verify_code'))

    return render_template('forgot_password.html', prefill_email=prefill_email)


@app.route('/verify-code', methods=['GET', 'POST'])
@limiter.limit('10 per minute;30 per hour', methods=['POST'])
def verify_code():
    """Step 2 â€” verify the 6-digit code."""
    reset_email = session.get('reset_email')
    if not reset_email:
        flash('Session expired. Please start again.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered = request.form.get('code', '').strip()
        db  = get_db()
        cur = db.cursor()

        # Fetch the latest unused, unexpired code for this email
        cur.execute(
            """
            SELECT id, code_hash, expires_at, attempts
            FROM password_reset_codes
            WHERE email=%s AND used=FALSE
            ORDER BY created_at DESC LIMIT 1
            """,
            (reset_email,)
        )
        row = cur.fetchone()

        if not row:
            flash('No active reset code found. Please request a new one.', 'error')
            return render_template('verify_code.html', email=reset_email)

        # Max 5 attempts
        if row['attempts'] >= 5:
            cur.execute(
                "UPDATE password_reset_codes SET used=TRUE WHERE id=%s", (row['id'],)
            )
            db.commit()
            flash('Too many incorrect attempts. Please request a new code.', 'error')
            return redirect(url_for('forgot_password'))

        # Check expiry
        from datetime import timezone
        now = datetime.now(timezone.utc)
        exp = row['expires_at']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            cur.execute(
                "UPDATE password_reset_codes SET used=TRUE WHERE id=%s", (row['id'],)
            )
            db.commit()
            flash('This code has expired. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))

        # Verify code against hash
        if bcrypt.checkpw(entered.encode(), row['code_hash'].encode()):
            cur.execute(
                "UPDATE password_reset_codes SET used=TRUE WHERE id=%s", (row['id'],)
            )
            db.commit()
            session['reset_verified'] = True
            log_audit_event('password_reset_code_verified', actor_email=reset_email)
            return redirect(url_for('reset_password'))
        else:
            cur.execute(
                "UPDATE password_reset_codes SET attempts=attempts+1 WHERE id=%s",
                (row['id'],)
            )
            db.commit()
            remaining = 4 - row['attempts']
            flash(
                f'Incorrect code. {remaining} attempt{"s" if remaining != 1 else ""} remaining.',
                'error'
            )

    return render_template('verify_code.html', email=reset_email)


@app.route('/resend-code', methods=['POST'])
@limiter.limit('3 per minute;6 per hour')
def resend_code():
    """Resend a fresh reset code to the same email."""
    reset_email = session.get('reset_email')
    if not reset_email:
        flash('Session expired. Please start again.', 'error')
        return redirect(url_for('forgot_password'))

    user = get_user(reset_email)
    if user and user.get('password_hash') and user.get('email_verified', True):
        db  = get_db()
        cur = db.cursor()
        # Invalidate old codes
        cur.execute(
            "UPDATE password_reset_codes SET used=TRUE WHERE email=%s AND used=FALSE",
            (reset_email,)
        )
        code      = str(secrets.randbelow(900000) + 100000)
        code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()
        from datetime import timezone
        expires   = datetime.now(timezone.utc) + timedelta(minutes=10)
        cur.execute(
            "INSERT INTO password_reset_codes (email, code_hash, expires_at) VALUES (%s, %s, %s)",
            (reset_email, code_hash, expires)
        )
        db.commit()
        _send_reset_email(reset_email, code)
        log_audit_event('password_reset_resend', actor_email=reset_email)

    flash('A new code has been sent if an account exists for this email.', 'success')
    return redirect(url_for('verify_code'))


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Step 3 â€” set a new password after code is verified."""
    reset_email    = session.get('reset_email')
    reset_verified = session.get('reset_verified')

    if not reset_email or not reset_verified:
        flash('Unauthorized. Please complete the verification step first.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw  = request.form.get('new_password', '')
        conf_pw = request.form.get('confirm_password', '')

        if len(new_pw) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('reset_password.html')
        if new_pw != conf_pw:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')

        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE users SET password_hash=%s WHERE email=%s",
            (generate_password_hash(new_pw), reset_email)
        )
        db.commit()
        log_audit_event('password_reset_success', actor_email=reset_email)

        # Invalidate any lingering codes for this email
        cur.execute(
            "UPDATE password_reset_codes SET used=TRUE WHERE email=%s AND used=FALSE",
            (reset_email,)
        )
        db.commit()

        # Clear reset session keys & user session so they re-login
        session.pop('reset_email', None)
        session.pop('reset_verified', None)
        session.pop('user_email', None)
        session.pop('user_name', None)

        flash(
            'Your password has been successfully updated. You can now sign in with your new password.',
            'success'
        )
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# â”€â”€ Google Sign-In â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Verifies the ID token Google Identity Services hands back to the browser,
# never touches a Google password, and reuses the exact same session keys
# as the normal login() route above.
@app.route('/auth/google', methods=['POST'])
@limiter.limit("20 per minute;100 per hour")
def google_signin():
    if not GOOGLE_CLIENT_ID:
        return jsonify({'error': 'Google Sign-In is not configured on this server.'}), 503

    credential = request.form.get('credential')
    if not credential:
        return jsonify({'error': 'Missing Google credential.'}), 400

    try:
        payload = google_id_token.verify_oauth2_token(
            credential, google_auth_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError:
        log_audit_event('login_failed_google', details='token_verification_failed')
        return jsonify({'error': 'Could not verify Google sign-in. Please try again.'}), 401

    # verify_oauth2_token already checks signature, audience and expiry;
    # these two checks are Google's documented extra hardening on top.
    if payload.get('iss') not in ('accounts.google.com', 'https://accounts.google.com'):
        log_audit_event('login_failed_google', details='bad_issuer')
        return jsonify({'error': 'Invalid token issuer.'}), 401
    if not payload.get('email_verified', False):
        log_audit_event('login_failed_google', details='email_not_verified')
        return jsonify({'error': 'Your Google email is not verified.'}), 401

    google_id_value = payload['sub']
    email           = payload['email'].strip().lower()
    name            = payload.get('name') or email.split('@')[0]
    picture         = payload.get('picture')

    if not valid_email(email):
        return jsonify({'error': 'Google account email is invalid.'}), 400

    db  = get_db()
    cur = db.cursor()

    user = get_user_by_google_id(google_id_value)

    if user:
        # Returning Google user â€” keep name/photo fresh, nothing else changes.
        cur.execute(
            "UPDATE users SET name = %s, profile_picture = %s WHERE google_id = %s",
            (name, picture, google_id_value)
        )
    else:
        existing = get_user(email)
        if existing:
            # An account already exists for this email (e.g. they registered
            # with a password) â€” link Google to it instead of creating a
            # second account. Their password login keeps working exactly
            # as before; this just adds Google as an extra way in.
            cur.execute(
                "UPDATE users SET google_id = %s, email_verified = TRUE, "
                "profile_picture = COALESCE(%s, profile_picture) WHERE email = %s",
                (google_id_value, picture, email)
            )
        else:
            cur.execute(
                "INSERT INTO users (email, name, password_hash, google_id, profile_picture, auth_provider, email_verified) "
                "VALUES (%s, %s, NULL, %s, %s, 'google', TRUE)",
                (email, name, google_id_value, picture)
            )

    user = get_user(email)
    session.permanent = True
    session['user_email'] = user['email']
    session['user_name']  = user.get('name', '')
    log_audit_event('login_success_google', actor_email=user['email'])
    flash(f"Welcome, {user.get('name') or user['email']}!", 'success')

    return jsonify({'redirect': url_for('dashboard')})

@app.route('/dashboard')
@login_required
def dashboard():
    email = session['user_email']
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT vault_id, vault_name, created_at FROM vaults WHERE owner_email = %s ORDER BY created_at DESC",
        (email,)
    )
    all_vaults = to_iso_all(cur.fetchall())
    
    cur.execute("""
        SELECT d.*, v.vault_name
        FROM documents d
        JOIN vaults v ON d.vault_id = v.vault_id
        WHERE v.owner_email = %s
        ORDER BY d.upload_date DESC
    """, (email,))
    all_docs = to_iso_all(cur.fetchall())
    
    all_vault = {
        'vault_id': 'all',
        'vault_name': 'All Documents',
        'documents': all_docs,
        'is_all': True
    }
    return render_template('vault.html', vault=all_vault, vault_id='all', all_vaults=all_vaults)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_vault():
    if request.method == 'POST':
        vault_name = request.form.get('vault_name', '').strip()
        files      = request.files.getlist('documents')

        if not vault_name:
            flash('Please give your folder a name.', 'error')
            return render_template('create.html')
        if not files or all(f.filename == '' for f in files):
            flash('Please upload at least one document.', 'error')
            return render_template('create.html')

        vault_id  = generate_vault_id()
        vault_dir = os.path.join(UPLOAD_DIR, vault_id)
        os.makedirs(vault_dir, exist_ok=True)

        saved_docs, errors = [], []
        base_url = request.host_url.rstrip('/')
        
        for index, f in enumerate(files):
            if f.filename == '':
                continue
            if not allowed_file(f.filename):
                errors.append(f"{f.filename}: unsupported format.")
                continue
            claimed_ext = f.filename.rsplit('.', 1)[1].lower()
            if not content_matches_extension(f, claimed_ext):
                errors.append(f"{f.filename}: file content doesn't match its .{claimed_ext} extension.")
                continue
            f.seek(0, 2); size = f.tell(); f.seek(0)
            if size > MAX_FILE_SIZE:
                errors.append(f"{f.filename}: exceeds {MAX_FILE_MB} MB.")
                continue
            fname  = secure_filename(f.filename)
            unique = f"{uuid.uuid4().hex}_{fname}"
            # Files are encrypted at rest (services/crypto_utils.py) before
            # ever touching disk â€” size is measured from the plaintext the
            # user actually uploaded, not the (slightly larger) ciphertext.
            size = encrypt_stream_to_path(f, os.path.join(vault_dir, unique))
            
            doc_id = uuid.uuid4().hex
            
            # Parse access settings
            access_type = request.form.get(f'access_type_{index}', 'public')
            access_code = hash_access_code(request.form.get(f'access_code_{index}', '').strip() or None)
            
            view_limit = request.form.get(f'view_limit_{index}', '').strip()
            view_limit = int(view_limit) if (view_limit and view_limit.isdigit()) else None
            
            expires_hours = request.form.get(f'expires_hours_{index}', '').strip()
            expires_at = datetime.now() + timedelta(hours=int(expires_hours)) if (expires_hours and expires_hours.isdigit()) else None
            
            folder_name = request.form.get(f'folder_name_{index}', '').strip() or None
            
            doc_qr_path = generate_doc_qr(fname, doc_id, base_url)
            
            saved_docs.append({
                "doc_id":      doc_id,
                "filename":    fname,
                "stored_name": unique,
                "file_type":   fname.rsplit('.', 1)[1].lower(),
                "file_size":   size,
                "access_type": access_type,
                "access_code": access_code,
                "view_limit":  view_limit,
                "expires_at":  expires_at,
                "qr_path":     doc_qr_path,
                "folder_name": folder_name
            })

        if not saved_docs:
            flash('No valid documents uploaded. ' + ' '.join(errors), 'error')
            return render_template('create.html')

        email    = session['user_email']
        qr_path  = generate_vault_qr(vault_name, vault_id, base_url)

        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO vaults (vault_id, vault_name, owner_email, qr_path) "
            "VALUES (%s, %s, %s, %s)",
            (vault_id, vault_name, email, qr_path)
        )
        for doc in saved_docs:
            cur.execute(
                "INSERT INTO documents (doc_id, vault_id, filename, stored_name, "
                "file_type, file_size, access_type, access_code, expires_at, view_limit, qr_path, folder_name) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (doc["doc_id"], vault_id, doc["filename"], doc["stored_name"],
                 doc["file_type"], doc["file_size"], doc["access_type"], doc["access_code"],
                 doc["expires_at"], doc["view_limit"], doc["qr_path"], doc["folder_name"])
            )
            cur.execute(
                "INSERT INTO document_indexing_status (doc_id, status) VALUES (%s, 'pending')",
                (doc["doc_id"],)
            )

        db.commit()
        for doc in saved_docs:
            index_document_async(doc["doc_id"], vault_id, email)

        log_audit_event('upload', actor_email=email,
                         details=f"vault_created vault_id={vault_id} doc_count={len(saved_docs)}")

        if errors:
            flash('Some files skipped: ' + ' '.join(errors), 'warning')

        return redirect(url_for('vault_view', vault_id=vault_id))

    return render_template('create.html')

@app.route('/created/<vault_id>')
@login_required
def vault_created(vault_id):
    vault = get_vault(vault_id)
    if not vault or vault['owner_email'] != session['user_email']:
        abort(404)
    qr_url    = url_for('static', filename=f'qrcodes/{vault_id}.png')
    vault_url = f"{request.host_url.rstrip('/')}/vault/{vault_id}"
    return render_template('created.html', vault=vault, qr_url=qr_url, vault_url=vault_url)

# â”€â”€ QR Gate (public â€” for phone scan) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/vault/<vault_id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute;50 per hour", methods=["POST"])
def vault_gate(vault_id):
    vault = get_vault(vault_id, with_documents=True)
    if not vault:
        abort(404)

    # Already logged in as owner â†’ go straight in
    if session.get('user_email') == vault['owner_email']:
        return redirect(url_for('vault_view', vault_id=vault_id))

    return render_template('public_vault.html', vault=vault, vault_id=vault_id)

@app.route('/vault/<vault_id>/view')
def vault_view(vault_id):
    vault = get_vault(vault_id)
    if not vault:
        abort(404)
    if session.get('user_email') != vault['owner_email']:
        flash('Please log in to access this folder.', 'error')
        return redirect(url_for('vault_gate', vault_id=vault_id))
    email = vault['owner_email']
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT vault_id, vault_name FROM vaults WHERE owner_email = %s ORDER BY created_at DESC", (email,))
    all_vaults = to_iso_all(cur.fetchall())
    return render_template('vault.html', vault=vault, vault_id=vault_id, all_vaults=all_vaults)

# â”€â”€ File serving â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/vault/<vault_id>/file/<doc_id>')
@login_required
def serve_file(vault_id, doc_id):
    vault = _auth_vault(vault_id, with_documents=False)
    doc = get_document(vault_id, doc_id)
    if not doc: abort(404)
    return send_encrypted_file(os.path.join(UPLOAD_DIR, vault_id, doc['stored_name']),
                                doc['filename'], as_attachment=False)

@app.route('/vault/<vault_id>/download/<doc_id>')
@login_required
def download_file(vault_id, doc_id):
    vault = _auth_vault(vault_id, with_documents=False)
    doc = get_document(vault_id, doc_id)
    if not doc: abort(404)
    return send_encrypted_file(os.path.join(UPLOAD_DIR, vault_id, doc['stored_name']),
                                doc['filename'], as_attachment=True)

# â”€â”€ Rename â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/vault/<vault_id>/rename/<doc_id>', methods=['POST'])
@login_required
def rename_document(vault_id, doc_id):
    vault    = _auth_vault(vault_id, with_documents=False)
    new_name = request.form.get('new_name', '').strip()
    if not new_name:
        flash('Please provide a valid name.', 'error')
        return redirect(url_for('vault_view', vault_id=vault_id))
    doc = get_document(vault_id, doc_id)
    if doc:
        ext = doc['filename'].rsplit('.', 1)[-1].lower()
        if not new_name.lower().endswith(f'.{ext}'):
            new_name = f"{new_name}.{ext}"
        new_name = secure_filename(new_name)
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE documents SET filename = %s WHERE doc_id = %s AND vault_id = %s",
            (new_name, doc_id, vault_id)
        )
        touch_vault(vault_id)
        flash(f'Renamed to "{new_name}".', 'success')
    return redirect(url_for('vault_view', vault_id=vault_id))

# â”€â”€ Delete Vault â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def purge_doc_qr_file(doc_id):
    for path in (os.path.join(QR_DIR, f"doc_{doc_id}.png"),
                 os.path.join(QR_DIR, f"doc_{doc_id}_card.png")):
        if os.path.exists(path):
            os.remove(path)

def purge_share_qr_file(share_id):
    for path in (os.path.join(QR_DIR, f"share_{share_id}.png"),
                 os.path.join(QR_DIR, f"share_{share_id}_card.png")):
        if os.path.exists(path):
            os.remove(path)

def purge_qr_files_for_vault(vault_id):
    """Remove every QR PNG tied to a vault (its own QR, every document's QR,
    and every share link's QR) before the vault row is deleted. The DB rows
    for documents/shared_links cascade-delete automatically via foreign
    keys, but the generated image files on disk don't â€” without this,
    deleting a vault leaves its QR images behind forever (retention gap)."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT doc_id FROM documents WHERE vault_id = %s", (vault_id,))
    for row in cur.fetchall():
        purge_doc_qr_file(row['doc_id'])
    cur.execute("SELECT share_id FROM shared_links WHERE vault_id = %s", (vault_id,))
    for row in cur.fetchall():
        purge_share_qr_file(row['share_id'])
    for vault_qr in (os.path.join(QR_DIR, f"{vault_id}.png"),
                      os.path.join(QR_DIR, f"{vault_id}_card.png")):
        if os.path.exists(vault_qr):
            os.remove(vault_qr)

# ── Rename Vault / Folder ──────────────────────────────────────────────────
@app.route('/vault/<vault_id>/rename-vault', methods=['POST'])
@login_required
def rename_vault(vault_id):
    vault = _auth_vault(vault_id, with_documents=False)
    new_name = request.form.get('vault_name', '').strip()
    next_url = request.form.get('next') or url_for('vault_view', vault_id=vault_id)
    if not new_name:
        flash('Folder name cannot be empty.', 'error')
        return redirect(next_url)

    if len(new_name) > 60:
        flash('Folder name must be 60 characters or less.', 'error')
        return redirect(next_url)

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE vaults SET vault_name = %s, updated_at = now() WHERE vault_id = %s",
        (new_name, vault_id)
    )
    db.commit()

    try:
        base_url = request.host_url.rstrip('/')
        qr_path = generate_vault_qr(new_name, vault_id, base_url)
        cur.execute("UPDATE vaults SET qr_path = %s WHERE vault_id = %s", (qr_path, vault_id))
        db.commit()
    except Exception as e:
        logger.warning("Failed to regenerate QR card after folder rename: %s", e)

    log_audit_event('rename_vault', actor_email=session['user_email'],
                    details=f"vault_id={vault_id} old_name={vault['vault_name']} new_name={new_name}")
    flash(f'Folder renamed to "{new_name}".', 'success')
    return redirect(next_url)

# ── Delete Vault / Folder ──────────────────────────────────────────────────
@app.route('/vault/<vault_id>/delete-vault', methods=['POST'])
@login_required
def delete_vault(vault_id):
    vault = _auth_vault(vault_id, with_documents=False)
    doc_count = len(get_vault(vault_id, with_documents=True).get('documents', []))

    purge_qr_files_for_vault(vault_id)

    vault_dir = os.path.join(UPLOAD_DIR, vault_id)
    if os.path.isdir(vault_dir):
        shutil.rmtree(vault_dir, ignore_errors=True)

    db  = get_db()
    cur = db.cursor()
    # ON DELETE CASCADE removes: documents, document_chunks,
    # document_indexing_status, shared_links (and in turn shared_items,
    # share_logs for those links) â€” everything derived from this vault.
    cur.execute("DELETE FROM vaults WHERE vault_id = %s", (vault_id,))

    log_audit_event('delete_vault', actor_email=session['user_email'],
                     details=f"vault_id={vault_id} doc_count={doc_count}")
    flash(f'Folder "{vault["vault_name"]}" and all its documents were deleted.', 'success')
    return redirect(url_for('dashboard'))

# â”€â”€ Delete document â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/vault/<vault_id>/delete/<doc_id>', methods=['POST'])
@login_required
def delete_document(vault_id, doc_id):
    vault = _auth_vault(vault_id, with_documents=False)
    doc   = get_document(vault_id, doc_id)
    if doc:
        fpath = os.path.join(UPLOAD_DIR, vault_id, doc['stored_name'])
        if os.path.exists(fpath):
            os.remove(fpath)
        purge_doc_qr_file(doc_id)
        db  = get_db()
        cur = db.cursor()
        # ON DELETE CASCADE removes this doc's chunks, indexing status, and
        # its entry in any share's shared_items (the share link itself, if
        # it still has other items, is left intact).
        cur.execute(
            "DELETE FROM documents WHERE doc_id = %s AND vault_id = %s",
            (doc_id, vault_id)
        )
        touch_vault(vault_id)
        log_audit_event('delete_document', actor_email=session['user_email'],
                         details=f"vault_id={vault_id} doc_id={doc_id}")
        flash('Document deleted successfully.', 'success')
    return redirect(url_for('vault_view', vault_id=vault_id))

# â”€â”€ QR Download â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/vault/<vault_id>/qr')
def download_qr(vault_id):
    card_path = os.path.join(QR_DIR, f"{vault_id}_card.png")
    clean_path = os.path.join(QR_DIR, f"{vault_id}.png")
    path = card_path if os.path.exists(card_path) else clean_path
    if not os.path.exists(path):
        vault = get_vault(vault_id, with_documents=False)
        if vault:
            generate_vault_qr(vault['vault_name'], vault_id, request.host_url.rstrip('/'))
            path = card_path if os.path.exists(card_path) else clean_path
        else:
            abort(404)
    return send_file(path, as_attachment=True,
                     download_name=f"vault_qr_{vault_id[:8]}.png")

# â”€â”€ Combined PDF â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/vault/<vault_id>/pdf')
@login_required
def download_combined_pdf(vault_id):
    vault = _auth_vault(vault_id)
    buf  = io.BytesIO()
    c    = canvas.Canvas(buf, pagesize=A4)
    W, H = A4
    for doc in vault['documents']:
        fpath = os.path.join(UPLOAD_DIR, vault_id, doc['stored_name'])
        if not os.path.exists(fpath):
            continue
        ftype = doc['file_type']
        if ftype in ('jpg', 'jpeg', 'png'):
            try:
                img = ImageReader(io.BytesIO(decrypt_path_to_bytes(fpath)))
                iw, ih = img.getSize()
                ratio = min(W / iw, H / ih) * 0.9
                nw, nh = iw * ratio, ih * ratio
                c.drawImage(img, (W - nw) / 2, (H - nh) / 2, nw, nh)
                c.setFont("Helvetica", 9)
                c.drawString(30, 20, doc['filename'])
                c.showPage()
            except Exception:
                pass
        elif ftype == 'pdf':
            try:
                import fitz
                dp = fitz.open(stream=decrypt_path_to_bytes(fpath), filetype='pdf')
                for page in dp:
                    pix = page.get_pixmap(dpi=100)
                    id_ = io.BytesIO(pix.tobytes("png"))
                    img = ImageReader(id_)
                    iw, ih = pix.width, pix.height
                    ratio = min(W / iw, H / ih) * 0.9
                    nw, nh = iw * ratio, ih * ratio
                    c.drawImage(img, (W - nw) / 2, (H - nh) / 2, nw, nh)
                    c.setFont("Helvetica", 9)
                    c.drawString(30, 20, doc['filename'])
                    c.showPage()
                dp.close()
            except ImportError:
                c.setFont("Helvetica-Bold", 14)
                c.drawCentredString(W / 2, H / 2, f"[PDF] {doc['filename']}")
                c.showPage()
    c.save()
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=True,
                     download_name=f"vault_{vault_id[:8]}.pdf")

@app.route('/vault/<vault_id>/manage', methods=['GET', 'POST'])
@login_required
def manage_vault(vault_id):
    vault = _auth_vault(vault_id)
    if request.method == 'POST':
        files = request.files.getlist('documents')
        saved, errors = [], []
        base_url = request.host_url.rstrip('/')
        for index, f in enumerate(files):
            if f.filename == '':
                continue
            if not allowed_file(f.filename):
                errors.append(f"{f.filename}: unsupported.")
                continue
            claimed_ext = f.filename.rsplit('.', 1)[1].lower()
            if not content_matches_extension(f, claimed_ext):
                errors.append(f"{f.filename}: file content doesn't match its .{claimed_ext} extension.")
                continue
            f.seek(0, 2); size = f.tell(); f.seek(0)
            if size > MAX_FILE_SIZE:
                errors.append(f"{f.filename}: too large.")
                continue
            vault_dir = os.path.join(UPLOAD_DIR, vault_id)
            os.makedirs(vault_dir, exist_ok=True)
            fname  = secure_filename(f.filename)
            unique = f"{uuid.uuid4().hex}_{fname}"
            size = encrypt_stream_to_path(f, os.path.join(vault_dir, unique))
            
            doc_id = uuid.uuid4().hex
            
            # Parse access settings
            access_type = request.form.get(f'access_type_{index}', 'public')
            access_code = hash_access_code(request.form.get(f'access_code_{index}', '').strip() or None)
            
            view_limit = request.form.get(f'view_limit_{index}', '').strip()
            view_limit = int(view_limit) if (view_limit and view_limit.isdigit()) else None
            
            expires_hours = request.form.get(f'expires_hours_{index}', '').strip()
            expires_at = datetime.now() + timedelta(hours=int(expires_hours)) if (expires_hours and expires_hours.isdigit()) else None
            
            folder_name = request.form.get(f'folder_name_{index}', '').strip() or None
            
            doc_qr_path = generate_doc_qr(fname, doc_id, base_url)
            
            saved.append({
                "doc_id":      doc_id,
                "filename":    fname,
                "stored_name": unique,
                "file_type":   fname.rsplit('.', 1)[1].lower(),
                "file_size":   size,
                "access_type": access_type,
                "access_code": access_code,
                "view_limit":  view_limit,
                "expires_at":  expires_at,
                "qr_path":     doc_qr_path,
                "folder_name": folder_name
            })
        db  = get_db()
        cur = db.cursor()
        for doc in saved:
            cur.execute(
                "INSERT INTO documents (doc_id, vault_id, filename, stored_name, "
                "file_type, file_size, access_type, access_code, expires_at, view_limit, qr_path, folder_name) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (doc["doc_id"], vault_id, doc["filename"], doc["stored_name"],
                 doc["file_type"], doc["file_size"], doc["access_type"], doc["access_code"],
                 doc["expires_at"], doc["view_limit"], doc["qr_path"], doc["folder_name"])
            )
            cur.execute(
                "INSERT INTO document_indexing_status (doc_id, status) VALUES (%s, 'pending')",
                (doc["doc_id"],)
            )
        
        if saved:
            touch_vault(vault_id)
            db.commit()
            email = session['user_email']
            for doc in saved:
                index_document_async(doc["doc_id"], vault_id, email)
            log_audit_event('upload', actor_email=email,
                             details=f"vault_id={vault_id} doc_count={len(saved)}")

        if errors: flash('Skipped: ' + ' '.join(errors), 'warning')
        if saved:  flash(f'{len(saved)} document(s) added.', 'success')
        return redirect(url_for('vault_view', vault_id=vault_id))
    # Redirect GET requests â€” manage page is removed from UI
    return redirect(url_for('vault_view', vault_id=vault_id))

@app.route('/vault/<vault_id>/shared-links')
@login_required
def shared_links_page(vault_id):
    vault = _auth_vault(vault_id, with_documents=False)
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM shared_links WHERE vault_id = %s ORDER BY created_at DESC",
        (vault_id,)
    )
    share_links = to_iso_all(cur.fetchall())
    now_iso = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
    return render_template('shared_links.html', vault=vault, vault_id=vault_id, share_links=share_links, now_iso=now_iso)

# â”€â”€ Delete Account â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/account/delete', methods=['POST'])
@login_required
@limiter.limit("5 per minute;20 per hour")
def delete_account():
    user  = get_current_user()
    email = user['email']

    confirm_text = request.form.get('confirm_text', '').strip()
    if confirm_text != 'DELETE':
        flash('Please type DELETE to confirm account deletion.', 'error')
        return redirect(url_for('security_page'))

    # Local (password) accounts must re-enter their password; Google-only
    # accounts (no password_hash) rely on the typed-DELETE confirmation
    # above plus their already-authenticated session, since there's no
    # local password to check.
    if user.get('password_hash'):
        entered_pw = request.form.get('password', '')
        if not entered_pw or not check_password_hash(user['password_hash'], entered_pw):
            log_audit_event('delete_account_failed', actor_email=email, details='bad_password')
            flash('Incorrect password. Account was not deleted.', 'error')
            return redirect(url_for('security_page'))

    db  = get_db()
    cur = db.cursor()

    cur.execute("SELECT vault_id FROM vaults WHERE owner_email = %s", (email,))
    vault_ids = [row['vault_id'] for row in cur.fetchall()]
    vault_count = len(vault_ids)

    # Remove files and QR images for every vault first â€” the DB rows are
    # about to cascade-delete, but files on disk never do.
    for vault_id in vault_ids:
        purge_qr_files_for_vault(vault_id)
        vault_dir = os.path.join(UPLOAD_DIR, vault_id)
        if os.path.isdir(vault_dir):
            shutil.rmtree(vault_dir, ignore_errors=True)

    # ai_queries isn't reachable via vault_id cascade (it's keyed on
    # owner_email directly), so it needs its own explicit delete.
    cur.execute("DELETE FROM ai_queries WHERE owner_email = %s", (email,))

    # Deleting the user row cascades: vaults -> documents -> document_chunks,
    # document_indexing_status, shared_items; vaults -> shared_links ->
    # shared_items, share_logs. Everything derived from this account goes
    # with it, per the account-deletion requirement.
    cur.execute("DELETE FROM users WHERE email = %s", (email,))

    log_audit_event('delete_account', actor_email=email,
                     details=f"vault_count={vault_count}")
    session.clear()
    flash('Your account and all associated data have been permanently deleted.', 'success')
    return redirect(url_for('index'))

# â”€â”€ Activity Log â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/activity')
@login_required
def activity_page():
    email = session['user_email']
    user = get_user(email)
    db = get_db()
    cur = db.cursor()

    active_tab = request.args.get('tab', 'audit').strip().lower()
    if active_tab not in ('audit', 'share'):
        active_tab = 'audit'

    q = request.args.get('q', '').strip()
    type_filter = request.args.get('type', 'all').strip().lower()
    date_filter = request.args.get('date', 'all').strip().lower()

    try:
        page = max(1, int(request.args.get('page', 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = max(5, min(100, int(request.args.get('per_page', 10))))
    except (ValueError, TypeError):
        per_page = 10

    offset = (page - 1) * per_page

    # â”€â”€ 1. Audit Logs (Account Operations) Query â”€â”€
    audit_clauses = ["actor_email = %s"]
    audit_params = [email]

    if q:
        audit_clauses.append("(event_type ILIKE %s OR details ILIKE %s OR ip_address ILIKE %s OR user_agent ILIKE %s)")
        q_term = f"%{q}%"
        audit_params.extend([q_term, q_term, q_term, q_term])

    if type_filter and type_filter != 'all':
        if type_filter == 'auth':
            audit_clauses.append("event_type IN ('login_success', 'login_failed', 'register', 'logout')")
        elif type_filter == 'doc':
            audit_clauses.append("event_type IN ('upload_doc', 'delete_doc', 'view_doc', 'download_doc', 'doc_upload', 'doc_delete', 'doc_view')")
        elif type_filter == 'vault':
            audit_clauses.append("event_type IN ('create_vault', 'delete_vault', 'vault_create', 'vault_delete')")
        elif type_filter == 'security':
            audit_clauses.append("event_type IN ('change_password', 'reset_password_request', 'reset_password_success', 'delete_account', 'data_export')")
        elif type_filter == 'share':
            audit_clauses.append("event_type IN ('create_share_link', 'delete_share_link', 'revoke_share_link', 'update_share', 'share_create', 'share_delete')")
        else:
            audit_clauses.append("event_type ILIKE %s")
            audit_params.append(f"%{type_filter}%")

    if date_filter == 'today':
        audit_clauses.append("created_at >= CURRENT_DATE")
    elif date_filter == '7d':
        audit_clauses.append("created_at >= NOW() - INTERVAL '7 days'")
    elif date_filter == '30d':
        audit_clauses.append("created_at >= NOW() - INTERVAL '30 days'")

    audit_where = " WHERE " + " AND ".join(audit_clauses)
    cur.execute(f"SELECT COUNT(*) as count FROM audit_logs {audit_where}", tuple(audit_params))
    audit_total_count = cur.fetchone()['count']

    # â”€â”€ 2. Share Logs Query â”€â”€
    share_clauses = ["v.owner_email = %s"]
    share_params = [email]

    if q:
        share_clauses.append("(sl.action ILIKE %s OR sl.details ILIKE %s OR sl.ip_address ILIKE %s OR v.vault_name ILIKE %s OR s.share_id ILIKE %s)")
        q_term = f"%{q}%"
        share_params.extend([q_term, q_term, q_term, q_term, q_term])

    if type_filter and type_filter != 'all':
        if type_filter == 'view':
            share_clauses.append("sl.action IN ('view', 'scan')")
        elif type_filter == 'download':
            share_clauses.append("sl.action = 'download'")
        elif type_filter == 'failed':
            share_clauses.append("sl.action = 'failed_auth'")
        else:
            share_clauses.append("sl.action ILIKE %s")
            share_params.append(f"%{type_filter}%")

    if date_filter == 'today':
        share_clauses.append("sl.scanned_at >= CURRENT_DATE")
    elif date_filter == '7d':
        share_clauses.append("sl.scanned_at >= NOW() - INTERVAL '7 days'")
    elif date_filter == '30d':
        share_clauses.append("sl.scanned_at >= NOW() - INTERVAL '30 days'")

    share_where = " WHERE " + " AND ".join(share_clauses)
    cur.execute(f"""
        SELECT COUNT(*) as count
        FROM share_logs sl
        JOIN shared_links s ON sl.share_id = s.share_id
        JOIN vaults v ON s.vault_id = v.vault_id
        {share_where}
    """, tuple(share_params))
    share_total_count = cur.fetchone()['count']

    # Active collection details for pagination
    current_total = audit_total_count if active_tab == 'audit' else share_total_count
    total_pages = max(1, (current_total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
        offset = (page - 1) * per_page

    # Fetch paginated audit events
    cur.execute(
        f"SELECT * FROM audit_logs {audit_where} ORDER BY created_at DESC LIMIT %s OFFSET %s",
        tuple(audit_params + [per_page, offset if active_tab == 'audit' else 0])
    )
    audit_events = to_iso_all(cur.fetchall())

    # Fetch paginated share events
    cur.execute(f"""
        SELECT sl.scanned_at, sl.action, sl.ip_address, sl.user_agent, sl.details, v.vault_name, v.vault_id, s.share_id, s.is_revoked, s.expires_at,
               s.allow_download, s.allow_printing, s.view_limit, (s.password_hash IS NOT NULL) AS has_password
        FROM share_logs sl
        JOIN shared_links s ON sl.share_id = s.share_id
        JOIN vaults v ON s.vault_id = v.vault_id
        {share_where}
        ORDER BY sl.scanned_at DESC LIMIT %s OFFSET %s
    """, tuple(share_params + [per_page, offset if active_tab == 'share' else 0]))
    share_events = to_iso_all(cur.fetchall())

    start_item = (page - 1) * per_page + 1 if current_total > 0 else 0
    end_item = min(page * per_page, current_total)
    now_iso = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

    # Page numbers
    pages_to_show = []
    for p in range(max(1, page - 2), min(total_pages, page + 2) + 1):
        pages_to_show.append(p)

    return render_template(
        'activity.html',
        user=user,
        audit_events=audit_events,
        share_events=share_events,
        active_tab=active_tab,
        q=q,
        type_filter=type_filter,
        date_filter=date_filter,
        page=page,
        total_pages=total_pages,
        audit_total_count=audit_total_count,
        share_total_count=share_total_count,
        current_total=current_total,
        start_item=start_item,
        end_item=end_item,
        pages_to_show=pages_to_show,
        per_page=per_page,
        now_iso=now_iso
    )

# â”€â”€ Security Settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/security')
@login_required
def security_page():
    email = session['user_email']
    user = get_user(email)

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT event_type, ip_address, user_agent, details, created_at "
        "FROM audit_logs WHERE actor_email = %s "
        "AND event_type IN ('login_success', 'login_failed', 'login_success_google', 'login_failed_google', 'logout') "
        "ORDER BY created_at DESC LIMIT 5",
        (email,)
    )
    login_activity = to_iso_all(cur.fetchall())

    return render_template('security.html', user=user, login_activity=login_activity)

@app.route('/security/export-data', methods=['POST'])
@login_required
def export_my_data():
    email = session['user_email']
    user = get_user(email)
    db = get_db()
    cur = db.cursor()

    cur.execute(
        "SELECT vault_id, vault_name, created_at FROM vaults WHERE owner_email = %s ORDER BY created_at DESC",
        (email,)
    )
    vaults = to_iso_all(cur.fetchall())

    cur.execute(
        "SELECT d.*, v.vault_name "
        "FROM documents d JOIN vaults v ON d.vault_id = v.vault_id "
        "WHERE v.owner_email = %s ORDER BY d.upload_date DESC",
        (email,)
    )
    documents = to_iso_all(cur.fetchall())

    cur.execute(
        "SELECT event_type, ip_address, user_agent, details, created_at "
        "FROM audit_logs WHERE actor_email = %s ORDER BY created_at DESC",
        (email,)
    )
    audit_rows = to_iso_all(cur.fetchall())

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        created_at = user.get('created_at')
        account_info = {
            'email': user['email'],
            'name': user.get('name'),
            'auth_provider': user.get('auth_provider'),
            'account_created_at': created_at.isoformat() if hasattr(created_at, 'isoformat') else created_at,
        }
        zf.writestr('account.json', json.dumps(account_info, indent=2, default=str))

        vaults_summary = [
            {'vault_id': v['vault_id'], 'vault_name': v['vault_name'], 'created_at': v['created_at']}
            for v in vaults
        ]
        zf.writestr('vaults.json', json.dumps(vaults_summary, indent=2, default=str))

        doc_fields = ('doc_id', 'vault_name', 'filename', 'file_type', 'file_size',
                      'upload_date', 'access_type', 'expires_at', 'view_limit', 'view_count')
        docs_summary = [{k: doc[k] for k in doc_fields} for doc in documents]
        zf.writestr('documents.json', json.dumps(docs_summary, indent=2, default=str))

        audit_buf = io.StringIO()
        writer = csv.writer(audit_buf)
        writer.writerow(['event_type', 'ip_address', 'user_agent', 'details', 'created_at'])
        for row in audit_rows:
            writer.writerow([row['event_type'], row['ip_address'], row['user_agent'], row['details'], row['created_at']])
        zf.writestr('audit_log.csv', audit_buf.getvalue())

        for doc in documents:
            try:
                disk_path = os.path.join(UPLOAD_DIR, doc['vault_id'], doc['stored_name'])
                data = decrypt_path_to_bytes(disk_path)
                safe_vault = secure_filename(doc['vault_name']) or doc['vault_id']
                zf.writestr(f"documents/{safe_vault}/{doc['filename']}", data)
            except Exception:
                app.logger.exception("export_my_data: failed to include doc_id=%s", doc.get('doc_id'))

    buf.seek(0)
    log_audit_event('data_export', actor_email=email)
    return send_file(
        buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'securevault-export-{datetime.utcnow().strftime("%Y%m%d")}.zip'
    )

# â”€â”€ Dedicated Change Password Page â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password_page():
    email = session['user_email']
    user = get_user(email)

    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw     = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if user.get('password_hash'):
            if not check_password_hash(user['password_hash'], current_pw):
                flash('Current password is incorrect.', 'error')
                return render_template('change_password.html', user=user)

        if len(new_pw) < 6:
            flash('New password must be at least 6 characters.', 'error')
            return render_template('change_password.html', user=user)

        if new_pw != confirm_pw:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html', user=user)

        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (generate_password_hash(new_pw), email))
        db.commit()
        log_audit_event('password_change', actor_email=email)
        flash('Password updated successfully!', 'success')
        return redirect(url_for('settings_page'))

    return render_template('change_password.html', user=user)

# â”€â”€ Update Account Password (API / Form handler) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/update-account-password', methods=['POST'])
@login_required
def update_account_password():
    email = session['user_email']
    user = get_user(email)
    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')
    confirm_pw = request.form.get('confirm_password', '')
    
    if user.get('password_hash'):
        if not check_password_hash(user['password_hash'], current_pw):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password_page'))
            
    if len(new_pw) < 6:
        flash('New password must be at least 6 characters.', 'error')
        return redirect(url_for('change_password_page'))
        
    if new_pw != confirm_pw:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('change_password_page'))
        
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (generate_password_hash(new_pw), email))
    db.commit()
    log_audit_event('password_change', actor_email=email)
    flash('Account password changed successfully.', 'success')
    return redirect(url_for('change_password_page'))

# â”€â”€ Profile & Settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_page():
    email = session['user_email']
    user = get_user(email)
    db = get_db()
    cur = db.cursor()
    
    if request.method == 'POST':
        new_name = request.form.get('name', '').strip()
        if not new_name:
            flash('Please enter a valid name.', 'error')
        else:
            cur.execute("UPDATE users SET name = %s WHERE email = %s", (new_name, email))
            db.commit()
            session['user_name'] = new_name
            log_audit_event('profile_update', actor_email=email, details='name_updated')
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile_page'))
            
    # Get summary stats
    cur.execute("SELECT * FROM vaults WHERE owner_email = %s", (email,))
    vaults = to_iso_all(cur.fetchall())
    total_docs = 0
    total_bytes = 0
    for v in vaults:
        cur.execute("SELECT file_size FROM documents WHERE vault_id = %s", (v['vault_id'],))
        docs = cur.fetchall()
        total_docs += len(docs)
        total_bytes += sum(d['file_size'] for d in docs)
        
    return render_template(
        'profile.html',
        user=user,
        vaults_count=len(vaults),
        docs_count=total_docs,
        total_bytes=total_bytes
    )

@app.route('/settings', methods=['GET'])
@login_required
def settings_page():
    user = get_current_user()
    return render_template('settings.html', user=user)


# â”€â”€ Update Document Access Settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/vault/<vault_id>/doc-access/<doc_id>', methods=['POST'])
@login_required
def update_doc_access(vault_id, doc_id):
    vault = _auth_vault(vault_id, with_documents=False)
    doc = get_document(vault_id, doc_id)
    if not doc:
        abort(404)
        
    access_type = request.form.get('access_type', 'public')
    entered_code = request.form.get('access_code', '').strip()
    # The form no longer pre-fills this field with the (now-hashed) stored
    # value, so: blank = keep the existing code, non-blank = set a new one.
    access_code = hash_access_code(entered_code) if entered_code else doc.get('access_code')
    
    view_limit = request.form.get('view_limit', '').strip()
    view_limit = int(view_limit) if (view_limit and view_limit.isdigit()) else None
    
    expires_hours = request.form.get('expires_hours', '').strip()
    expires_at = datetime.now() + timedelta(hours=int(expires_hours)) if (expires_hours and expires_hours.isdigit()) else None
    
    folder_name = request.form.get('folder_name', '').strip() or None
    
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE documents SET access_type = %s, access_code = %s, expires_at = %s, view_limit = %s, folder_name = %s "
        "WHERE doc_id = %s AND vault_id = %s",
        (access_type, access_code, expires_at, view_limit, folder_name, doc_id, vault_id)
    )
    
    # Regenerate document QR code card to display correct document name / metadata if changed
    base_url = request.host_url.rstrip('/')
    generate_doc_qr(doc['filename'], doc_id, base_url)
    
    touch_vault(vault_id)
    flash(f'Access settings for "{doc["filename"]}" updated successfully.', 'success')
    return redirect(url_for('vault_view', vault_id=vault_id))

# â”€â”€ Document Gate (public â€” for scanning/accessing individual files) â”€â”€â”€â”€â”€â”€â”€
@app.route('/document/<doc_id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute;50 per hour", methods=["POST"])
def doc_gate(doc_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM documents WHERE doc_id = %s", (doc_id,))
    doc = to_iso(cur.fetchone())
    if not doc:
        abort(404)
        
    cur.execute("SELECT owner_email FROM vaults WHERE vault_id = %s", (doc['vault_id'],))
    owner_row = cur.fetchone()
    if not owner_row:
        abort(404)
    owner_email = owner_row['owner_email']
    
    action = request.values.get('action', 'view') # view or download
    
    # If logged in as the owner, bypass all gates
    if session.get('user_email') == owner_email:
        return redirect(url_for('serve_doc_file', doc_id=doc_id, action=action))
        
    access_type = doc['access_type']
    
    # Check Expired states first.
    # NOTE on view_limit / onetime semantics: view_count is the number of
    # views already GRANTED (consumed). A fresh document starts at 0 with
    # view_limit=N meaning "N total views allowed". This pre-check uses
    # ">=" because it runs BEFORE any increment for this request â€” it's
    # asking "has the budget already been fully spent by earlier visitors".
    # The actual grant-and-increment further down uses try_consume_view(),
    # which re-checks the same condition atomically at write time so two
    # simultaneous requests can't both slip through this earlier read-only
    # check and jointly overspend the limit.
    if access_type == 'onetime' and doc['view_count'] >= 1:
        return render_template('doc_expired.html', doc=doc, reason='onetime')
        
    if access_type == 'expiring' and doc['expires_at']:
        exp = datetime.fromisoformat(doc['expires_at'])
        if exp.tzinfo is not None:
            now_t = datetime.now().astimezone(exp.tzinfo)
        else:
            now_t = datetime.now()
        if now_t > exp:
            return render_template('doc_expired.html', doc=doc, reason='expired')
            
    if access_type == 'limit' and doc['view_limit'] is not None:
        if doc['view_count'] >= doc['view_limit']:
            return render_template('doc_expired.html', doc=doc, reason='limit')
            
    # Access checking
    if access_type == 'public':
        return redirect(url_for('serve_doc_file', doc_id=doc_id, action=action))
        
    elif access_type == 'code':
        if request.method == 'POST':
            entered_code = request.form.get('code', '').strip()
            if check_access_code(entered_code, doc['access_code']):
                session[f'doc_auth_{doc_id}'] = True
                return redirect(url_for('serve_doc_file', doc_id=doc_id, action=action))
            else:
                flash('Incorrect Access Code.', 'error')
        return render_template('doc_gate.html', doc=doc, gate_type='code', action=action)
        
    elif access_type == 'onetime':
        if request.method == 'POST':
            if not try_consume_view('documents', 'doc_id', doc_id, 1):
                return render_template('doc_expired.html', doc=doc, reason='onetime')
            session[f'doc_auth_{doc_id}'] = True
            return redirect(url_for('serve_doc_file', doc_id=doc_id, action=action))
        return render_template('doc_gate.html', doc=doc, gate_type='onetime', action=action)
        
    elif access_type in ('expiring', 'limit'):
        if access_type == 'limit' and not session.get(f'doc_auth_{doc_id}'):
            if not try_consume_view('documents', 'doc_id', doc_id, doc['view_limit']):
                return render_template('doc_expired.html', doc=doc, reason='limit')
        session[f'doc_auth_{doc_id}'] = True
        return redirect(url_for('serve_doc_file', doc_id=doc_id, action=action))
        
    abort(403)

# â”€â”€ Serve Document Route (handles both view and download) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/document/<doc_id>/serve')
def serve_doc_file(doc_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM documents WHERE doc_id = %s", (doc_id,))
    doc = to_iso(cur.fetchone())
    if not doc:
        abort(404)
        
    cur.execute("SELECT owner_email FROM vaults WHERE vault_id = %s", (doc['vault_id'],))
    owner_row = cur.fetchone()
    if not owner_row:
        abort(404)
    owner_email = owner_row['owner_email']
    
    is_owner = session.get('user_email') == owner_email
    is_public = doc['access_type'] == 'public'
    is_session_auth = session.get(f'doc_auth_{doc_id}') is True
    # 'expiring' links are safe to allow without a prior doc_gate visit â€” the
    # expiry check below is a stateless timestamp comparison either way.
    # 'limit' is deliberately NOT included here: it only counts a view when
    # the visitor passes through doc_gate first, so if we let un-gated
    # requests straight through, direct/bookmarked links to /serve would
    # never increment the counter and the view limit could never be reached.
    is_non_credential_flow = doc['access_type'] == 'expiring'
    
    is_valid = True
    if doc['access_type'] == 'onetime' and doc['view_count'] > 1 and not is_owner:
        is_valid = False
    elif doc['access_type'] == 'expiring' and doc['expires_at'] and not is_owner:
        exp = datetime.fromisoformat(doc['expires_at'])
        if exp.tzinfo is not None:
            now_t = datetime.now().astimezone(exp.tzinfo)
        else:
            now_t = datetime.now()
        if now_t > exp:
            is_valid = False
    elif doc['access_type'] == 'limit' and doc['view_limit'] is not None and not is_owner:
        if doc['view_count'] > doc['view_limit']:
            is_valid = False
            
    if not (is_owner or is_public or is_session_auth or is_non_credential_flow) or not is_valid:
        flash('You must authenticate to access this document.', 'error')
        return redirect(url_for('doc_gate', doc_id=doc_id))
        
    action = request.args.get('action', 'view')
    as_attachment = (action == 'download')

    # For onetime and limit access types, the per-document session flag
    # (`doc_auth_<doc_id>`) is a SINGLE-USE grant, not a standing
    # authorization. If we leave it set, the same browser session could
    # keep hitting this route directly (bookmark/refresh) and be served
    # the file indefinitely, even though its view budget is already
    # spent â€” the actual counter never moves again because doc_gate only
    # consumes a view when the flag is absent. Popping it here forces
    # every subsequent request back through doc_gate, whose pre-checks
    # (`view_count >= 1` for onetime, `view_count >= view_limit` for
    # limit) correctly reject further access once the budget is used up.
    if not is_owner and doc['access_type'] in ('onetime', 'limit') and is_session_auth:
        session.pop(f'doc_auth_{doc_id}', None)

    return send_encrypted_file(os.path.join(UPLOAD_DIR, doc['vault_id'], doc['stored_name']),
                                doc['filename'], as_attachment=as_attachment)

# â”€â”€ Document QR Download â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route('/document/<doc_id>/qr')
def download_doc_qr(doc_id):
    card_path = os.path.join(QR_DIR, f"doc_{doc_id}_card.png")
    clean_path = os.path.join(QR_DIR, f"doc_{doc_id}.png")
    path = card_path if os.path.exists(card_path) else clean_path
    if not os.path.exists(path):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT filename FROM documents WHERE doc_id = %s", (doc_id,))
        doc = cur.fetchone()
        if doc:
            generate_doc_qr(doc['filename'], doc_id, request.host_url.rstrip('/'))
            path = card_path if os.path.exists(card_path) else clean_path
        else:
            abort(404)
    return send_file(path, as_attachment=True,
                     download_name=f"doc_qr_{doc_id[:8]}.png")

# â”€â”€ Secure Sharing Helpers & Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def log_share_access(share_id, action, details=None):
    db = get_db()
    cur = db.cursor()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # If comma separated list, pick the first
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    ua = request.user_agent.string if request.user_agent else 'Unknown'
    cur.execute(
        "INSERT INTO share_logs (share_id, ip_address, user_agent, action, details) "
        "VALUES (%s, %s, %s, %s, %s)",
        (share_id, ip, ua, action, details)
    )
    db.commit()

@app.route('/vault/<vault_id>/share', methods=['POST'])
@login_required
def create_share_link(vault_id):
    try:
        vault = _auth_vault(vault_id, with_documents=False)
        data = request.json or {}
        
        doc_ids = data.get('doc_ids', [])
        folders = data.get('folders', [])
        access_mode = data.get('access_mode', 'public')
        password = data.get('password', '')
        allow_download = bool(data.get('allow_download', True))
        allow_printing = bool(data.get('allow_printing', True))
        view_limit = data.get('view_limit')
        expires_at_str = data.get('expires_at')
        
        if not doc_ids and not folders:
            return jsonify({"success": False, "message": "No files or folders selected for sharing."}), 400

        # Authorization check: every doc_id/folder being shared must actually
        # belong to THIS vault (which the user was just confirmed to own via
        # _auth_vault above). Without this, a caller could pass doc_ids for
        # documents that live in someone else's vault and have them exposed
        # through a share link created against a vault they merely own.
        db_check = get_db()
        cur_check = db_check.cursor()
        doc_ids = [str(d) for d in doc_ids]
        if doc_ids:
            cur_check.execute(
                "SELECT doc_id FROM documents WHERE vault_id = %s AND doc_id IN %s",
                (vault_id, tuple(doc_ids))
            )
            owned_doc_ids = {r['doc_id'] for r in cur_check.fetchall()}
            if owned_doc_ids != set(doc_ids):
                return jsonify({"success": False, "message": "One or more selected documents are invalid."}), 400
        if folders:
            cur_check.execute(
                "SELECT DISTINCT folder_name FROM documents WHERE vault_id = %s AND folder_name IN %s",
                (vault_id, tuple(folders))
            )
            owned_folders = {r['folder_name'] for r in cur_check.fetchall()}
            if owned_folders != set(folders):
                return jsonify({"success": False, "message": "One or more selected folders are invalid."}), 400

        view_limit = int(view_limit) if (view_limit and str(view_limit).strip().isdigit()) else None
        
        expires_at = None
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
            except (ValueError, TypeError):
                pass

        share_id = secrets.token_urlsafe(16)
        pw_hash = None
        if access_mode == 'password' and password:
            pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
        base_url = request.host_url.rstrip('/')
        share_url = f"{base_url}/shared/{share_id}"

        # Generate QR codes: a clean one for on-screen display, and a
        # separate stylized card (header/footer) for the download only.
        generate_share_qr(f"Shared Selection - {vault['vault_name']}", share_id, share_url)
        
        db = get_db()
        cur = db.cursor()
        
        # Insert link config
        cur.execute(
            "INSERT INTO shared_links (share_id, vault_id, password_hash, allow_download, allow_printing, view_limit, expires_at, qr_path) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (share_id, vault_id, pw_hash, allow_download, allow_printing, view_limit, expires_at, f"share_{share_id}.png")
        )
        
        # Resolve and insert selected items
        for d_id in doc_ids:
            cur.execute(
                "INSERT INTO shared_items (share_id, doc_id, folder_name) VALUES (%s, %s, NULL)",
                (share_id, str(d_id))
            )
        for f_name in folders:
            cur.execute(
                "INSERT INTO shared_items (share_id, doc_id, folder_name) VALUES (%s, NULL, %s)",
                (share_id, f_name)
            )
            
        db.commit()
        log_audit_event('create_share', actor_email=session['user_email'],
                         details=f"vault_id={vault_id} share_id={share_id} "
                                 f"doc_count={len(doc_ids)} folder_count={len(folders)} "
                                 f"password_protected={bool(pw_hash)}")
        
        return jsonify({
            "success": True,
            "share_url": share_url,
            "qr_url": url_for('static', filename=f'qrcodes/share_{share_id}.png'),
            "download_qr_url": url_for('download_share_qr', share_id=share_id)
        })
    except Exception as e:
        import traceback
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            raise
        # Log the full detail server-side only â€” never echo exception text
        # (which can include file paths, query fragments, etc.) back to the client.
        app.logger.error(f"create_share_link error: {traceback.format_exc()}")
        return jsonify({"success": False, "message": "Server error while creating the share link. Please try again."}), 500

@app.route('/shared/qr/<share_id>')
def download_share_qr(share_id):
    path = os.path.join(QR_DIR, f"share_{share_id}_card.png")
    if not os.path.exists(path):
        # Fallback for share links created before the clean/card QR split
        path = os.path.join(QR_DIR, f"share_{share_id}.png")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True,
                     download_name=f"share_qr_{share_id[:8]}.png")

@app.route('/shared/<share_id>', methods=['GET'])
def view_shared_vault(share_id):
    # NOTE (Vault AI isolation): this route, and the rest of the /shared/*
    # family, intentionally never call ask_vault_ai() or expose any Vault AI
    # UI/endpoint. Recipients of a share link are unauthenticated visitors,
    # not vault owners â€” ask_vault_ai() runs against the AUTHENTICATED
    # owner's full corpus (session['user_email']) and must never be
    # invoked on their behalf. If Vault AI is ever extended to shared
    # links, it must take an explicit, share-scoped document allow-list
    # (e.g. only shared_doc_ids below) rather than an owner_email, so a
    # recipient can never reach documents outside what was shared with them.
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM shared_links WHERE share_id = %s", (share_id,))
    link = to_iso(cur.fetchone())
    if not link:
        abort(404)
        
    if link['is_revoked']:
        log_share_access(share_id, 'blocked_revoked', 'Access attempt on revoked link')
        return render_template('doc_expired.html', reason='revoked')
        
    # Check expiry
    if link['expires_at']:
        exp = datetime.fromisoformat(link['expires_at'])
        now_t = datetime.now().astimezone(exp.tzinfo) if exp.tzinfo else datetime.now()
        if now_t > exp:
            log_share_access(share_id, 'blocked_expired', 'Access attempt after expiration')
            return render_template('doc_expired.html', reason='expired')
            
    # Check view limit
    # Pre-check only (">=", read-only) â€” avoids prompting for a password on
    # a link that's already visibly exhausted. The actual grant below is
    # atomic via try_consume_view(), which re-checks this at write time so
    # concurrent requests can't jointly exceed the limit.
    if link['view_limit'] is not None and link['view_count'] >= link['view_limit']:
        log_share_access(share_id, 'blocked_limit', 'Access attempt after view limit reached')
        return render_template('doc_expired.html', reason='limit')
        
    # Check password protection
    if link['password_hash']:
        if not session.get(f'share_auth_{share_id}'):
            return render_template('doc_gate.html', doc={"filename": "Shared Folder Selection"}, gate_type='share_password', action='view', share_id=share_id)
            
    # Increment view count (atomically, re-checking the limit) and log access
    if link['view_limit'] is not None:
        if not try_consume_view('shared_links', 'share_id', share_id, link['view_limit']):
            return render_template('doc_expired.html', reason='limit')
    else:
        cur.execute("UPDATE shared_links SET view_count = view_count + 1 WHERE share_id = %s", (share_id,))
        db.commit()
    
    log_share_access(share_id, 'scan', 'Scanned QR / Accessed Shared Selection')
    
    # Retrieve vault info
    cur.execute("SELECT * FROM vaults WHERE vault_id = %s", (link['vault_id'],))
    vault = to_iso(cur.fetchone())
    
    # Retrieve shared documents & folders
    cur.execute("SELECT doc_id, folder_name FROM shared_items WHERE share_id = %s", (share_id,))
    items = cur.fetchall()
    
    shared_doc_ids = [it['doc_id'] for it in items if it['doc_id']]
    shared_folders = [it['folder_name'] for it in items if it['folder_name']]
    
    shared_docs = []
    if shared_doc_ids:
        # Always scope to this share link's own vault â€” shared_items rows are
        # meant to reference documents from that vault only, but this extra
        # "AND vault_id = %s" is defense-in-depth: even if a bad/rogue row
        # ever pointed at a doc_id from a *different* vault (e.g. a bug or
        # tampering elsewhere), it can never leak another vault's document
        # metadata through a share link.
        cur.execute(
            "SELECT * FROM documents WHERE doc_id IN %s AND vault_id = %s",
            (tuple(shared_doc_ids), link['vault_id'])
        )
        shared_docs.extend(to_iso_all(cur.fetchall()))
        
    for folder in shared_folders:
        cur.execute("SELECT * FROM documents WHERE vault_id = %s AND folder_name = %s", (link['vault_id'], folder))
        shared_docs.extend(to_iso_all(cur.fetchall()))
        
    # Remove duplicates
    seen = set()
    unique_docs = []
    for d in shared_docs:
        if d['doc_id'] not in seen:
            seen.add(d['doc_id'])
            unique_docs.append(d)
            
    vault['documents'] = unique_docs
    
    return render_template('shared_vault.html', vault=vault, link=link, share_id=share_id)

@app.route('/shared/<share_id>/auth', methods=['POST'])
@limiter.limit("10 per minute;50 per hour")
def auth_shared_vault(share_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT password_hash FROM shared_links WHERE share_id = %s", (share_id,))
    link = cur.fetchone()
    if not link or not link['password_hash']:
        abort(404)
        
    entered_pw = request.form.get('password', '')
    if bcrypt.checkpw(entered_pw.encode('utf-8'), link['password_hash'].encode('utf-8')):
        session[f'share_auth_{share_id}'] = True
        return redirect(url_for('view_shared_vault', share_id=share_id))
    else:
        log_share_access(share_id, 'failed_auth', 'Failed password attempt')
        flash('Incorrect Password.', 'error')
        return redirect(url_for('view_shared_vault', share_id=share_id))

@app.route('/shared/<share_id>/file/<doc_id>', methods=['GET'])
def serve_shared_file(share_id, doc_id):
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM shared_links WHERE share_id = %s", (share_id,))
    link = to_iso(cur.fetchone())
    if not link or link['is_revoked']:
        abort(403)
        
    # Check expiry/limits
    if link['expires_at']:
        exp = datetime.fromisoformat(link['expires_at'])
        now_t = datetime.now().astimezone(exp.tzinfo) if exp.tzinfo else datetime.now()
        if now_t > exp: abort(403)
    # Match the pre-check in view_shared_vault(): once the link's view
    # budget is fully spent, direct/bookmarked file URLs must be blocked
    # too, not just the shared-vault landing page.
    if link['view_limit'] is not None and link['view_count'] >= link['view_limit']:
        abort(403)
        
    if link['password_hash'] and not session.get(f'share_auth_{share_id}'):
        abort(403)
        
    # Verify doc is shared
    cur.execute("SELECT * FROM documents WHERE doc_id = %s", (doc_id,))
    doc = to_iso(cur.fetchone())
    if not doc or doc['vault_id'] != link['vault_id']:
        abort(404)
        
    cur.execute("SELECT 1 FROM shared_items WHERE share_id = %s AND (doc_id = %s OR folder_name = %s)", 
                (share_id, doc_id, doc['folder_name']))
    if not cur.fetchone():
        abort(403)
        
    action = request.args.get('action', 'view')
    if action == 'download' and not link['allow_download']:
        abort(403)
        
    # Log access
    log_share_access(share_id, action, f"File: {doc['filename']}")
    
    # Handle print restrictions for viewing
    if action == 'view' and not link['allow_printing']:
        # Serve in custom viewer template to enforce no printing
        # Embed the document: images can use <img>, PDFs can use <embed> or PDF.js/iframe
        file_web_path = url_for('serve_shared_file_raw', share_id=share_id, doc_id=doc_id)
        return render_template('shared_viewer.html', doc=doc, file_url=file_web_path, link=link, share_id=share_id)
        
    as_attachment = (action == 'download')
    return send_encrypted_file(os.path.join(UPLOAD_DIR, doc['vault_id'], doc['stored_name']),
                                doc['filename'], as_attachment=as_attachment)

@app.route('/shared/<share_id>/file/<doc_id>/raw', methods=['GET'])
def serve_shared_file_raw(share_id, doc_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM shared_links WHERE share_id = %s", (share_id,))
    link = to_iso(cur.fetchone())
    if not link or link['is_revoked']:
        abort(403)

    # Check expiry/limits â€” this route is reachable directly (it's the URL
    # embedded in the no-printing viewer), so it must enforce the same
    # expiry/view-limit rules as serve_shared_file(), not just revocation.
    if link['expires_at']:
        exp = datetime.fromisoformat(link['expires_at'])
        now_t = datetime.now().astimezone(exp.tzinfo) if exp.tzinfo else datetime.now()
        if now_t > exp: abort(403)
    # Same enforcement as serve_shared_file() â€” this raw route is directly
    # reachable (it's the URL embedded in the no-printing viewer), so it
    # needs the identical budget check, not the looser "> limit" version.
    if link['view_limit'] is not None and link['view_count'] >= link['view_limit']:
        abort(403)

    if link['password_hash'] and not session.get(f'share_auth_{share_id}'):
        abort(403)
        
    cur.execute("SELECT * FROM documents WHERE doc_id = %s", (doc_id,))
    doc = to_iso(cur.fetchone())
    if not doc or doc['vault_id'] != link['vault_id']:
        abort(404)
        
    cur.execute("SELECT 1 FROM shared_items WHERE share_id = %s AND (doc_id = %s OR folder_name = %s)", 
                (share_id, doc_id, doc['folder_name']))
    if not cur.fetchone():
        abort(403)

    # Downloads are never allowed through the inline/raw endpoint, regardless
    # of the link's allow_download setting â€” it exists only to embed the
    # document for viewing.
    # Inline serve only
    return send_encrypted_file(os.path.join(UPLOAD_DIR, doc['vault_id'], doc['stored_name']),
                                doc['filename'], as_attachment=False)

@app.route('/vault/<vault_id>/share/<share_id>/revoke', methods=['POST'])
@login_required
def revoke_share_link(vault_id, share_id):
    _auth_vault(vault_id, with_documents=False)
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT share_id FROM shared_links WHERE share_id = %s AND vault_id = %s", (share_id, vault_id))
    if not cur.fetchone():
        if _wants_json():
            return jsonify({"success": False, "message": "Share link not found."}), 404
        abort(404)
    cur.execute("UPDATE shared_links SET is_revoked = TRUE WHERE share_id = %s AND vault_id = %s", (share_id, vault_id))
    db.commit()
    log_audit_event('revoke_share', actor_email=session['user_email'],
                     details=f"vault_id={vault_id} share_id={share_id}")
    if _wants_json():
        return jsonify({"success": True, "message": "Share link stopped."})
    flash("Share link revoked successfully.", "success")
    return redirect(url_for('shared_links_page', vault_id=vault_id))

@app.route('/vault/<vault_id>/share/<share_id>/update', methods=['POST'])
@login_required
def update_share_link(vault_id, share_id):
    """Edit an existing share link's access controls (download/printing,
    view limit, expiry, password) without having to revoke and recreate it."""
    _auth_vault(vault_id, with_documents=False)
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM shared_links WHERE share_id = %s AND vault_id = %s", (share_id, vault_id))
    link = cur.fetchone()
    if not link:
        abort(404)

    data = request.json if request.is_json else request.form
    allow_download = str(data.get('allow_download', 'true')).lower() in ('true', '1', 'on', 'yes')
    allow_printing = str(data.get('allow_printing', 'true')).lower() in ('true', '1', 'on', 'yes')

    view_limit_raw = str(data.get('view_limit', '') or '').strip()
    view_limit = int(view_limit_raw) if view_limit_raw.isdigit() else None

    expires_at_str = (data.get('expires_at') or '').strip()
    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except (ValueError, TypeError):
            expires_at = link['expires_at']

    # Password handling: leave unchanged unless the caller explicitly sends
    # a new password, or explicitly asks to remove it.
    pw_hash = link['password_hash']
    new_password = (data.get('password') or '').strip()
    remove_password = str(data.get('remove_password', 'false')).lower() in ('true', '1', 'on', 'yes')
    if remove_password:
        pw_hash = None
    elif new_password:
        pw_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cur.execute(
        "UPDATE shared_links SET allow_download = %s, allow_printing = %s, view_limit = %s, "
        "expires_at = %s, password_hash = %s WHERE share_id = %s AND vault_id = %s",
        (allow_download, allow_printing, view_limit, expires_at, pw_hash, share_id, vault_id)
    )
    db.commit()
    log_audit_event('update_share', actor_email=session['user_email'],
                     details=f"vault_id={vault_id} share_id={share_id} "
                             f"allow_download={allow_download} allow_printing={allow_printing} "
                             f"view_limit={view_limit} expires_at={expires_at} "
                             f"password_changed={bool(new_password or remove_password)}")

    if request.is_json:
        return jsonify({"success": True, "message": "Permissions updated."})
    flash("Share link permissions updated.", "success")
    return redirect(url_for('shared_links_page', vault_id=vault_id))

@app.route('/vault/<vault_id>/share/<share_id>/delete', methods=['POST'])
@login_required
def delete_share_link(vault_id, share_id):
    _auth_vault(vault_id, with_documents=False)
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT qr_path FROM shared_links WHERE share_id = %s AND vault_id = %s", (share_id, vault_id))
    link = cur.fetchone()
    if not link:
        abort(404)

    # Remove the QR image files for this share link, if present
    # (both the clean display QR and the stylized download card)
    purge_share_qr_file(share_id)

    cur.execute("DELETE FROM share_logs WHERE share_id = %s", (share_id,))
    cur.execute("DELETE FROM shared_items WHERE share_id = %s", (share_id,))
    cur.execute("DELETE FROM shared_links WHERE share_id = %s AND vault_id = %s", (share_id, vault_id))
    db.commit()
    log_audit_event('delete_share', actor_email=session['user_email'],
                     details=f"vault_id={vault_id} share_id={share_id}")
    flash("Share link deleted permanently.", "success")
    return redirect(url_for('shared_links_page', vault_id=vault_id))

@app.route('/vault/<vault_id>/share/<share_id>/logs', methods=['GET'])
@login_required
def get_share_logs(vault_id, share_id):
    vault = _auth_vault(vault_id, with_documents=False)
    _auth_share(vault_id, share_id)
    db = get_db()
    cur = db.cursor()
    
    query = "SELECT * FROM share_logs WHERE share_id = %s"
    params = [share_id]
    
    # Filtering
    search = request.args.get('search')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if search:
        query += " AND (ip_address ILIKE %s OR details ILIKE %s OR action ILIKE %s)"
        like_search = f"%{search}%"
        params.extend([like_search, like_search, like_search])
        
    if start_date:
        query += " AND scanned_at >= %s"
        params.append(start_date)
        
    if end_date:
        # Include the whole end_date day
        query += " AND scanned_at <= %s::timestamp + interval '1 day' - interval '1 microsecond'"
        params.append(end_date)
        
    query += " ORDER BY scanned_at DESC"
    
    cur.execute(query, tuple(params))
    logs = to_iso_all(cur.fetchall())
    
    # Global summary stats for this share link (unfiltered)
    cur.execute("""
        SELECT 
            COUNT(*) as total_scans,
            COUNT(*) FILTER (WHERE action IN ('view', 'scan')) as successful_views,
            COUNT(*) FILTER (WHERE action = 'failed_auth') as failed_attempts,
            COUNT(*) FILTER (WHERE action = 'download') as total_downloads
        FROM share_logs WHERE share_id = %s
    """, (share_id,))
    stats = cur.fetchone()
    if stats:
        # Default to 0 instead of None
        stats = {k: v or 0 for k, v in stats.items()}
    else:
        stats = {"total_scans": 0, "successful_views": 0, "failed_attempts": 0, "total_downloads": 0}
        
    return {"success": True, "logs": logs, "stats": stats}

@app.route('/vault/<vault_id>/share/<share_id>/logs', methods=['DELETE'])
@login_required
def clear_share_logs(vault_id, share_id):
    vault = _auth_vault(vault_id, with_documents=False)
    _auth_share(vault_id, share_id)
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM share_logs WHERE share_id = %s", (share_id,))
    db.commit()
    return {"success": True}

@app.route('/vault/<vault_id>/share/<share_id>/logs/export', methods=['GET'])
@login_required
def export_share_logs(vault_id, share_id):
    vault = _auth_vault(vault_id, with_documents=False)
    _auth_share(vault_id, share_id)
    db = get_db()
    cur = db.cursor()
    
    query = "SELECT scanned_at, action, ip_address, user_agent, details FROM share_logs WHERE share_id = %s"
    params = [share_id]
    
    # Filtering (same as above so export matches current view)
    search = request.args.get('search')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if search:
        query += " AND (ip_address ILIKE %s OR details ILIKE %s OR action ILIKE %s)"
        like_search = f"%{search}%"
        params.extend([like_search, like_search, like_search])
        
    if start_date:
        query += " AND scanned_at >= %s"
        params.append(start_date)
        
    if end_date:
        query += " AND scanned_at <= %s::timestamp + interval '1 day' - interval '1 microsecond'"
        params.append(end_date)
        
    query += " ORDER BY scanned_at DESC"
    
    cur.execute(query, tuple(params))
    rows = cur.fetchall()
    
    import io, csv
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Timestamp', 'Action', 'IP Address', 'Browser/User Agent', 'Details'])
    
    for row in rows:
        cw.writerow([
            row['scanned_at'],
            row['action'],
            row['ip_address'],
            row['user_agent'],
            row['details']
        ])
        
    output = si.getvalue()
    si.close()
    
    # Return as CSV file download
    from flask import make_response
    response = make_response(output)
    response.headers["Content-Disposition"] = f"attachment; filename=share_logs_{share_id[:8]}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/vault/<vault_id>/share/<share_id>/regenerate', methods=['POST'])
@login_required
def regenerate_share_link(vault_id, share_id):
    vault = _auth_vault(vault_id, with_documents=False)
    db = get_db()
    cur = db.cursor()
    
    # Get old details
    cur.execute("SELECT * FROM shared_links WHERE share_id = %s AND vault_id = %s", (share_id, vault_id))
    old_link = cur.fetchone()
    if not old_link:
        abort(404)
        
    # Get associated items
    cur.execute("SELECT doc_id, folder_name FROM shared_items WHERE share_id = %s", (share_id,))
    items = cur.fetchall()
    
    # Create new share link
    new_share_id = secrets.token_urlsafe(16)
    base_url = request.host_url.rstrip('/')
    share_url = f"{base_url}/shared/{new_share_id}"

    generate_share_qr(f"Shared Selection - {vault['vault_name']}", new_share_id, share_url)
    
    # Revoke old link
    cur.execute("UPDATE shared_links SET is_revoked = TRUE WHERE share_id = %s", (share_id,))
    
    # Insert new link
    cur.execute(
        "INSERT INTO shared_links (share_id, vault_id, password_hash, allow_download, allow_printing, view_limit, expires_at, qr_path) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (new_share_id, vault_id, old_link['password_hash'], old_link['allow_download'], old_link['allow_printing'], 
         old_link['view_limit'], old_link['expires_at'], f"share_{new_share_id}.png")
    )
    
    # Insert items
    for it in items:
        cur.execute(
            "INSERT INTO shared_items (share_id, doc_id, folder_name) VALUES (%s, %s, %s)",
            (new_share_id, it['doc_id'], it['folder_name'])
        )
        
    db.commit()
    flash("Share QR link regenerated successfully. Old link has been revoked.", "success")
    return redirect(url_for('shared_links_page', vault_id=vault_id))


# â”€â”€ Vault AI Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route('/vault-ai')
@login_required
def vault_ai():
    email = session['user_email']
    user = get_user(email)
    
    # Auto-index any existing documents for the user that aren't indexed yet
    index_all_user_documents(email)
    
    # Retrieve user's documents and indexing status
    db = get_db()
    cur = db.cursor()
    
    cur.execute("""
        SELECT d.doc_id, d.filename, d.vault_id, s.status, s.error_message
        FROM documents d
        JOIN vaults v ON d.vault_id = v.vault_id
        LEFT JOIN document_indexing_status s ON d.doc_id = s.doc_id
        WHERE v.owner_email = %s
        ORDER BY d.upload_date DESC
    """, (email,))
    documents = to_iso_all(cur.fetchall())
    
    # Calculate stats
    total_docs = len(documents)
    completed_docs = sum(1 for d in documents if d['status'] == 'completed')
    failed_docs = sum(1 for d in documents if d['status'] == 'failed')
    processing_docs = sum(1 for d in documents if d['status'] in ('processing', 'pending'))
    
    # Retrieve and decrypt recent AI query history for this user in chronological order.
    cur.execute("""
        SELECT id, question_ciphertext, answer_ciphertext, sources_ciphertext,
               question, answer, source_documents, created_at
        FROM ai_queries
        WHERE owner_email = %s
        ORDER BY created_at ASC
        LIMIT 50
    """, (email,))
    raw_history = to_iso_all(cur.fetchall())
    history = []
    for item in raw_history:
        # Prefer encrypted columns; fall back to legacy plaintext only if
        # ciphertext column is absent (pre-encryption history rows).
        try:
            q = decrypt_text(item['question_ciphertext']) if item.get('question_ciphertext') else item.get('question', '')
            a = decrypt_text(item['answer_ciphertext'])   if item.get('answer_ciphertext')   else item.get('answer', '')
            s_raw = decrypt_text(item['sources_ciphertext']) if item.get('sources_ciphertext') else item.get('source_documents', '[]')
        except (ValueError, RuntimeError):
            # Decryption failed for this history row â€” skip rather than expose garbage.
            logger.warning("vault_ai: decryption failed for history id=%s â€” skipping.", item.get('id'))
            continue
        import json as _json
        try:
            sources = _json.loads(s_raw) if isinstance(s_raw, str) else s_raw
        except Exception:
            sources = []
        history.append({
            'id':               item['id'],
            'question':         q,
            'answer':           a,
            'source_documents': sources,
            'created_at':       item['created_at'],
        })
    
    return render_template(
        'vault_ai.html',
        user=user,
        documents=documents,
        total_docs=total_docs,
        completed_docs=completed_docs,
        failed_docs=failed_docs,
        processing_docs=processing_docs,
        history=history
    )


@app.route('/api/ai/ask', methods=['POST'])
@login_required
def api_ai_ask():
    data = request.get_json() or {}
    question = data.get('question', '').strip()
    if not question:
        return jsonify({
            "answer": "Please ask a valid question.",
            "found": False,
            "sources": []
        }), 400
        
    email = session['user_email']

    try:
        answer, found, sources = ask_vault_ai(email, question)

        # Encrypt and save query to database history.
        import json as _json
        sources_json = _json.dumps(sources)

        db = get_db()
        cur = db.cursor()

        if TEXT_ENCRYPTION_AVAILABLE:
            q_cipher = encrypt_text(question)
            a_cipher = encrypt_text(answer)
            s_cipher = encrypt_text(sources_json)
            cur.execute("""
                INSERT INTO ai_queries
                    (owner_email, question, answer, source_documents,
                     question_ciphertext, answer_ciphertext, sources_ciphertext)
                VALUES (%s, '', '', '[]', %s, %s, %s)
            """, (email, q_cipher, a_cipher, s_cipher))
        else:
            # Key not loaded: write empty ciphertext fields; question/answer
            # stored as empty sentinels so no plaintext reaches the DB.
            logger.warning("api_ai_ask: DOCUMENT_TEXT_ENCRYPTION_KEY not set â€” AI history NOT saved.")
            cur.execute("""
                INSERT INTO ai_queries (owner_email, question, answer, source_documents)
                VALUES (%s, '', '', '[]')
            """, (email,))

        db.commit()

        return jsonify({
            "answer": answer,
            "found":  found,
            "sources": sources
        })
    except Exception as e:
        logger.warning("api_ai_ask: request failed: %s", type(e).__name__)
        return jsonify({
            "answer": "An internal error occurred while processing your query.",
            "found": False,
            "sources": []
        }), 500


@app.route('/api/ai/index-status')
@login_required
def api_ai_index_status():
    email = session['user_email']
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT s.status, COUNT(*) as count
        FROM documents d
        JOIN vaults v ON d.vault_id = v.vault_id
        LEFT JOIN document_indexing_status s ON d.doc_id = s.doc_id
        WHERE v.owner_email = %s
        GROUP BY s.status
    """, (email,))
    rows = cur.fetchall()
    
    stats = {
        "total": 0,
        "completed": 0,
        "processing": 0,
        "pending": 0,
        "failed": 0
    }
    
    for r in rows:
        status = r['status'] or 'pending'
        count = r['count']
        stats["total"] += count
        if status in stats:
            stats[status] += count
        elif status == 'processing':
            stats['processing'] += count
            
    return jsonify(stats)


@app.route('/api/ai/clear-history', methods=['POST'])
@login_required
def api_ai_clear_history():
    email = session['user_email']
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM ai_queries WHERE owner_email = %s", (email,))
    db.commit()
    return jsonify({"success": True})


# â”€â”€ Run â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.errorhandler(Exception)
def handle_all_exceptions(e):
    import traceback
    traceback.print_exc()
    return f"<pre>{traceback.format_exc()}</pre>", 500

if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    # Debug mode exposes stack traces and Werkzeug's interactive debugger
    # (which allows remote code execution) â€” keep it off unless FLASK_DEBUG=true
    # is explicitly set, and never set it in production.
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='127.0.0.1', port=port)
