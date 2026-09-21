"""
Document processing service for Vault AI.
Handles text extraction (PDF, DOCX, TXT, Images/OCR) and text chunking.
"""

import os
import re

# Internal marker inserted between extracted PDF pages (see _extract_from_pdf).
# Never shown to the user or the LLM — chunk_text_parent_child() splits on it
# and then discards it.
PAGE_BREAK_MARKER = '\x0c<<<VAULT_PAGE_BREAK>>>\x0c'

# Lines that look like a section heading: markdown-style ("## Section"),
# or a short standalone line ending without terminal punctuation that's
# followed by more content (common in OCR'd certificates/mark sheets and
# DOCX exports where real heading styles get flattened to plain text).
_MARKDOWN_HEADER_RE = re.compile(r'^\s{0,3}#{1,6}\s+\S.*$')
_SHORT_HEADING_RE = re.compile(r'^[A-Z][A-Za-z0-9 &/\-]{2,60}$')

# Resolve Tesseract path on Windows if present
TESSERACT_PATHS = [
    r'C:\Program Files\Tesseract-OCR\tesseract.exe',
    r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
    os.path.expandvars(r'%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe'),
    os.path.expandvars(r'%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe')
]

for t_path in TESSERACT_PATHS:
    if os.path.exists(t_path):
        try:
            import pytesseract
            pytesseract.pytesseract.tesseract_cmd = t_path
            break
        except ImportError:
            pass


def extract_text_from_file(file_path, file_type):
    """
    Extract text content from a document file based on its file extension.
    Supports pdf, docx, txt, jpg, jpeg, png.
    """
    file_type = file_type.lower().lstrip('.')
    text = ""

    if file_type == 'pdf':
        text = _extract_from_pdf(file_path)
    elif file_type == 'docx':
        text = _extract_from_docx(file_path)
    elif file_type == 'txt':
        text = _extract_from_txt(file_path)
    elif file_type in ('jpg', 'jpeg', 'png', 'bmp', 'webp', 'tiff', 'jfif'):
        text = _extract_from_image(file_path)

    return text.strip()


# Hex-only watermark pattern: repeating blocks of 8+ hex chars (e.g. background
# watermarks on govt certificates like Karnataka Nadakacheri documents).
_HEX_WATERMARK_RE = re.compile(r'^(?:[0-9A-F]{6,}\s*){3,}$')


def _filter_ocr_lines(lines):
    """Remove hex watermark artifacts and other OCR noise from a list of text lines."""
    clean = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        # Filter repeating hex-only lines (background watermarks)
        if _HEX_WATERMARK_RE.match(ln.upper()):
            continue
        # Filter lines that are >80% non-printable or purely hex sequences
        hex_chars = sum(1 for c in ln if c in '0123456789ABCDEFabcdef')
        if len(ln) >= 8 and hex_chars / len(ln) > 0.85:
            continue
        clean.append(ln)
    return clean


# EasyOCR reader cache — initialised once per language set to avoid reloading models
_easyocr_readers = {}


def _get_easyocr_reader(langs=('en', 'kn', 'hi')):
    """Return a cached EasyOCR Reader for the given language list."""
    key = tuple(sorted(langs))
    if key not in _easyocr_readers:
        try:
            import easyocr
            _easyocr_readers[key] = easyocr.Reader(list(langs), gpu=False, verbose=False)
        except Exception as e:
            logger.warning("EasyOCR reader init failed (%s): %s", langs, type(e).__name__)
            _easyocr_readers[key] = None
    return _easyocr_readers[key]


def _ocr_image(img_or_bytes):
    """
    Perform robust, multilingual OCR on an image (PIL Image, numpy array, or image bytes).

    Strategy (in order):
      1. EasyOCR with Kannada + Hindi + English — best for Indic-script documents.
      2. RapidOCR — fast, Latin-script ONNX engine, good fallback.
      3. pytesseract — last-resort system OCR.

    Hex watermark artifacts (common on govt certificate scans) are stripped.
    """
    import io, numpy as np
    from PIL import Image

    # Normalise input to a PIL Image for uniform handling across engines
    if isinstance(img_or_bytes, (bytes, bytearray)):
        pil_img = Image.open(io.BytesIO(img_or_bytes)).convert('RGB')
    elif hasattr(img_or_bytes, 'convert'):
        pil_img = img_or_bytes.convert('RGB')
    else:
        # Already a numpy array or similar
        pil_img = Image.fromarray(np.array(img_or_bytes)).convert('RGB')

    np_img = np.array(pil_img)

    # 1. EasyOCR — multilingual (Kannada + Hindi + English)
    try:
        reader = _get_easyocr_reader(('en', 'kn', 'hi'))
        if reader is not None:
            results = reader.readtext(np_img, detail=0, paragraph=False)
            lines = _filter_ocr_lines(results)
            if lines:
                logger.debug("EasyOCR extracted %d lines", len(lines))
                return '\n'.join(lines)
    except Exception as e:
        logger.warning("EasyOCR inference error: %s", type(e).__name__)

    # 2. RapidOCR — self-contained ONNX engine, good for Latin/CJK
    try:
        from rapidocr_onnxruntime import RapidOCR
        engine = RapidOCR()
        result, _ = engine(np_img)
        if result:
            raw = [item[1].strip() for item in result if len(item) > 1 and item[1]]
            lines = _filter_ocr_lines(raw)
            if lines:
                return '\n'.join(lines)
    except Exception as e:
        logger.warning("RapidOCR error: %s", type(e).__name__)

    # 3. pytesseract — last resort
    try:
        import pytesseract
        text = pytesseract.image_to_string(pil_img)
        if text and text.strip():
            lines = _filter_ocr_lines(text.splitlines())
            return '\n'.join(lines) if lines else text.strip()
    except Exception:
        pass

    return ""


def _extract_from_pdf(file_path):
    """Extract text from PDF using PyMuPDF (fitz) or pypdf, falling back to OCR if scanned."""
    extracted = []
    
    # Try PyMuPDF (fitz)
    try:
        import fitz
        doc = fitz.open(file_path)
        for page in doc:
            page_text = page.get_text("text") or ""
            if page_text.strip():
                extracted.append(page_text.strip())
            else:
                # Page is empty / image scan — perform OCR on page pixmap
                try:
                    pix = page.get_pixmap(dpi=150)
                    ocr_text = _ocr_image(pix.tobytes("png"))
                    if ocr_text.strip():
                        extracted.append(ocr_text.strip())
                except Exception as e:
                    logger.warning("PDF page OCR error: %s", type(e).__name__)
        doc.close()
    except Exception:
        # Fallback to pypdf
        try:
            from pypdf import PdfReader
            reader = PdfReader(file_path)
            for page in reader.pages:
                t = page.extract_text() or ""
                if t.strip():
                    extracted.append(t.strip())
        except Exception:
            pass

    return f"\n\n{PAGE_BREAK_MARKER}\n\n".join(extracted)


import logging

logger = logging.getLogger(__name__)


def _extract_from_docx(file_path):
    """Extract text from DOCX document including paragraphs and tables."""
    try:
        import docx
        doc = docx.Document(file_path)
        parts = []
        for p in doc.paragraphs:
            if p.text.strip():
                parts.append(p.text.strip())
        for table in doc.tables:
            for row in table.rows:
                row_text = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if row_text:
                    parts.append(row_text)
        return "\n".join(parts)
    except Exception as e:
        logger.warning("Error extracting DOCX text: %s", type(e).__name__)
        return ""


def _extract_from_txt(file_path):
    """Extract text from plain text file."""
    for enc in ('utf-8', 'latin-1', 'cp1252'):
        try:
            with open(file_path, 'r', encoding=enc) as f:
                return f.read()
        except Exception:
            continue
    return ""


def _extract_from_image(file_path):
    """Extract text from image using OCR."""
    try:
        from PIL import Image, ImageOps
        img = Image.open(file_path)
        img = ImageOps.exif_transpose(img)
        return _ocr_image(img)
    except Exception as e:
        logger.warning("OCR failed for image: %s", type(e).__name__)
        return ""


def chunk_text(text, max_chunk_size=700, overlap=100):
    """
    Split text into chunks of max_chunk_size with overlap characters.
    Splits along paragraph or sentence boundaries where possible.
    """
    if not text or not text.strip():
        return []

    # Clean whitespace
    clean = re.sub(r'\r\n', '\n', text)
    clean = re.sub(r'[ \t]+', ' ', clean)
    clean = clean.strip()

    if len(clean) <= max_chunk_size:
        return [clean]

    # Split by double newline (paragraphs) first
    paragraphs = clean.split('\n\n')
    chunks = []
    current_chunk = ""

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        if len(current_chunk) + len(para) + 2 <= max_chunk_size:
            current_chunk = (current_chunk + "\n\n" + para).strip()
        else:
            if current_chunk:
                chunks.append(current_chunk)
            
            # If paragraph itself is larger than max_chunk_size, split by sentences or sliding window
            if len(para) > max_chunk_size:
                sub_chunks = _split_long_paragraph(para, max_chunk_size, overlap)
                chunks.extend(sub_chunks[:-1])
                current_chunk = sub_chunks[-1] if sub_chunks else ""
            else:
                current_chunk = para

    if current_chunk:
        chunks.append(current_chunk)

    return chunks


def _split_long_paragraph(paragraph, max_chunk_size, overlap):
    """Split long paragraphs into chunks with overlap."""
    sub_chunks = []
    start = 0
    length = len(paragraph)

    while start < length:
        end = start + max_chunk_size
        if end >= length:
            sub_chunks.append(paragraph[start:length].strip())
            break
        
        # Try to find sentence end boundary near `end`
        match = re.search(r'[.!?]\s', paragraph[max(start, end - 100):end])
        if match:
            actual_end = max(start, end - 100) + match.end()
        else:
            actual_end = end

        sub_chunks.append(paragraph[start:actual_end].strip())
        start = max(start + 1, actual_end - overlap)

    return sub_chunks


# ── Parent/child chunking ────────────────────────────────────────────────
# Fixed-length chunk_text() above is still used as the "child" splitter
# below. These functions add a structure-aware "parent" layer on top of it
# so retrieval can match against small, precise child chunks while the LLM
# gets the fuller parent section they came from as context.

def _looks_like_heading(line):
    """Heuristic for whether a line is a section heading rather than body
    text: markdown-style ('## Section'), or a short standalone line with no
    terminal punctuation (common once real heading styles get flattened to
    plain text by OCR or DOCX/PDF text extraction)."""
    line = line.strip()
    if not line or len(line) > 70:
        return False
    if _MARKDOWN_HEADER_RE.match(line):
        return True
    if line.endswith(('.', ',', ';')):
        return False
    if _SHORT_HEADING_RE.match(line) and len(line.split()) <= 8:
        return True
    return False


def _accumulate_paragraphs(text, max_size):
    """Greedily group blank-line-separated paragraphs up to max_size
    characters, splitting any single paragraph that's already larger than
    max_size on its own. Used to keep oversized structural sections from
    becoming a single unbounded parent chunk."""
    paragraphs = text.split('\n\n')
    chunks = []
    current = ""
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if len(current) + len(para) + 2 <= max_size:
            current = (current + "\n\n" + para).strip() if current else para
        else:
            if current:
                chunks.append(current)
            if len(para) > max_size:
                chunks.extend(_split_long_paragraph(para, max_size, overlap=0))
                current = ""
            else:
                current = para
    if current:
        chunks.append(current)
    return chunks


def split_into_parent_sections(text, parent_size=1200):
    """
    Split text into "parent" sections using structural signals — PDF page
    breaks (see PAGE_BREAK_MARKER) and header-like lines — as the primary
    split points, rather than a blind character count. Sections are then
    merged (if small) or further split (if oversized) so each parent stays
    close to parent_size characters. Page breaks are a hard boundary: the
    buffer is always flushed at the end of a page so trailing content from
    one page never gets silently merged into the next page's parent.
    """
    pages = text.split(PAGE_BREAK_MARKER)
    parents = []

    for page in pages:
        page = page.strip()
        if not page:
            continue

        lines = page.split('\n')
        sections = []
        current_lines = []
        for line in lines:
            if _looks_like_heading(line) and current_lines:
                sections.append('\n'.join(current_lines).strip())
                current_lines = [line]
            else:
                current_lines.append(line)
        if current_lines:
            sections.append('\n'.join(current_lines).strip())
        sections = [s for s in sections if s]

        buffer = ""
        for sec in sections:
            if len(buffer) + len(sec) + 2 <= parent_size:
                buffer = (buffer + "\n\n" + sec).strip() if buffer else sec
            else:
                if buffer:
                    parents.append(buffer)
                if len(sec) > parent_size:
                    parents.extend(_accumulate_paragraphs(sec, parent_size))
                    buffer = ""
                else:
                    buffer = sec
        if buffer:
            parents.append(buffer)  # flush at page boundary — never carried to the next page

    if not parents and text.strip():
        parents = [text.strip()]
    return parents


def chunk_text_parent_child(text, parent_size=1200, child_size=300, child_overlap=60):
    """
    Parent/child chunking for Vault AI retrieval.

    Splits `text` into larger "parent" sections along structural
    boundaries (PDF page breaks, header-like lines, paragraph groups), up
    to ~parent_size characters each, then splits every parent into smaller
    "child" chunks (~child_size characters, via the existing chunk_text())
    for precise matching.

    Retrieval should score against `child_text` — short and specific, so
    an exact term/number match ranks well — but the LLM should be given
    `parent_text` as context, so the surrounding heading/paragraph/table
    row that gives the matched line its meaning isn't lost. Returns a list
    of dicts: {'child_text', 'parent_text', 'parent_index'} (parent_index
    lets callers de-duplicate multiple child hits that share one parent).
    """
    if not text or not text.strip():
        return []

    clean = re.sub(r'\r\n', '\n', text)
    clean = re.sub(r'[ \t]+', ' ', clean)
    clean = clean.strip()

    parents = split_into_parent_sections(clean, parent_size=parent_size)
    results = []
    for parent_idx, parent_text in enumerate(parents):
        children = chunk_text(parent_text, max_chunk_size=child_size, overlap=child_overlap)
        for child_text in children:
            results.append({
                'child_text': child_text,
                'parent_text': parent_text,
                'parent_index': parent_idx,
            })
    return results
