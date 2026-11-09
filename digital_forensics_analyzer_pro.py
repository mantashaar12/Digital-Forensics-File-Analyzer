"""
Digital Forensics File Analyzer - PRO (forensic-lab dashboard edition)
======================================================================

A defensive, read-only digital forensics dashboard built with Streamlit.

What it does
------------
* Copies an uploaded file to a private temporary folder (the original is never modified)
* Computes MD5 / SHA-256 using streaming 4096-byte chunks
* Verifies integrity against a user-supplied hash
* Extracts metadata (PDF, DOCX, JPG/PNG EXIF, basic PE header information)
* Detects suspicious filename traits, extension/content mismatches, archive oddities
* Extracts URLs and IPv4 addresses from text-based files (never contacts them)
* Calculates a transparent 0-100 risk score
* Generates a downloadable forensic report (PDF, with a plain-text fallback)

What it NEVER does
------------------
It never executes, opens-with-an-application, modifies or deletes evidence, never connects
to the network, never scans or contacts URLs/IPs found in files, and never attempts
password cracking or exploitation.

Run with:  streamlit run digital_forensics_analyzer_pro.py
"""

from __future__ import annotations

import csv
import hashlib
import html
import math
import mimetypes
import os
import re
import shutil
import struct
import tempfile
import unicodedata
import zipfile
import ipaddress
import json
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

import streamlit as st

# --------------------------------------------------------------------------------------
# Optional third-party libraries (the app degrades gracefully when one is missing)
# --------------------------------------------------------------------------------------
try:
    from pypdf import PdfReader
    PDF_LIB = "pypdf"
except ImportError:  # pragma: no cover - depends on the environment
    try:
        from PyPDF2 import PdfReader  # type: ignore
        PDF_LIB = "PyPDF2"
    except ImportError:
        PdfReader = None  # type: ignore
        PDF_LIB = None

try:
    from docx import Document as DocxDocument
except ImportError:  # pragma: no cover
    DocxDocument = None  # type: ignore

try:
    from PIL import ExifTags, Image
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ExifTags = None  # type: ignore

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_OK = True
except ImportError:  # pragma: no cover
    REPORTLAB_OK = False

try:
    import plotly.graph_objects as go
    PLOTLY_OK = True
except ImportError:  # pragma: no cover
    go = None
    PLOTLY_OK = False

# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------
PROJECT_NAME = "Digital Forensics File Analyzer"
REPORT_TITLE = "Digital Forensic Analysis Report"
CHUNK_SIZE = 4096                       # streaming hash chunk size (bytes)
TEXT_SCAN_LIMIT = 25 * 1024 * 1024      # max characters scanned for URLs / IPs

UPLOAD_TYPES = [
    "txt", "pdf", "jpg", "jpeg", "png", "docx", "exe", "zip", "log", "csv", "json",
    # Extra types so the suspicious-extension detector can be demonstrated (never executed).
    "scr", "bat", "cmd", "ps1", "vbs", "js", "jar",
]
TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json"}
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}
EXECUTABLE_KINDS = {"exe", "elf"}
# Extensions commonly used as a "decoy" in front of a real executable extension.
KNOWN_FILE_EXTENSIONS = {
    ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg",
    ".png", ".gif", ".bmp", ".csv", ".json", ".zip", ".rtf", ".log", ".mp3", ".mp4",
    ".html", ".htm", ".xml",
}
COMPOUND_EXTENSIONS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst")

# Transparent risk-scoring weights (documented in the UI and in the report).
RISK_POINTS = {
    "double_extension_executable": 35,
    "double_extension_other": 15,
    "risky_extension": 20,
    "type_mismatch": 25,
    "type_mismatch_executable_disguised": 50,
    "hidden_file": 5,
    "filename_anomaly_each": 5,
    "filename_anomaly_cap": 15,
    "control_characters": 20,
    "urls_found": 5,
    "urls_many": 10,
    "ips_found": 5,
    "ips_many": 10,
    "integrity_mismatch": 30,
    "archive_executables": 10,
    "archive_path_traversal": 15,
    "archive_macro_part": 10,
    "archive_high_ratio": 10,
    "high_entropy_executable": 10,
}
URLS_MANY_THRESHOLD = 10
IPS_MANY_THRESHOLD = 5
ENTROPY_SCAN_LIMIT = 32 * 1024 * 1024   # bytes analysed for entropy / byte distribution
ENTROPY_MAX_BLOCKS = 128
HIGH_ENTROPY_THRESHOLD = 7.2            # bits per byte
TECHNICAL_SECTIONS = {"Image Properties", "Document Structure"}

URL_REGEX = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`{}|\\^\[\]]+", re.IGNORECASE)
IPV4_REGEX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")

# (magic bytes, kind, description, mime type, is_executable)
SIGNATURES: List[Tuple[bytes, str, str, str, bool]] = [
    (b"%PDF-", "pdf", "PDF document", "application/pdf", False),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image", "image/png", False),
    (b"\xff\xd8\xff", "jpeg", "JPEG image", "image/jpeg", False),
    (b"GIF87a", "gif", "GIF image", "image/gif", False),
    (b"GIF89a", "gif", "GIF image", "image/gif", False),
    (b"PK\x03\x04", "zip", "ZIP-based container (ZIP / DOCX / JAR ...)", "application/zip", False),
    (b"PK\x05\x06", "zip", "ZIP archive (empty)", "application/zip", False),
    (b"\x7fELF", "elf", "ELF executable", "application/x-executable", True),
    (b"Rar!\x1a\x07", "rar", "RAR archive", "application/vnd.rar", False),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive", "application/x-7z-compressed", False),
    (b"\x1f\x8b", "gzip", "GZIP compressed data", "application/gzip", False),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "Legacy Microsoft Office (OLE2)", "application/x-ole-storage", False),
]

# Which detected content kinds are acceptable for each extension.
EXPECTED_KINDS: Dict[str, Tuple[str, ...]] = {
    ".pdf": ("pdf",), ".png": ("png",), ".jpg": ("jpeg",), ".jpeg": ("jpeg",),
    ".zip": ("zip",), ".docx": ("zip",), ".jar": ("zip",),
    ".exe": ("exe",), ".scr": ("exe",),
    ".txt": ("text",), ".log": ("text",), ".csv": ("text",), ".json": ("text",),
    ".bat": ("text",), ".cmd": ("text",), ".ps1": ("text",), ".vbs": ("text",), ".js": ("text",),
}
KIND_LABELS = {
    "pdf": "PDF document", "png": "PNG image", "jpeg": "JPEG image", "zip": "ZIP-based container",
    "exe": "Windows PE executable", "text": "plain text", "elf": "ELF executable",
}


# --------------------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------------------
def safe_display(text: Any) -> str:
    """Return text with control/format characters (e.g. right-to-left override) shown as escapes."""
    out = []
    for ch in str(text):
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            out.append("\\u%04x" % ord(ch) if ord(ch) <= 0xFFFF else "\\U%08x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def format_size(num_bytes: int) -> str:
    """Format a byte count as Bytes / KB / MB / GB."""
    if num_bytes < 1024:
        return f"{num_bytes:,} Bytes"
    if num_bytes < 1024 ** 2:
        return f"{num_bytes / 1024:.2f} KB ({num_bytes:,} Bytes)"
    if num_bytes < 1024 ** 3:
        return f"{num_bytes / 1024 ** 2:.2f} MB ({num_bytes:,} Bytes)"
    return f"{num_bytes / 1024 ** 3:.2f} GB ({num_bytes:,} Bytes)"


def format_timestamp(ts: Optional[float]) -> str:
    """Format an epoch timestamp in local time, or a clear 'not available' message."""
    if ts is None:
        return "Not available on this platform"
    try:
        return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except (OverflowError, OSError, ValueError):
        return "Not available"


def get_extension(filename: str) -> str:
    """Return the lower-case final extension (including the dot) of a file name."""
    clean = filename.replace("\\", "/").split("/")[-1]
    return Path(clean).suffix.strip().lower()


def clean_value(value: Any) -> str:
    """Convert a metadata value (bytes, rationals, tuples ...) into a short readable string."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if raw.startswith(b"ASCII\x00\x00\x00"):
            raw = raw[8:]
        try:
            text = raw.decode("utf-8").strip("\x00 ")
        except UnicodeDecodeError:
            return f"<binary data, {len(raw)} bytes>"
    elif hasattr(value, "numerator") and hasattr(value, "denominator"):
        try:
            number = float(value)
            if not math.isfinite(number):
                text = "unknown"
            elif number == int(number):
                text = str(int(number))
            else:
                text = f"{number:.6g}"
        except (ValueError, ZeroDivisionError, OverflowError):
            text = "unknown"
    elif isinstance(value, (tuple, list)):
        text = ", ".join(clean_value(v) for v in value)
    else:
        text = str(value)
    text = re.sub(r"[\r\n\t]+", " ", text).strip()
    return text if len(text) <= 300 else text[:300] + " [truncated]"


def new_metadata_result(kind: str) -> Dict[str, Any]:
    """Create an empty metadata result structure."""
    return {"type": kind, "sections": {}, "notes": [], "error": None}


def metadata_available(meta: Dict[str, Any]) -> bool:
    """True when at least one non-technical metadata field was found."""
    return any(
        bool(fields) for name, fields in meta.get("sections", {}).items()
        if name not in TECHNICAL_SECTIONS
    )


# --------------------------------------------------------------------------------------
# Hashing and integrity
# --------------------------------------------------------------------------------------
def calculate_hashes(file_path: str) -> Dict[str, str]:
    """Compute MD5 and SHA-256 by streaming the file in 4096-byte chunks."""
    try:
        md5 = hashlib.md5(usedforsecurity=False)
    except TypeError:  # older Python versions
        md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def identify_hash_type(value: str) -> Optional[str]:
    """Return 'MD5', 'SHA-256' or None depending on whether value is a valid hex digest."""
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return "MD5"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "SHA-256"
    return None


def verify_integrity(expected_raw: str, hashes: Dict[str, Optional[str]]) -> Dict[str, Any]:
    """Compare a user-supplied hash with the calculated one (case-insensitive)."""
    expected = (expected_raw or "").strip()
    result: Dict[str, Any] = {
        "status": "not_provided", "algorithm": None, "expected": expected,
        "calculated": None, "message": "No expected hash was supplied, so integrity was not checked.",
    }
    if not expected:
        return result
    algorithm = identify_hash_type(expected)
    if algorithm is None:
        result.update(
            status="invalid",
            message="Invalid hash: enter a 32-character MD5 or a 64-character SHA-256 hexadecimal value.",
        )
        return result
    calculated = hashes.get("md5" if algorithm == "MD5" else "sha256")
    result.update(algorithm=algorithm, calculated=calculated)
    if not calculated:
        result.update(status="error", message="The file hash could not be calculated, so no comparison was possible.")
    elif expected.lower() == calculated.lower():
        result.update(status="match", message="Integrity Verified — File has not changed according to the supplied hash.")
    else:
        result.update(status="mismatch", message="Integrity Warning — The calculated hash does not match the supplied hash.")
    return result


# --------------------------------------------------------------------------------------
# File information, signatures and content-type detection
# --------------------------------------------------------------------------------------
def parse_pe_header(file_path: str) -> Optional[Dict[str, Any]]:
    """Parse the basic PE header structure (read-only). Returns None if not a valid PE file."""
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as handle:
        head = handle.read(64)
        if len(head) < 64 or head[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if e_lfanew < 64 or e_lfanew + 24 > size:
            return None
        handle.seek(e_lfanew)
        pe = handle.read(24)
    if len(pe) < 24 or pe[:4] != b"PE\x00\x00":
        return None
    machine, sections, timestamp, _sym_ptr, _sym_count, _opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", pe, 4
    )
    machines = {0x14C: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "Itanium"}
    return {
        "machine": machines.get(machine, f"Unknown (0x{machine:04X})"),
        "sections": sections,
        "timestamp": timestamp,
        "is_dll": bool(characteristics & 0x2000),
    }


def looks_like_text(sample: bytes) -> bool:
    """Heuristic check whether a byte sample is readable text."""
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in sample:
        return False
    try:
        import codecs
        codecs.getincrementaldecoder("utf-8")().decode(sample, final=False)
        return True
    except UnicodeDecodeError:
        printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
        return printable / max(len(sample), 1) >= 0.90


def detect_file_signature(file_path: str) -> Dict[str, Any]:
    """Identify the real content type from magic bytes (no execution, read-only)."""
    with open(file_path, "rb") as handle:
        sample = handle.read(8192)
    if not sample:
        return {"kind": "empty", "description": "Empty file (0 bytes)", "mime": "application/x-empty", "executable": False}
    if sample[:2] == b"MZ" and parse_pe_header(file_path) is not None:
        return {"kind": "exe", "description": "Windows PE executable (EXE/DLL/SCR)",
                "mime": "application/vnd.microsoft.portable-executable", "executable": True}
    for magic, kind, description, mime, executable in SIGNATURES:
        if sample.startswith(magic):
            return {"kind": kind, "description": description, "mime": mime, "executable": executable}
    if looks_like_text(sample):
        return {"kind": "text", "description": "Plain text / script content", "mime": "text/plain", "executable": False}
    return {"kind": "unknown", "description": "Unrecognised binary data", "mime": "application/octet-stream", "executable": False}


def get_file_information(file_path: str, original_name: str, signature: Dict[str, Any]) -> Dict[str, Any]:
    """Collect name, extension, size, type, MIME type, path and timestamps."""
    stat = os.stat(file_path)
    name = original_name.replace("\\", "/").split("/")[-1] or "unnamed"
    extension = get_extension(name)
    mime_by_ext, _ = mimetypes.guess_type(name)

    created_ts = getattr(stat, "st_birthtime", None)
    if created_ts is None and os.name == "nt":
        created_ts = stat.st_ctime
    return {
        "name": name,
        "display_name": safe_display(name),
        "extension": extension if extension else "(none)",
        "size_bytes": stat.st_size,
        "size_human": format_size(stat.st_size),
        "file_type": signature["description"],
        "mime_by_extension": mime_by_ext or "Unknown",
        "mime_detected": signature["mime"],
        "path": file_path,
        "created": format_timestamp(created_ts),
        "modified": format_timestamp(stat.st_mtime),
        "accessed": format_timestamp(stat.st_atime),
        "timestamp_note": (
            "Uploaded files are transferred as bytes and copied to a private temporary file for analysis. "
            "These timestamps therefore describe that temporary copy, NOT the original evidence file on "
            "the examiner's disk."
        ),
    }


def detect_hidden_status(filename: str) -> Dict[str, str]:
    """Report hidden status only when it can genuinely be determined."""
    name = filename.replace("\\", "/").split("/")[-1]
    if name.startswith("."):
        return {"status": "Yes", "explanation": "The file name begins with a dot, which marks a hidden file on Unix-like systems."}
    return {
        "status": "Unable to determine",
        "explanation": (
            "A browser upload carries only the file name and its bytes. Operating-system hidden/system "
            "attributes of the original file are not transmitted, so they cannot be read."
        ),
    }


# --------------------------------------------------------------------------------------
# Metadata extraction
# --------------------------------------------------------------------------------------
def parse_pdf_date(raw: Any) -> str:
    """Convert a PDF date string (D:YYYYMMDDHHmmSS+HH'mm') into a readable form."""
    text = str(raw)
    match = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+\-])?(?:(\d{2})'?(\d{2})?'?)?", text)
    if not match:
        return text
    year, month, day, hour, minute, second, sign, tz_h, tz_m = match.groups()
    formatted = f"{year}-{month or '01'}-{day or '01'} {hour or '00'}:{minute or '00'}:{second or '00'}"
    if sign in ("Z", "z"):
        formatted += " UTC"
    elif sign and tz_h:
        formatted += f" UTC{sign}{tz_h}:{tz_m or '00'}"
    return formatted


def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """Extract document-information metadata from a PDF without rendering or executing it."""
    result = new_metadata_result("PDF")
    if PdfReader is None:
        result["error"] = "PDF metadata extraction is unavailable because pypdf is not installed."
        return result
    try:
        reader = PdfReader(file_path)
        if getattr(reader, "is_encrypted", False):
            result["notes"].append("The PDF is encrypted. No password was attempted, so metadata was not read.")
            return result
        info = reader.metadata
        fields: Dict[str, str] = {}
        mapping = [
            ("Title", "/Title"), ("Author", "/Author"), ("Subject", "/Subject"), ("Creator", "/Creator"),
            ("Producer", "/Producer"), ("Keywords", "/Keywords"),
            ("Creation Date", "/CreationDate"), ("Modification Date", "/ModDate"),
        ]
        if info:
            for label, key in mapping:
                value = info.get(key)
                if value not in (None, ""):
                    fields[label] = parse_pdf_date(value) if "Date" in label else clean_value(value)
        result["sections"]["Document Properties"] = fields
        try:
            result["sections"]["Document Structure"] = {"Page Count": str(len(reader.pages))}
        except Exception:
            result["notes"].append("The page count could not be determined.")
    except Exception as exc:
        result["error"] = f"The PDF could not be parsed (it may be corrupted or malformed): {type(exc).__name__}."
    return result


def extract_docx_metadata(file_path: str) -> Dict[str, Any]:
    """Extract core document properties from a DOCX file (no macros are run)."""
    result = new_metadata_result("DOCX")
    if DocxDocument is None:
        result["error"] = "DOCX metadata extraction is unavailable because python-docx is not installed."
        return result
    if not zipfile.is_zipfile(file_path):
        result["error"] = "The file is not a valid DOCX package (it is not a ZIP-based Office document)."
        return result
    try:
        props = DocxDocument(file_path).core_properties
        candidates = [
            ("Author", props.author), ("Last Modified By", props.last_modified_by), ("Title", props.title),
            ("Subject", props.subject), ("Created", props.created), ("Modified", props.modified),
            ("Revision", props.revision), ("Keywords", props.keywords), ("Category", props.category),
            ("Comments", props.comments), ("Last Printed", props.last_printed),
        ]
        fields = {label: clean_value(val) for label, val in candidates if val not in (None, "", 0)}
        result["sections"]["Document Properties"] = fields
    except Exception as exc:
        result["error"] = f"The DOCX file could not be read (invalid or corrupted): {type(exc).__name__}."
    return result


def _gps_to_decimal(dms: Any, ref: Any) -> Optional[float]:
    """Convert EXIF degrees/minutes/seconds to signed decimal degrees."""
    try:
        degrees, minutes, seconds = (float(x) for x in dms)
        value = degrees + minutes / 60.0 + seconds / 3600.0
        if not math.isfinite(value):
            return None
        if str(ref).strip().upper() in ("S", "W"):
            value = -value
        return round(value, 6)
    except Exception:
        return None


def extract_image_metadata(file_path: str) -> Dict[str, Any]:
    """Extract EXIF (camera, date/time, software, GPS) and PNG text metadata from an image."""
    result = new_metadata_result("Image")
    if Image is None or ExifTags is None:
        result["error"] = "Image metadata extraction is unavailable because Pillow is not installed."
        return result
    try:
        with Image.open(file_path) as img:
            result["sections"]["Image Properties"] = {
                "Format": str(img.format), "Dimensions": f"{img.width} x {img.height} pixels", "Color Mode": str(img.mode),
            }
            camera_names = {"Make", "Model", "LensMake", "LensModel", "Software", "HostComputer", "Artist",
                            "Copyright", "CameraOwnerName", "BodySerialNumber"}
            skip_names = {"MakerNote", "ExifOffset", "GPSInfo", "InteropOffset", "SubIFDs", "PrintImageMatching"}
            camera: Dict[str, str] = {}
            dates: Dict[str, str] = {}
            other: Dict[str, str] = {}
            gps: Dict[str, str] = {}

            exif = img.getexif()
            tag_items: List[Tuple[Any, Any]] = list(exif.items()) if exif else []
            if exif:
                for ifd_id in (0x8769,):  # Exif sub-IFD (DateTimeOriginal, lens, etc.)
                    try:
                        tag_items.extend(exif.get_ifd(ifd_id).items())
                    except Exception:
                        pass
            for tag, value in tag_items:
                name = ExifTags.TAGS.get(tag, f"Tag 0x{tag:04X}") if isinstance(tag, int) else str(tag)
                if name in skip_names:
                    continue
                text = clean_value(value)
                if text == "":
                    continue
                if name in camera_names:
                    camera[name] = text
                elif name.startswith(("DateTime", "OffsetTime", "SubsecTime")):
                    dates[name] = text
                else:
                    other[name] = text

            if exif:
                try:
                    gps_raw = exif.get_ifd(0x8825)
                except Exception:
                    gps_raw = {}
                named = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in dict(gps_raw).items()}
                for key, value in named.items():
                    text = clean_value(value)
                    if text:
                        gps[key] = text
                if "GPSLatitude" in named and "GPSLongitude" in named:
                    lat = _gps_to_decimal(named["GPSLatitude"], named.get("GPSLatitudeRef", "N"))
                    lon = _gps_to_decimal(named["GPSLongitude"], named.get("GPSLongitudeRef", "E"))
                    if lat is not None and lon is not None:
                        gps["Decimal Coordinates (lat, lon)"] = f"{lat}, {lon}"
                if gps:
                    result["notes"].append(
                        "GPS coordinates are embedded in this image. They may reveal where it was captured; "
                        "handle with appropriate privacy care."
                    )

            if str(img.format).upper() == "PNG":
                png_text: Dict[str, str] = {}
                ignored = {"exif", "icc_profile", "transparency", "gamma", "dpi", "interlace", "aspect"}
                for key, value in list(img.info.items())[:30]:
                    if key not in ignored and isinstance(value, str) and value.strip():
                        png_text[str(key)] = clean_value(value)
                if png_text:
                    result["sections"]["PNG Text Chunks"] = png_text

            result["sections"]["EXIF - Camera & Software"] = camera
            result["sections"]["EXIF - Date/Time"] = dates
            result["sections"]["EXIF - Other"] = other
            result["sections"]["EXIF - GPS"] = gps
            result["sections"] = {k: v for k, v in result["sections"].items() if v}
    except Exception as exc:
        result["error"] = f"The image could not be read (invalid, truncated or unsupported): {type(exc).__name__}."
    return result


def extract_pe_metadata(file_path: str) -> Dict[str, Any]:
    """Read basic PE header fields from an executable (the file is NEVER executed)."""
    result = new_metadata_result("Windows PE executable")
    try:
        pe = parse_pe_header(file_path)
        if pe is None:
            result["notes"].append("A valid PE header could not be parsed.")
            return result
        fields = {
            "Target Architecture": pe["machine"],
            "Number of Sections": str(pe["sections"]),
            "Type": "DLL (library)" if pe["is_dll"] else "Executable image",
        }
        if pe["timestamp"]:
            compiled = datetime.fromtimestamp(pe["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            fields["Header Compile Timestamp"] = compiled
            result["notes"].append("The compile timestamp is written by the build tool and can be forged or zeroed; treat it as a hint only.")
        result["sections"]["PE Header"] = fields
    except Exception as exc:
        result["error"] = f"The PE header could not be read: {type(exc).__name__}."
    return result


def analyze_metadata(file_path: str, extension: str, kind: str) -> Dict[str, Any]:
    """Choose the right metadata extractor based on detected content (or extension as a fallback)."""
    if kind == "pdf":
        meta = extract_pdf_metadata(file_path)
    elif kind in ("png", "jpeg"):
        meta = extract_image_metadata(file_path)
    elif kind == "exe":
        meta = extract_pe_metadata(file_path)
    elif kind == "zip" and extension == ".docx":
        meta = extract_docx_metadata(file_path)
    elif extension == ".pdf":
        meta = extract_pdf_metadata(file_path)
    elif extension in (".jpg", ".jpeg", ".png"):
        meta = extract_image_metadata(file_path)
    elif extension == ".docx":
        meta = extract_docx_metadata(file_path)
    else:
        meta = new_metadata_result("Not applicable")
        meta["notes"].append("No metadata extractor is available for this file type.")
    meta["available"] = metadata_available(meta)
    return meta


# --------------------------------------------------------------------------------------
# Suspicious file detection
# --------------------------------------------------------------------------------------
def detect_suspicious_filename(filename: str) -> Dict[str, Any]:
    """Check the file name for double extensions, risky extensions and naming anomalies."""
    clean = filename.replace("\\", "/").split("/")[-1]
    lowered = clean.lower()
    suffixes = [s.strip().lower() for s in Path(clean).suffixes]
    extension = suffixes[-1] if suffixes else ""
    compound = lowered.endswith(COMPOUND_EXTENSIONS)

    double_extension = False
    double_executable = False
    if len(suffixes) >= 2 and not compound:
        penultimate, last = suffixes[-2], suffixes[-1]
        if penultimate in KNOWN_FILE_EXTENSIONS and (last in RISKY_EXTENSIONS or last in KNOWN_FILE_EXTENSIONS) \
                and penultimate != last:
            double_extension = True
            double_executable = last in RISKY_EXTENSIONS

    anomalies: List[Dict[str, str]] = []
    alpha_suffixes = [s for s in suffixes if re.fullmatch(r"\.[a-z]{2,5}", s)]
    if len(alpha_suffixes) >= 3 and not compound:
        anomalies.append({
            "title": f"Multiple extensions detected ({len(alpha_suffixes)})",
            "explanation": "Several consecutive extensions can be used to confuse users about the real file type.",
        })
    if any(suffixes[i] == suffixes[i + 1] for i in range(len(suffixes) - 1)):
        anomalies.append({
            "title": "Repeated extension detected",
            "explanation": "The same extension appears twice in a row (for example 'file.pdf.pdf'), which is unusual.",
        })
    if re.search(r"\s{3,}", clean) or re.search(r"\s+\.", clean) or clean != clean.strip():
        anomalies.append({
            "title": "Excessive or misplaced spaces in file name",
            "explanation": "Long runs of spaces can push the real extension out of view in some file listings.",
        })
    if len(clean) > 100:
        anomalies.append({
            "title": f"Very long file name ({len(clean)} characters)",
            "explanation": "Extremely long names can hide the true extension when truncated by user interfaces.",
        })
    control_chars = any(unicodedata.category(ch) in ("Cc", "Cf") for ch in clean)
    if control_chars:
        anomalies.append({
            "title": "Hidden control/formatting characters in file name",
            "explanation": (
                "Characters such as the right-to-left override (U+202E) can make a file name display with a "
                "different extension than it really has."
            ),
        })

    return {
        "extension": extension if extension else "(none)",
        "all_extensions": suffixes,
        "double_extension": double_extension,
        "double_extension_executable": double_executable,
        "risky_extension": extension in RISKY_EXTENSIONS,
        "control_characters": control_chars,
        "anomalies": anomalies,
    }


def detect_file_type_mismatch(filename: str, file_path: str, signature: Dict[str, Any]) -> Dict[str, Any]:
    """Compare the extension with the detected content type (magic bytes)."""
    extension = get_extension(filename)
    kind = signature["kind"]
    result: Dict[str, Any] = {
        "status": "inconclusive", "extension": extension or "(none)", "detected_kind": kind,
        "detected_description": signature["description"], "detected_mime": signature["mime"],
        "mime_by_extension": mimetypes.guess_type(filename)[0] or "Unknown",
        "explanation": "", "executable_disguised": False,
    }
    expected = EXPECTED_KINDS.get(extension)
    if kind == "empty":
        result["explanation"] = "The file is empty, so no signature comparison is possible. Result is inconclusive."
        return result
    if expected is None:
        result["explanation"] = (
            f"No signature rule exists for the extension '{extension or '(none)'}'. Result is inconclusive."
        )
        return result

    if kind in expected:
        # Extra structural validation for DOCX packages.
        if extension == ".docx" and kind == "zip":
            try:
                with zipfile.ZipFile(file_path) as archive:
                    names = set(archive.namelist())
                if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                    result.update(
                        status="mismatch",
                        explanation=(
                            "The file is a ZIP container but lacks the standard Word package structure "
                            "(word/document.xml). Possible file type mismatch detected."
                        ),
                    )
                    return result
            except zipfile.BadZipFile:
                result["explanation"] = "The ZIP structure could not be read. Result is inconclusive."
                return result
        result.update(status="match", explanation="The file extension is consistent with the detected content signature.")
        return result

    if kind == "unknown" and "text" in expected:
        result.update(
            status="mismatch",
            explanation=(
                "The extension suggests readable text but the content looks like binary data. Possible file "
                "type mismatch detected (compressed or encrypted data can also cause this)."
            ),
        )
        return result
    if kind == "unknown":
        result["explanation"] = "The content does not match any known signature. Result is inconclusive."
        return result

    disguised = signature.get("executable", False) and not any(k in EXECUTABLE_KINDS for k in expected)
    expected_label = KIND_LABELS.get(expected[0], expected[0])
    result.update(
        status="mismatch",
        executable_disguised=disguised,
        explanation=(
            f"Possible file type mismatch detected: the extension '{extension}' normally indicates "
            f"{expected_label}, but the content appears to be {signature['description']}. "
            "A mismatch does not by itself prove malicious intent."
        ),
    )
    return result


def analyze_archive(file_path: str) -> Dict[str, Any]:
    """Inspect ZIP-based containers by reading the central directory only (nothing is extracted)."""
    info: Dict[str, Any] = {
        "analyzed": False, "error": None, "entries": 0, "encrypted": 0, "path_traversal": [],
        "executables": [], "macro_parts": [], "total_uncompressed": 0, "ratio": 0.0, "listing": [],
    }
    try:
        with zipfile.ZipFile(file_path) as archive:
            infos = archive.infolist()
            info["entries"] = len(infos)
            compressed_total = 0
            for item in infos:
                name = item.filename
                parts = name.replace("\\", "/").split("/")
                if item.flag_bits & 0x1:
                    info["encrypted"] += 1
                if name.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", name):
                    info["path_traversal"].append(safe_display(name))
                lower = name.lower()
                if Path(lower).suffix in RISKY_EXTENSIONS | {".dll", ".msi", ".com", ".pif"}:
                    info["executables"].append(safe_display(name))
                if lower.endswith("vbaproject.bin"):
                    info["macro_parts"].append(safe_display(name))
                info["total_uncompressed"] += item.file_size
                compressed_total += item.compress_size
                if len(info["listing"]) < 200:
                    info["listing"].append({
                        "Entry": safe_display(name), "Size (bytes)": item.file_size,
                        "Compressed (bytes)": item.compress_size, "Encrypted": "Yes" if item.flag_bits & 0x1 else "No",
                    })
            if compressed_total > 0:
                info["ratio"] = round(info["total_uncompressed"] / compressed_total, 1)
            info["analyzed"] = True
    except zipfile.BadZipFile:
        info["error"] = "The ZIP structure is corrupted or incomplete and could not be read."
    except Exception as exc:
        info["error"] = f"The archive could not be inspected: {type(exc).__name__}."
    for key in ("path_traversal", "executables", "macro_parts"):
        info[key] = info[key][:50]
    return info


# --------------------------------------------------------------------------------------
# Indicators: URLs and IPv4 addresses
# --------------------------------------------------------------------------------------
def is_valid_ipv4(candidate: str) -> bool:
    """Strict IPv4 validation: four octets, 0-255, no leading zeros."""
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) > 255 or (len(part) > 1 and part.startswith("0")):
            return False
    return True


def classify_ip(ip_text: str) -> str:
    """Label an IPv4 address (private, loopback, public ...) for analyst context only."""
    try:
        ip = ipaddress.IPv4Address(ip_text)
    except ValueError:
        return "Unknown"
    if ip.is_loopback:
        return "Loopback"
    if ip.is_private:
        return "Private"
    if ip.is_link_local:
        return "Link-local"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "Reserved/Special"
    return "Public"


def detect_text_encoding(file_path: str) -> str:
    """Pick a text encoding by BOM; default to UTF-8."""
    with open(file_path, "rb") as handle:
        head = handle.read(4)
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def extract_urls_and_ips(file_path: str, extension: str, kind: str) -> Dict[str, Any]:
    """Extract URLs and valid IPv4 addresses from TXT/LOG/CSV/JSON files (offline, line by line)."""
    result: Dict[str, Any] = {
        "supported": False, "urls": [], "ips": [], "total_urls": 0, "total_ips": 0,
        "truncated": False, "note": "",
    }
    if extension not in TEXT_EXTENSIONS:
        result["note"] = "Not applicable: indicator extraction is performed only for TXT, LOG, CSV and JSON files."
        return result
    if kind == "empty":
        result["supported"] = True
        result["note"] = "The file is empty, so there is nothing to scan."
        return result
    if kind != "text":
        result["note"] = "The content is not readable text, so URL/IP extraction was skipped."
        return result

    result["supported"] = True
    url_counter: Counter = Counter()
    ip_counter: Counter = Counter()
    scanned = 0
    encoding = detect_text_encoding(file_path)
    with open(file_path, "r", encoding=encoding, errors="ignore") as handle:
        for line in handle:
            scanned += len(line)
            if scanned > TEXT_SCAN_LIMIT:
                result["truncated"] = True
                break
            for match in URL_REGEX.findall(line):
                url = match.rstrip(".,;:!?)'\"")
                if url:
                    url_counter[url] += 1
            for match in IPV4_REGEX.findall(line):
                if is_valid_ipv4(match):
                    ip_counter[match] += 1

    result["urls"] = [{"url": u, "count": c} for u, c in url_counter.most_common()]
    result["ips"] = [{"ip": ip, "count": c, "type": classify_ip(ip)} for ip, c in ip_counter.most_common()]
    result["total_urls"] = sum(url_counter.values())
    result["total_ips"] = sum(ip_counter.values())
    notes = ["Extracted values were NOT visited, pinged or contacted. Dotted numbers such as software versions can resemble IPv4 addresses."]
    if result["truncated"]:
        notes.append(f"Only the first {TEXT_SCAN_LIMIT // (1024 * 1024)} MB of text was scanned.")
    result["note"] = " ".join(notes)
    return result


# --------------------------------------------------------------------------------------
# Binary analysis: entropy, byte distribution and hex dumps
# --------------------------------------------------------------------------------------
def shannon_entropy(counts: Any, total: int) -> float:
    """Shannon entropy in bits per byte from byte-value counts."""
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def describe_entropy(value: float) -> str:
    """Plain-language label for an entropy value."""
    if value < 3.5:
        return "Low (repetitive or sparse data)"
    if value < 6.0:
        return "Moderate (typical text or structured data)"
    if value < HIGH_ENTROPY_THRESHOLD:
        return "Elevated (mixed content or native code)"
    return "High (compressed, encrypted or packed data)"


def analyze_entropy(file_path: str) -> Dict[str, Any]:
    """Stream the file in blocks and compute per-block entropy plus a 256-bin byte histogram."""
    size = os.path.getsize(file_path)
    scan_size = min(size, ENTROPY_SCAN_LIMIT)
    result: Dict[str, Any] = {
        "overall": 0.0, "block_size": 0, "blocks": [], "byte_counts": [0] * 256, "scanned": scan_size,
        "truncated": size > ENTROPY_SCAN_LIMIT, "high_blocks": 0, "high_entropy": False,
    }
    if scan_size == 0:
        return result
    block_size = max(256, -(-scan_size // ENTROPY_MAX_BLOCKS))
    result["block_size"] = block_size
    totals = result["byte_counts"]
    offset = 0
    remaining = scan_size
    with open(file_path, "rb") as handle:
        while remaining > 0:
            chunk = handle.read(min(block_size, remaining))
            if not chunk:
                break
            counts = Counter(chunk)
            for value, count in counts.items():
                totals[value] += count
            block_entropy = shannon_entropy(counts.values(), len(chunk))
            result["blocks"].append({"start": offset, "end": offset + len(chunk) - 1, "entropy": round(block_entropy, 4)})
            if len(chunk) >= 1024 and block_entropy >= HIGH_ENTROPY_THRESHOLD:
                result["high_blocks"] += 1
            offset += len(chunk)
            remaining -= len(chunk)
    result["overall"] = round(shannon_entropy(totals, sum(totals)), 4)
    result["high_entropy"] = result["overall"] >= HIGH_ENTROPY_THRESHOLD
    return result


def format_hex_lines(data: bytes, start_offset: int = 0, width: int = 16) -> List[str]:
    """Classic hex dump lines: offset, hex bytes, ASCII column."""
    lines: List[str] = []
    for i in range(0, len(data), width):
        part = data[i:i + width]
        hex_part = " ".join(f"{b:02X}" for b in part).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in part)
        lines.append(f"{start_offset + i:08X}  {hex_part}  |{ascii_part}|")
    return lines


def generate_hex_dump(file_path: str, length: int = 256) -> List[str]:
    """Hex dump of the first bytes of the file (read-only)."""
    with open(file_path, "rb") as handle:
        data = handle.read(length)
    return format_hex_lines(data)


# --------------------------------------------------------------------------------------
# Risk score and findings
# --------------------------------------------------------------------------------------
def calculate_risk_score(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Transparent additive score (0-100) built only from detected findings."""
    reasons: List[Tuple[str, int]] = []
    sec = analysis["security"]
    filename_info = sec["filename"]
    mismatch = sec["mismatch"]
    archive = sec["archive"]
    indicators = analysis["indicators"]
    integrity = analysis["integrity"]

    if filename_info["double_extension"]:
        if filename_info["double_extension_executable"]:
            reasons.append(("Double extension ending in an executable/script type", RISK_POINTS["double_extension_executable"]))
        else:
            reasons.append(("Double extension (multiple known file extensions)", RISK_POINTS["double_extension_other"]))
    if filename_info["risky_extension"]:
        reasons.append((f"Potentially risky file type ({filename_info['extension']})", RISK_POINTS["risky_extension"]))
    if mismatch["status"] == "mismatch":
        if mismatch["executable_disguised"]:
            reasons.append(("Executable content hidden behind a non-executable extension", RISK_POINTS["type_mismatch_executable_disguised"]))
        else:
            reasons.append(("File type / extension mismatch", RISK_POINTS["type_mismatch"]))
    if sec["hidden"]["status"] == "Yes":
        reasons.append(("File is hidden (name begins with a dot)", RISK_POINTS["hidden_file"]))
    if filename_info["control_characters"]:
        reasons.append(("Control/formatting characters in file name", RISK_POINTS["control_characters"]))
    other_anomalies = [a for a in filename_info["anomalies"] if not a["title"].startswith("Hidden control")]
    if other_anomalies:
        points = min(len(other_anomalies) * RISK_POINTS["filename_anomaly_each"], RISK_POINTS["filename_anomaly_cap"])
        reasons.append((f"{len(other_anomalies)} file name anomaly indicator(s)", points))
    if indicators["urls"]:
        many = len(indicators["urls"]) >= URLS_MANY_THRESHOLD
        reasons.append((f"{len(indicators['urls'])} unique URL(s) found", RISK_POINTS["urls_many" if many else "urls_found"]))
    if indicators["ips"]:
        many = len(indicators["ips"]) >= IPS_MANY_THRESHOLD
        reasons.append((f"{len(indicators['ips'])} unique IPv4 address(es) found", RISK_POINTS["ips_many" if many else "ips_found"]))
    if integrity["status"] == "mismatch":
        reasons.append(("Supplied hash does not match calculated hash", RISK_POINTS["integrity_mismatch"]))
    if archive.get("analyzed"):
        if archive["executables"]:
            reasons.append((f"Archive contains {len(archive['executables'])} executable/script entr(ies)", RISK_POINTS["archive_executables"]))
        if archive["path_traversal"]:
            reasons.append(("Archive entries use absolute or parent-directory paths", RISK_POINTS["archive_path_traversal"]))
        if archive["macro_parts"]:
            reasons.append(("Office package contains a VBA macro project", RISK_POINTS["archive_macro_part"]))
        if archive["ratio"] >= 100 or archive["total_uncompressed"] > 1024 ** 3:
            reasons.append(("Very high compression ratio / expanded size", RISK_POINTS["archive_high_ratio"]))

    entropy_info = analysis.get("entropy", {})
    if entropy_info.get("high_entropy") and analysis["signature"]["kind"] in EXECUTABLE_KINDS:
        reasons.append(("Executable with very high byte entropy (possible packing/encryption)", RISK_POINTS["high_entropy_executable"]))
    score = min(sum(points for _, points in reasons), 100)
    level = "High Risk" if score >= 70 else "Medium Risk" if score >= 30 else "Low Risk"
    return {"score": score, "level": level, "reasons": reasons}


def build_findings(analysis: Dict[str, Any]) -> List[Dict[str, str]]:
    """Convert analysis results into Information / Warning / Critical findings."""
    findings: List[Dict[str, str]] = []

    def add(level: str, title: str, explanation: str) -> None:
        findings.append({"level": level, "title": title, "explanation": explanation})

    sec = analysis["security"]
    fn = sec["filename"]
    mm = sec["mismatch"]
    arc = sec["archive"]
    ind = analysis["indicators"]
    integ = analysis["integrity"]
    meta = analysis["metadata"]

    add("Information", "File information collected", "Basic file attributes were read from the temporary copy of the evidence.")
    if analysis["hashes"].get("sha256"):
        add("Information", "Cryptographic hashes calculated", "MD5 and SHA-256 values can later be used to prove the file was not altered.")
    add("Information", "Metadata found" if meta.get("available") else "No readable metadata found",
        "Metadata fields were extracted without modifying the file." if meta.get("available")
        else "The file has no metadata supported by this tool, or none could be read.")

    if integ["status"] == "match":
        add("Information", "Integrity verified", "The calculated hash equals the supplied hash.")
    elif integ["status"] == "mismatch":
        add("Warning", "Integrity mismatch",
            "The calculated hash differs from the supplied hash. The file differs from the version the hash was taken "
            "from; this does not by itself prove malicious activity (the wrong hash or file version may have been supplied).")
    elif integ["status"] == "invalid":
        add("Information", "Supplied hash is not valid", "The expected hash was not a valid MD5 or SHA-256 value, so no comparison was made.")
    else:
        add("Information", "Integrity not checked", "No expected hash was supplied.")

    if fn["double_extension"]:
        add("Warning", "Suspicious double extension detected",
            "Multiple extensions can sometimes be used to disguise executable files, but this does not prove malicious activity.")
    if fn["risky_extension"]:
        add("Warning", f"Potentially risky file type ({fn['extension']})",
            "Potentially risky file type — manual verification recommended. The extension alone does not mean the file is malware.")
    for anomaly in fn["anomalies"]:
        add("Warning", anomaly["title"], anomaly["explanation"])

    if mm["status"] == "mismatch":
        if mm["executable_disguised"]:
            add("Critical / High Risk", "Executable content disguised with a non-executable extension",
                "The file signature indicates an executable program, yet the extension suggests a different, harmless-looking "
                "type. This is a clearly defined high-risk indicator, but it still does not prove the program is malicious.")
        else:
            add("Warning", "Possible file type mismatch detected",
                "The extension does not agree with the detected content signature. A mismatch does not automatically mean malware.")
    elif mm["status"] == "match":
        add("Information", "File type consistent with extension", "The magic bytes agree with the file extension.")
    else:
        add("Information", "File type check inconclusive", mm["explanation"])

    if sec["hidden"]["status"] == "Yes":
        add("Information", "Hidden file", sec["hidden"]["explanation"])
    else:
        add("Information", "Hidden status could not be determined", sec["hidden"]["explanation"])

    if arc.get("analyzed"):
        if arc["executables"]:
            add("Warning", "Archive contains executable or script entries",
                "The container lists executable-type files. They were not extracted or run; manual review is recommended.")
        if arc["path_traversal"]:
            add("Warning", "Archive entries with absolute or parent-directory paths",
                "Such paths can overwrite files when carelessly extracted. Extract only in an isolated environment.")
        if arc["macro_parts"]:
            add("Warning", "Embedded VBA macro project found",
                "Macros can automate actions when a document is opened in an office application. The macro was not executed.")
        if arc["encrypted"]:
            add("Information", "Encrypted archive entries", f"{arc['encrypted']} entr(ies) are password protected and cannot be inspected.")
        if arc["ratio"] >= 100 or arc["total_uncompressed"] > 1024 ** 3:
            add("Warning", "Very high compression ratio",
                "Extremely compressible archives can expand to very large sizes (a 'decompression bomb' pattern), though legitimate data can behave similarly.")
    elif arc.get("error"):
        add("Information", "Archive could not be inspected", arc["error"])

    ent = analysis.get("entropy", {})
    if ent.get("scanned"):
        if ent["high_entropy"] and analysis["signature"]["kind"] in EXECUTABLE_KINDS:
            add("Warning", "Very high byte entropy in an executable",
                "Sustained entropy near 8 bits/byte can indicate packing or encryption, but legitimate installers and compressed resources behave similarly. It does not prove malicious activity.")
        elif ent["high_entropy"]:
            add("Information", "High overall entropy",
                "The content looks compressed or encrypted. This is normal for formats such as ZIP, PNG, JPEG and DOCX.")
        else:
            add("Information", f"Entropy profile calculated ({ent['overall']:.2f} bits/byte)", describe_entropy(ent["overall"]) + ".")
    if ind["supported"]:
        add("Information", f"{len(ind['urls'])} unique URL(s) / {len(ind['ips'])} unique IPv4 address(es) found",
            "Indicators are listed for review only. They were not visited or contacted, and their presence is not proof of malicious intent.")
    return findings


def build_analysis(base: Dict[str, Any], expected_hash: str, case: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Combine the cached base analysis with the (cheap) integrity, score and findings steps."""
    analysis = dict(base)
    analysis["case"] = case or {}
    analysis["integrity"] = verify_integrity(expected_hash, base["hashes"])
    analysis["risk"] = calculate_risk_score(analysis)
    analysis["findings"] = build_findings(analysis)
    return analysis


# --------------------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------------------
def run_step(errors: List[str], label: str, func: Callable[..., Any], default: Any, *args: Any) -> Any:
    """Run an analysis step; on failure record a friendly error and return a default."""
    try:
        return func(*args)
    except PermissionError:
        errors.append(f"{label}: permission denied while reading the file.")
    except Exception as exc:
        errors.append(f"{label} could not be completed ({type(exc).__name__}: {str(exc)[:120]}).")
    return default


def analyze_file(file_path: str, original_name: str) -> Dict[str, Any]:
    """Run every analysis step on a (temporary) file path. The file is only ever read."""
    errors: List[str] = []
    name = original_name.replace("\\", "/").split("/")[-1] or "unnamed"
    extension = get_extension(name)

    signature = run_step(errors, "Signature detection", detect_file_signature, None, file_path)
    if signature is None:
        signature = {"kind": "unknown", "description": "Could not be determined", "mime": "Unknown", "executable": False}
    file_info = run_step(errors, "File information", get_file_information, None, file_path, name, signature)
    if file_info is None:
        file_info = {
            "name": name, "display_name": safe_display(name), "extension": extension or "(none)", "size_bytes": 0,
            "size_human": "Unavailable", "file_type": signature["description"], "mime_by_extension": "Unknown",
            "mime_detected": signature["mime"], "path": file_path, "created": "Unavailable", "modified": "Unavailable",
            "accessed": "Unavailable", "timestamp_note": "",
        }
    hashes = run_step(errors, "Hash calculation", calculate_hashes, {"md5": None, "sha256": None}, file_path)
    metadata = run_step(errors, "Metadata analysis", analyze_metadata, None, file_path, extension, signature["kind"])
    if metadata is None:
        metadata = new_metadata_result("Unavailable")
        metadata["available"] = False
    filename_info = detect_suspicious_filename(name)
    mismatch = run_step(
        errors, "File type check", detect_file_type_mismatch,
        {"status": "inconclusive", "extension": extension, "detected_kind": signature["kind"],
         "detected_description": signature["description"], "detected_mime": signature["mime"],
         "mime_by_extension": "Unknown", "explanation": "The check could not be completed.", "executable_disguised": False},
        name, file_path, signature,
    )
    archive = {"analyzed": False, "error": None, "entries": 0, "encrypted": 0, "path_traversal": [],
               "executables": [], "macro_parts": [], "total_uncompressed": 0, "ratio": 0.0, "listing": []}
    if signature["kind"] == "zip":
        archive = run_step(errors, "Archive inspection", analyze_archive, archive, file_path)
    indicators = run_step(
        errors, "Indicator extraction", extract_urls_and_ips,
        {"supported": False, "urls": [], "ips": [], "total_urls": 0, "total_ips": 0, "truncated": False,
         "note": "Indicator extraction could not be completed."},
        file_path, extension, signature["kind"],
    )
    entropy = run_step(
        errors, "Entropy analysis", analyze_entropy,
        {"overall": 0.0, "block_size": 0, "blocks": [], "byte_counts": [0] * 256, "scanned": 0, "truncated": False,
         "high_blocks": 0, "high_entropy": False},
        file_path,
    )
    hex_head = run_step(errors, "Hex dump", generate_hex_dump, [], file_path)
    return {
        "analysis_time": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "file": file_info,
        "signature": signature,
        "hashes": hashes,
        "metadata": metadata,
        "security": {
            "filename": filename_info,
            "mismatch": mismatch,
            "hidden": detect_hidden_status(name),
            "archive": archive,
        },
        "indicators": indicators,
        "entropy": entropy,
        "hex_head": hex_head,
        "errors": errors,
    }


def analyze_uploaded_file(uploaded: Any) -> Dict[str, Any]:
    """Copy the upload to a private temporary folder, analyse the copy, then discard it."""
    original_name = uploaded.name or "unnamed"
    safe_name = "evidence_" + (re.sub(r"[^A-Za-z0-9._-]", "_", Path(original_name.replace("\\", "/")).name)[:100] or "file")
    with tempfile.TemporaryDirectory(prefix="dffa_") as temp_dir:
        temp_path = os.path.join(temp_dir, safe_name)
        uploaded.seek(0)
        with open(temp_path, "wb") as out:
            shutil.copyfileobj(uploaded, out, 1024 * 1024)
        uploaded.seek(0)
        return analyze_file(temp_path, original_name)


# --------------------------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------------------------
def build_final_assessment(analysis: Dict[str, Any]) -> str:
    """Neutral summary sentence(s) for the report."""
    risk = analysis["risk"]
    flagged = [f for f in analysis["findings"] if f["level"] != "Information"]
    text = (
        f"The automated analysis of '{analysis['file']['display_name']}' produced a forensic risk score of "
        f"{risk['score']}/100 ({risk['level']}) from {len(flagged)} finding(s) that need review. "
    )
    if flagged:
        text += "The flagged characteristics are indicators for manual review and do not, on their own, establish that the file is malicious. "
    else:
        text += "No suspicious characteristics were detected by the checks implemented in this tool. "
    text += (
        "This tool performs static, read-only analysis only; the absence of findings does not guarantee that a file is safe. "
        "Conclusions should be confirmed with additional forensic tooling and expert judgement."
    )
    return text


def build_report_content(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build the report as neutral section data used by both the PDF and text writers."""
    f = analysis["file"]
    sec = analysis["security"]
    fn, mm, hid, arc = sec["filename"], sec["mismatch"], sec["hidden"], sec["archive"]
    integ, risk, ind, meta = analysis["integrity"], analysis["risk"], analysis["indicators"], analysis["metadata"]
    sections: List[Dict[str, Any]] = []

    header_rows = [("Project Name", PROJECT_NAME), ("Report Title", REPORT_TITLE), ("Analysis Date and Time", analysis["analysis_time"])]
    case = analysis.get("case") or {}
    for label, key in (("Case ID", "case_id"), ("Investigator", "investigator"), ("Organization / Unit", "organization"),
                       ("Examiner Notes", "notes")):
        if case.get(key):
            header_rows.append((label, case[key]))
    sections.append({"title": "Report Header", "rows": header_rows})
    sections.append({"title": "Evidence Information", "rows": [
        ("File Name", f["display_name"]), ("File Type", f["file_type"]), ("File Extension", f["extension"]),
        ("File Size", f["size_human"]), ("MIME (by extension)", f["mime_by_extension"]),
        ("MIME (by content)", f["mime_detected"]), ("File Path (temporary copy)", f["path"]),
    ]})
    sections.append({"title": "Timeline", "rows": [
        ("Created", f["created"]), ("Modified", f["modified"]), ("Accessed", f["accessed"]),
        ("Note", f["timestamp_note"]),
    ]})
    sections.append({"title": "Hash Information", "rows": [
        ("MD5", analysis["hashes"].get("md5") or "Unavailable"), ("SHA-256", analysis["hashes"].get("sha256") or "Unavailable"),
    ]})
    sections.append({"title": "Integrity Verification", "rows": [
        ("Expected Hash", integ["expected"] or "Not supplied"),
        ("Calculated Hash", (integ["calculated"] or "Not applicable") + (f" ({integ['algorithm']})" if integ["algorithm"] else "")),
        ("Verification Result", integ["message"]),
    ]})

    meta_rows: List[Tuple[str, str]] = []
    if meta.get("error"):
        meta_rows.append(("Error", meta["error"]))
    for section_name, fields in meta.get("sections", {}).items():
        for key, value in fields.items():
            meta_rows.append((f"{section_name}: {key}", value))
    for note in meta.get("notes", []):
        meta_rows.append(("Note", note))
    if not meta.get("available"):
        meta_rows.insert(0, ("Result", "No readable metadata found."))
    sections.append({"title": "Metadata", "rows": meta_rows})

    security_rows: List[Tuple[str, str]] = [
        ("Final Extension", fn["extension"]),
        ("Potentially Risky Extension", "Yes — potentially risky file type; manual verification recommended" if fn["risky_extension"] else "No"),
        ("Double Extension", "Yes — suspicious double extension detected" if fn["double_extension"] else "No"),
        ("File Type Mismatch", {"mismatch": "Yes — possible file type mismatch detected", "match": "No — extension consistent with content",
                                "inconclusive": "Inconclusive"}[mm["status"]]),
        ("Detail", mm["explanation"]),
        ("Hidden File Status", f"{hid['status']} — {hid['explanation']}"),
    ]
    if fn["anomalies"]:
        for anomaly in fn["anomalies"]:
            security_rows.append(("File Name Anomaly", anomaly["title"]))
    else:
        security_rows.append(("File Name Anomalies", "None detected"))
    if arc.get("analyzed"):
        security_rows.append(("Archive Entries", f"{arc['entries']} (executable-type: {len(arc['executables'])}, "
                                                 f"path traversal: {len(arc['path_traversal'])}, encrypted: {arc['encrypted']}, "
                                                 f"macro projects: {len(arc['macro_parts'])})"))
    sections.append({"title": "Security Analysis", "rows": security_rows})

    ind_lines: List[str] = []
    if ind["supported"]:
        ind_lines.append(f"URLs found: {ind['total_urls']} total ({len(ind['urls'])} unique)")
        ind_lines.extend(f"{safe_display(u['url'])}  (x{u['count']})" for u in ind["urls"][:100])
        if len(ind["urls"]) > 100:
            ind_lines.append(f"{len(ind['urls']) - 100} further unique URL(s) omitted from this report.")
        ind_lines.append(f"IPv4 addresses found: {ind['total_ips']} total ({len(ind['ips'])} unique)")
        ind_lines.extend(f"{i['ip']}  [{i['type']}]  (x{i['count']})" for i in ind["ips"][:100])
        if len(ind["ips"]) > 100:
            ind_lines.append(f"{len(ind['ips']) - 100} further unique IPv4 address(es) omitted from this report.")
    ind_lines.append(ind["note"] or "Indicators were not contacted or visited.")
    sections.append({"title": "Indicators (URLs and IPv4 Addresses)", "lines": ind_lines})

    ent = analysis.get("entropy", {})
    if ent.get("scanned"):
        sections.append({"title": "Binary Analysis", "rows": [
            ("Overall Entropy", f"{ent['overall']:.3f} bits/byte (maximum 8.0) - {describe_entropy(ent['overall'])}"),
            ("Bytes Analysed", f"{ent['scanned']:,}" + (" (first 32 MB only)" if ent["truncated"] else " (entire file)")),
            ("Blocks Analysed", f"{len(ent['blocks'])} blocks of about {ent['block_size']:,} bytes"),
            (f"High-Entropy Blocks (>= {HIGH_ENTROPY_THRESHOLD})", str(ent["high_blocks"])),
        ]})
    if analysis.get("hex_head"):
        sections.append({"title": "Hex Dump (first 256 bytes)", "mono": list(analysis["hex_head"])})
    risk_lines = [f"Risk Score: {risk['score']} / 100", f"Risk Level: {risk['level']}"]
    risk_lines.extend(f"+{points}: {reason}" for reason, points in risk["reasons"])
    if not risk["reasons"]:
        risk_lines.append("No contributing factors were detected.")
    sections.append({"title": "Risk Assessment", "lines": risk_lines})
    sections.append({"title": "Findings", "lines": [f"[{x['level']}] {x['title']}: {x['explanation']}" for x in analysis["findings"]]})
    if analysis["errors"]:
        sections.append({"title": "Analysis Errors / Limitations", "lines": list(analysis["errors"])})
    sections.append({"title": "Final Assessment", "lines": [build_final_assessment(analysis)]})
    return sections


def pdf_text(value: Any) -> str:
    """Make text safe for ReportLab paragraphs (escaped, Latin-1 only for the built-in fonts)."""
    text = safe_display(value).encode("latin-1", "replace").decode("latin-1")
    return xml_escape(text)


def generate_pdf_report(analysis: Dict[str, Any]) -> bytes:
    """Create the PDF forensic report with ReportLab and return its bytes."""
    if not REPORTLAB_OK:
        raise RuntimeError("ReportLab is not installed.")
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
        title=REPORT_TITLE, author=PROJECT_NAME,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("DFTitle", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#0b3d62"))
    h2_style = ParagraphStyle("DFH2", parent=styles["Heading2"], textColor=colors.HexColor("#0b3d62"), spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("DFBody", parent=styles["BodyText"], fontSize=9.5, leading=13, wordWrap="CJK")
    cell = ParagraphStyle("DFCell", parent=body, fontSize=8.5, leading=11)
    mono_style = ParagraphStyle("DFMono", fontName="Courier", fontSize=6.8, leading=8.6)

    def footer(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(1.8 * cm, 1.0 * cm, f"{PROJECT_NAME} - confidential forensic report")
        canvas.drawRightString(A4[0] - 1.8 * cm, 1.0 * cm, f"Page {document.page}")
        canvas.restoreState()

    story: List[Any] = [Paragraph(pdf_text(REPORT_TITLE), title_style),
                        Paragraph(pdf_text(f"{PROJECT_NAME} | Generated {analysis['analysis_time']}"), body),
                        Spacer(1, 8)]
    for section in build_report_content(analysis):
        story.append(Paragraph(pdf_text(section["title"]), h2_style))
        if "rows" in section:
            data = [[Paragraph("<b>" + pdf_text(k) + "</b>", cell), Paragraph(pdf_text(v), cell)] for k, v in section["rows"]]
            table = Table(data, colWidths=[4.8 * cm, 12.6 * cm])
            table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b8c4d0")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eaf1f8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(table)
        elif "lines" in section:
            for line in section["lines"]:
                story.append(Paragraph("&bull; " + pdf_text(line), body))
                story.append(Spacer(1, 2))
        else:
            mono_text = "\n".join(l.encode("latin-1", "replace").decode("latin-1") for l in section["mono"])
            story.append(Preformatted(mono_text, mono_style))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def generate_text_report(analysis: Dict[str, Any]) -> bytes:
    """Create the plain-text fallback forensic report."""
    lines: List[str] = [REPORT_TITLE.upper(), "=" * len(REPORT_TITLE), ""]
    for section in build_report_content(analysis):
        lines.extend([section["title"].upper(), "-" * len(section["title"])])
        if "rows" in section:
            lines.extend(f"{k}: {v}" for k, v in section["rows"])
        elif "lines" in section:
            lines.extend(f"- {line}" for line in section["lines"])
        else:
            lines.extend(section["mono"])
        lines.append("")
    return "\n".join(lines).encode("utf-8", errors="replace")


def generate_report(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a PDF report; fall back to a text report if PDF generation fails."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    short_hash = (analysis["hashes"].get("sha256") or "nohash")[:12]
    try:
        data = generate_pdf_report(analysis)
        return {"data": data, "file_name": f"forensic_report_{short_hash}_{stamp}.pdf",
                "mime": "application/pdf", "format": "PDF", "fallback_reason": None}
    except Exception as exc:
        data = generate_text_report(analysis)
        return {"data": data, "file_name": f"forensic_report_{short_hash}_{stamp}.txt",
                "mime": "text/plain", "format": "TXT", "fallback_reason": f"{type(exc).__name__}: {str(exc)[:120]}"}


# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Extra report formats (Markdown evidence file + bundle)
# --------------------------------------------------------------------------------------
def md_escape(value: Any) -> str:
    """Escape Markdown/HTML control characters so untrusted values cannot inject formatting or links."""
    text = re.sub(r"[\r\n]+", " ", safe_display(value))
    return re.sub(r"([\\`*_{}\[\]()<>#+!|~$])", r"\\\1", text)


def generate_markdown_report(analysis: Dict[str, Any]) -> str:
    """Create a structured Markdown evidence file (executive summary, case details, hashes, IOCs ...)."""
    f, risk, integ, ind = analysis["file"], analysis["risk"], analysis["integrity"], analysis["indicators"]
    flagged = sum(1 for x in analysis["findings"] if x["level"] != "Information")
    out: List[str] = [
        f"# {REPORT_TITLE}", "",
        f"**{PROJECT_NAME}** | Generated: {md_escape(analysis['analysis_time'])}", "",
        "## Executive Summary", "",
        "| Item | Result |", "|---|---|",
        f"| File Name | {md_escape(f['display_name'])} |",
        f"| SHA-256 | {md_escape(analysis['hashes'].get('sha256') or 'Unavailable')} |",
        f"| MD5 | {md_escape(analysis['hashes'].get('md5') or 'Unavailable')} |",
        f"| Integrity Status | {md_escape(integ['message'])} |",
        f"| Risk Score / Level | {risk['score']} / 100 - {md_escape(risk['level'])} |",
        f"| Findings Needing Review | {flagged} |",
        f"| IOC Summary | {len(ind['urls'])} unique URL(s), {len(ind['ips'])} unique IPv4 address(es) |",
        "",
    ]
    for section in build_report_content(analysis):
        out.extend([f"## {section['title']}", ""])
        if "rows" in section:
            out.extend(["| Field | Value |", "|---|---|"])
            out.extend(f"| {md_escape(k)} | {md_escape(v)} |" for k, v in section["rows"])
        elif "lines" in section:
            out.extend(f"- {md_escape(line)}" for line in section["lines"])
        else:
            out.append("```text")
            out.extend(section["mono"])
            out.append("```")
        out.append("")
    out.extend(["---", "*Static, read-only analysis. Findings are indicators for manual review and do not by themselves prove malicious activity.*", ""])
    return "\n".join(out)


def generate_all_reports(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build every downloadable evidence file (PDF or fallback, Markdown, plain text)."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    short = (analysis["hashes"].get("sha256") or "nohash")[:12]
    items: List[Dict[str, Any]] = []
    primary = generate_report(analysis)
    items.append({
        "label": f"{primary['format']} Report", "data": primary["data"], "file_name": primary["file_name"],
        "mime": primary["mime"], "note": "Fallback text report (PDF unavailable)." if primary["fallback_reason"] else "Formatted executive report.",
    })
    items.append({
        "label": "Markdown Evidence File", "data": generate_markdown_report(analysis).encode("utf-8", errors="replace"),
        "file_name": f"evidence_{short}_{stamp}.md", "mime": "text/markdown", "note": "Structured evidence file for documentation.",
    })
    if primary["format"] != "TXT":
        items.append({
            "label": "Plain Text Report", "data": generate_text_report(analysis),
            "file_name": f"forensic_report_{short}_{stamp}.txt", "mime": "text/plain", "note": "Portable plain-text copy.",
        })
    for item in items:
        item["sha256"] = hashlib.sha256(item["data"]).hexdigest()
    return items


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection in exported CSV cells."""
    text = safe_display(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def build_ioc_csv(analysis: Dict[str, Any]) -> bytes:
    """Export extracted indicators of compromise (URLs and IPv4 addresses) as CSV."""
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "occurrences", "category"])
    for entry in analysis["indicators"]["urls"]:
        writer.writerow(["url", csv_safe(entry["url"]), entry["count"], ""])
    for entry in analysis["indicators"]["ips"]:
        writer.writerow(["ipv4", entry["ip"], entry["count"], entry["type"]])
    return buffer.getvalue().encode("utf-8")


# --------------------------------------------------------------------------------------
# Streamlit user interface: forensic-lab dark theme
# --------------------------------------------------------------------------------------
LEVEL_COLORS = {"Low Risk": "#00FFC8", "Medium Risk": "#FFB020", "High Risk": "#FF3366"}

CUSTOM_CSS = """<style>
:root{--bg:#090A0F;--neon:#00FFC8;--alert:#FF3366;--warn:#FFB020;--violet:#B36BFF;--text:#D6FFF6;--muted:#8A9BB0;--glass:rgba(255,255,255,0.045);--mono:'JetBrains Mono','Fira Code',Consolas,'Courier New',monospace;}
.stApp{background:radial-gradient(1100px 560px at 8% -8%,rgba(0,255,200,0.08),transparent 60%),radial-gradient(900px 500px at 100% 0%,rgba(255,51,102,0.07),transparent 55%),#090A0F;color:var(--text);}
[data-testid="stHeader"]{background:transparent;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0B0E16,#070810);border-right:1px solid rgba(0,255,200,0.2);}
.stApp,.stApp p,.stApp label,.stApp li,.stApp span{color:var(--text);}
h1,h2,h3,h4,h5{color:var(--neon)!important;font-family:var(--mono)!important;letter-spacing:0.5px;}
h4{border-left:3px solid var(--neon);padding-left:10px;margin-top:1.2rem!important;text-shadow:0 0 10px rgba(0,255,200,0.35);}
hr{border-color:rgba(0,255,200,0.15)!important;}
.hero{position:relative;overflow:hidden;padding:22px 26px;margin-bottom:14px;border-radius:16px;background:linear-gradient(135deg,rgba(0,255,200,0.10),rgba(255,51,102,0.06));border:1px solid rgba(0,255,200,0.35);box-shadow:0 0 28px rgba(0,255,200,0.15),inset 0 0 30px rgba(0,255,200,0.05);backdrop-filter:blur(10px);}
.hero:after{content:"";position:absolute;left:0;right:0;height:2px;top:0;background:linear-gradient(90deg,transparent,var(--neon),transparent);animation:scan 3.5s linear infinite;}
@keyframes scan{0%{top:0;opacity:0.9}100%{top:100%;opacity:0}}
.hero-title{font-family:var(--mono);font-size:2rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:var(--neon);text-shadow:0 0 18px rgba(0,255,200,0.7);}
.hero-sub{font-family:var(--mono);color:var(--muted);margin-top:4px;font-size:0.9rem;}
.chip{display:inline-block;margin:10px 8px 0 0;padding:3px 10px;border-radius:999px;font-family:var(--mono);font-size:0.72rem;letter-spacing:1px;border:1px solid rgba(0,255,200,0.45);color:var(--neon);background:rgba(0,255,200,0.08);}
.chip.red{border-color:rgba(255,51,102,0.55);color:var(--alert);background:rgba(255,51,102,0.08);}
.sec-title{font-family:var(--mono);font-size:1.15rem;color:var(--neon);margin:18px 0 8px 0;letter-spacing:1px;text-transform:uppercase;}
.sec-num{display:inline-block;margin-right:10px;padding:2px 9px;border-radius:6px;background:rgba(0,255,200,0.12);border:1px solid rgba(0,255,200,0.4);}
.glass-card{background:var(--glass);backdrop-filter:blur(10px);border-radius:14px;padding:12px 16px;margin-bottom:12px;border:1px solid rgba(0,255,200,0.3);box-shadow:0 0 16px rgba(0,255,200,0.12);transition:box-shadow 0.25s,transform 0.25s;}
.glass-card:hover{box-shadow:0 0 26px rgba(0,255,200,0.3);transform:translateY(-1px);}
.glass-card.accent-red{border-color:rgba(255,51,102,0.5);box-shadow:0 0 16px rgba(255,51,102,0.18);}
.glass-card.accent-amber{border-color:rgba(255,176,32,0.5);box-shadow:0 0 16px rgba(255,176,32,0.15);}
.glass-card.accent-violet{border-color:rgba(179,107,255,0.5);box-shadow:0 0 16px rgba(179,107,255,0.15);}
.card-label{font-family:var(--mono);font-size:0.68rem;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);}
.card-value{font-family:var(--mono);font-size:0.98rem;color:var(--neon);margin-top:3px;word-break:break-all;text-shadow:0 0 8px rgba(0,255,200,0.35);}
.card-sub{font-family:var(--mono);font-size:0.72rem;color:var(--muted);margin-top:3px;}
.badge{display:inline-block;margin:3px 6px 3px 0;padding:3px 10px;border-radius:8px;font-family:var(--mono);font-size:0.78rem;word-break:break-all;border:1px solid;}
.badge-ok{color:var(--neon);border-color:rgba(0,255,200,0.5);background:rgba(0,255,200,0.08);}
.badge-warn{color:var(--warn);border-color:rgba(255,176,32,0.55);background:rgba(255,176,32,0.09);}
.badge-bad{color:var(--alert);border-color:rgba(255,51,102,0.6);background:rgba(255,51,102,0.10);box-shadow:0 0 10px rgba(255,51,102,0.25);}
.badge-url{color:#6CC8FF;border-color:rgba(108,200,255,0.5);background:rgba(108,200,255,0.08);}
.badge-muted{color:var(--muted);border-color:rgba(138,155,176,0.4);background:rgba(138,155,176,0.07);}
.banner{padding:14px 18px;border-radius:14px;margin:8px 0 14px 0;font-family:var(--mono);border:1px solid;backdrop-filter:blur(8px);}
.banner-title{font-weight:800;letter-spacing:1.5px;text-transform:uppercase;font-size:0.95rem;}
.banner-msg{margin-top:4px;font-size:0.85rem;opacity:0.92;}
.banner-ok{color:var(--neon);border-color:rgba(0,255,200,0.6);background:rgba(0,255,200,0.07);animation:pulseOk 2.2s ease-in-out infinite;}
.banner-bad{color:var(--alert);border-color:rgba(255,51,102,0.7);background:rgba(255,51,102,0.08);animation:pulseBad 1.1s ease-in-out infinite;}
.banner-warn{color:var(--warn);border-color:rgba(255,176,32,0.6);background:rgba(255,176,32,0.07);}
.banner-info{color:#6CC8FF;border-color:rgba(108,200,255,0.5);background:rgba(108,200,255,0.06);}
@keyframes pulseOk{0%,100%{box-shadow:0 0 6px rgba(0,255,200,0.25)}50%{box-shadow:0 0 26px rgba(0,255,200,0.6)}}
@keyframes pulseBad{0%,100%{box-shadow:0 0 6px rgba(255,51,102,0.3)}50%{box-shadow:0 0 28px rgba(255,51,102,0.75)}}
.hexview{font-family:var(--mono);font-size:0.82rem;line-height:1.55;white-space:pre;overflow-x:auto;padding:14px 16px;border-radius:12px;background:#05060A;border:1px solid rgba(0,255,200,0.35);box-shadow:0 0 18px rgba(0,255,200,0.15);}
.hx-off{color:#6CC8FF;}.hx-asc{color:var(--neon);}.hx-nul{color:#3C4656;}.hx-hi{color:var(--violet);}.hx-ctl{color:var(--warn);}.hx-txt{color:var(--warn);}
.df-ok{color:var(--neon);}.df-bad{color:#FFF;background:var(--alert);border-radius:3px;box-shadow:0 0 8px var(--alert);}
.hashbox{font-family:var(--mono);word-break:break-all;font-size:0.95rem;letter-spacing:0.5px;}
[data-testid="stMetric"]{background:var(--glass);border:1px solid rgba(0,255,200,0.25);border-radius:12px;padding:12px 14px;box-shadow:0 0 14px rgba(0,255,200,0.08);backdrop-filter:blur(8px);}
[data-testid="stMetricLabel"] p{color:var(--muted)!important;font-family:var(--mono);font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;}
[data-testid="stMetricValue"]{color:var(--neon)!important;font-family:var(--mono);text-shadow:0 0 10px rgba(0,255,200,0.4);}
button[data-baseweb="tab"]{font-family:var(--mono);color:var(--muted);background:transparent;}
button[data-baseweb="tab"][aria-selected="true"]{color:var(--neon);text-shadow:0 0 10px rgba(0,255,200,0.6);}
[data-baseweb="tab-highlight"]{background-color:var(--neon)!important;box-shadow:0 0 12px var(--neon);}
[data-baseweb="tab-border"]{background-color:rgba(0,255,200,0.15)!important;}
[data-testid="stCode"] pre,[data-testid="stCode"]{background:#05060A!important;border-radius:10px;}
[data-testid="stCode"] pre{border:1px solid rgba(0,255,200,0.4);box-shadow:0 0 14px rgba(0,255,200,0.18);}
[data-testid="stCode"] code{color:var(--neon)!important;font-family:var(--mono)!important;}
.stButton button,.stDownloadButton button{background:rgba(0,255,200,0.06);color:var(--neon);border:1px solid var(--neon);border-radius:10px;font-family:var(--mono);letter-spacing:1px;transition:all 0.2s;}
.stButton button:hover,.stDownloadButton button:hover{background:rgba(0,255,200,0.18);box-shadow:0 0 18px rgba(0,255,200,0.55);color:#FFFFFF;border-color:var(--neon);}
.stTextInput input,.stTextArea textarea,.stNumberInput input{background:#05060A!important;color:var(--neon)!important;font-family:var(--mono)!important;border:1px solid rgba(0,255,200,0.3)!important;border-radius:10px!important;}
.stTextInput input:focus,.stTextArea textarea:focus{box-shadow:0 0 14px rgba(0,255,200,0.4)!important;border-color:var(--neon)!important;}
[data-testid="stExpander"] details{background:var(--glass);border:1px solid rgba(0,255,200,0.22);border-radius:12px;}
[data-testid="stExpander"] summary{font-family:var(--mono);}
[data-testid="stFileUploaderDropzone"]{background:var(--glass);border:1px dashed rgba(0,255,200,0.55);border-radius:14px;}
[data-testid="stDataFrame"]{border:1px solid rgba(0,255,200,0.25);border-radius:10px;}
[data-testid="stAlert"]{border-radius:12px;backdrop-filter:blur(6px);}
::-webkit-scrollbar{width:9px;height:9px;}::-webkit-scrollbar-thumb{background:rgba(0,255,200,0.35);border-radius:8px;}::-webkit-scrollbar-track{background:#05060A;}
</style>"""

SCORING_RULES = [
    ("Double extension ending in an executable/script type", "double_extension_executable"),
    ("Double extension with other known extensions", "double_extension_other"),
    ("Potentially risky extension (.exe .scr .bat .cmd .ps1 .vbs .js .jar)", "risky_extension"),
    ("File type / extension mismatch", "type_mismatch"),
    ("Executable content behind a non-executable extension", "type_mismatch_executable_disguised"),
    ("Hidden file (leading dot)", "hidden_file"),
    ("Each file name anomaly (capped at +15 in total)", "filename_anomaly_each"),
    ("Control/formatting characters in file name", "control_characters"),
    ("URLs found (+10 if 10 or more unique)", "urls_found"),
    ("IPv4 addresses found (+10 if 5 or more unique)", "ips_found"),
    ("Supplied hash does not match calculated hash", "integrity_mismatch"),
    ("Archive contains executable/script entries", "archive_executables"),
    ("Archive entries with absolute/parent paths", "archive_path_traversal"),
    ("Embedded VBA macro project", "archive_macro_part"),
    ("Very high compression ratio", "archive_high_ratio"),
    ("Executable with very high byte entropy (possible packing/encryption)", "high_entropy_executable"),
]


# ---- small HTML helpers (every untrusted value goes through esc) ----------------------
def esc(value: Any) -> str:
    """HTML-escape untrusted text (and neutralise '$') before embedding it in custom markup."""
    return html.escape(safe_display(value), quote=True).replace("$", "&#36;")


def html_block(markup: str) -> None:
    """Render trusted/escaped HTML markup."""
    st.markdown(markup, unsafe_allow_html=True)


def card(label: str, value: Any, accent: str = "neon", sub: str = "") -> str:
    """Glowing glass card markup."""
    sub_html = f'<div class="card-sub">{esc(sub)}</div>' if sub else ""
    return (f'<div class="glass-card accent-{accent}"><div class="card-label">{esc(label)}</div>'
            f'<div class="card-value">{esc(value)}</div>{sub_html}</div>')


def badge(text: Any, kind: str = "ok") -> str:
    """Badge markup (kind: ok, warn, bad, url, muted)."""
    return f'<span class="badge badge-{kind}">{esc(text)}</span>'


def banner(kind: str, title: str, message: str = "") -> str:
    """Animated alert banner markup (kind: ok, bad, warn, info)."""
    msg = f'<div class="banner-msg">{esc(message)}</div>' if message else ""
    return f'<div class="banner banner-{kind}"><div class="banner-title">{esc(title)}</div>{msg}</div>'


def section_title(number: str, title: str) -> None:
    """Numbered section heading."""
    html_block(f'<div class="sec-title"><span class="sec-num">{esc(number)}</span>{esc(title)}</div>')


def show_table(rows: List[Dict[str, Any]]) -> None:
    """Render rows as plain text (never markdown, so untrusted content cannot become a link)."""
    st.dataframe(rows, hide_index=True)


def kv_rows(pairs: List[Tuple[str, Any]]) -> List[Dict[str, str]]:
    """Convert (property, value) pairs into table rows."""
    return [{"Property": k, "Value": safe_display(v)} for k, v in pairs]


def hash_diff_html(expected: str, calculated: str) -> Tuple[str, str, int]:
    """Highlight differing characters between two equal-length hex digests."""
    exp, calc = expected.lower(), calculated.lower()
    exp_parts: List[str] = []
    calc_parts: List[str] = []
    different = 0
    for index, calc_char in enumerate(calc):
        exp_char = exp[index] if index < len(exp) else ""
        same = exp_char == calc_char
        different += 0 if same else 1
        cls = "df-ok" if same else "df-bad"
        exp_parts.append(f'<span class="{cls}">{esc(exp_char)}</span>')
        calc_parts.append(f'<span class="{cls}">{esc(calc_char)}</span>')
    return "".join(exp_parts), "".join(calc_parts), different


# ---- charts ---------------------------------------------------------------------------
def style_figure(fig: Any, height: int = 320) -> Any:
    """Apply the dark forensic-lab look to a Plotly figure."""
    fig.update_layout(
        height=height, template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(5,6,10,0.65)",
        font=dict(family="JetBrains Mono, Consolas, monospace", color="#D6FFF6"), margin=dict(l=45, r=20, t=50, b=45),
    )
    fig.update_xaxes(gridcolor="rgba(0,255,200,0.08)")
    fig.update_yaxes(gridcolor="rgba(0,255,200,0.08)")
    return fig


def show_figure(fig: Any, key: str) -> None:
    """Display a Plotly figure using the theme defined by style_figure."""
    st.plotly_chart(fig, theme=None, key=key, config={"displayModeBar": False})


def plotly_missing_notice() -> None:
    """Explain how to enable interactive charts."""
    html_block(banner("warn", "Interactive charts unavailable", "Plotly is not installed. Run: pip install plotly (a simplified chart is shown instead)."))


def render_risk_gauge(risk: Dict[str, Any]) -> None:
    """Speedometer gauge for the 0-100 forensic risk score."""
    color = LEVEL_COLORS[risk["level"]]
    if not PLOTLY_OK:
        plotly_missing_notice()
        st.metric("Forensic Risk Score", f"{risk['score']} / 100")
        st.progress(risk["score"] / 100)
        return
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=risk["score"],
        number={"suffix": " / 100", "font": {"size": 42, "color": color}},
        title={"text": risk["level"].upper(), "font": {"size": 18, "color": color}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8A9BB0"}, "bar": {"color": color, "thickness": 0.28},
            "bgcolor": "rgba(0,0,0,0)", "borderwidth": 1, "bordercolor": "rgba(0,255,200,0.3)",
            "steps": [
                {"range": [0, 30], "color": "rgba(0,255,200,0.25)"},
                {"range": [30, 70], "color": "rgba(255,176,32,0.28)"},
                {"range": [70, 100], "color": "rgba(255,51,102,0.32)"},
            ],
            "threshold": {"line": {"color": "#FFFFFF", "width": 3}, "thickness": 0.8, "value": risk["score"]},
        },
    ))
    show_figure(style_figure(fig, 300), "risk_gauge")


def render_entropy_chart(entropy: Dict[str, Any]) -> None:
    """Bar chart of Shannon entropy per file block (high values suggest compression/encryption/packing)."""
    blocks = entropy["blocks"]
    if not blocks:
        st.info("No data to analyse (the file is empty).")
        return
    if not PLOTLY_OK:
        plotly_missing_notice()
        st.bar_chart([b["entropy"] for b in blocks])
        return
    values = [b["entropy"] for b in blocks]
    colors = ["#FF3366" if v >= HIGH_ENTROPY_THRESHOLD else "#FFB020" if v >= 6.0 else "#00FFC8" for v in values]
    fig = go.Figure(go.Bar(
        x=[b["start"] for b in blocks], y=values, marker_color=colors, width=[entropy["block_size"] * 0.9] * len(blocks),
        customdata=[[b["start"], b["end"]] for b in blocks],
        hovertemplate="Offset %{customdata[0]:,} - %{customdata[1]:,}<br>Entropy %{y:.3f} bits/byte<extra></extra>",
    ))
    fig.add_hline(y=HIGH_ENTROPY_THRESHOLD, line_dash="dash", line_color="#FF3366",
                  annotation_text="high-entropy threshold", annotation_font_color="#FF3366")
    fig.update_yaxes(range=[0, 8.2], title="bits per byte")
    fig.update_xaxes(title="file offset (bytes)")
    fig.update_layout(title="Byte entropy across the file")
    show_figure(style_figure(fig, 340), "entropy_chart")


def render_byte_distribution(entropy: Dict[str, Any]) -> None:
    """Histogram of byte values 0x00-0xFF, coloured by byte class."""
    counts = entropy["byte_counts"]
    if sum(counts) == 0:
        st.info("No data to analyse (the file is empty).")
        return
    if not PLOTLY_OK:
        plotly_missing_notice()
        st.bar_chart(counts)
        return
    log_scale = st.checkbox("Logarithmic scale", key="byte_dist_log")
    colors = ["#7F8FA6" if i == 0 else "#00FFC8" if 32 <= i < 127 else "#FFB020" if i < 32 or i == 127 else "#B36BFF" for i in range(256)]
    labels = [f"0x{i:02X} ({chr(i) if 32 <= i < 127 else 'non-printable'})" for i in range(256)]
    fig = go.Figure(go.Bar(x=list(range(256)), y=counts, marker_color=colors, customdata=labels,
                           hovertemplate="Byte %{customdata}<br>Count %{y:,}<extra></extra>"))
    fig.update_xaxes(title="byte value (0-255)", range=[-1, 256])
    fig.update_yaxes(title="occurrences", type="log" if log_scale else "linear")
    fig.update_layout(title="Byte value distribution")
    show_figure(style_figure(fig, 330), "byte_distribution")
    st.caption("Grey = null byte, cyan = printable ASCII, amber = control characters, violet = bytes above 0x7F.")


def render_severity_chart(findings: List[Dict[str, str]]) -> None:
    """Small bar chart of finding counts by severity."""
    order = ["Information", "Warning", "Critical / High Risk"]
    counts = [sum(1 for x in findings if x["level"] == level) for level in order]
    if not PLOTLY_OK:
        plotly_missing_notice()
        return
    fig = go.Figure(go.Bar(x=order, y=counts, marker_color=["#6CC8FF", "#FFB020", "#FF3366"], text=counts, textposition="outside"))
    fig.update_yaxes(title="findings", dtick=1)
    fig.update_layout(title="Findings by severity")
    show_figure(style_figure(fig, 280), "severity_chart")


# ---- hex viewer -----------------------------------------------------------------------
def hex_dump_html(data: bytes, start_offset: int = 0, width: int = 16) -> str:
    """Styled hex dump markup with offsets, coloured hex bytes and an ASCII column."""
    lines: List[str] = []
    for i in range(0, len(data), width):
        part = data[i:i + width]
        cells = []
        for byte in part:
            cls = "hx-nul" if byte == 0 else "hx-asc" if 32 <= byte < 127 else "hx-hi" if byte >= 128 else "hx-ctl"
            cells.append(f'<span class="{cls}">{byte:02X}</span>')
        padding = "   " * (width - len(part))
        ascii_text = esc("".join(chr(b) if 32 <= b < 127 else "." for b in part))
        lines.append(f'<span class="hx-off">{start_offset + i:08X}</span>  {" ".join(cells)}{padding}  <span class="hx-txt">|{ascii_text}|</span>')
    return '<div class="hexview">' + "<br>".join(lines) + "</div>"


def read_slice(uploaded: Any, offset: int, length: int) -> bytes:
    """Read a byte range from the in-memory upload (read-only)."""
    try:
        uploaded.seek(offset)
        return uploaded.read(length)
    finally:
        uploaded.seek(0)


# ---- UI sections ----------------------------------------------------------------------
def render_header() -> None:
    """Hero banner."""
    html_block(
        '<div class="hero"><div class="hero-title">' + esc(PROJECT_NAME) + '</div>'
        '<div class="hero-sub">Enterprise-style forensic workstation | static, read-only analysis of authorized evidence</div>'
        '<span class="chip">READ-ONLY</span><span class="chip">OFFLINE</span><span class="chip">NO EXECUTION</span>'
        '<span class="chip red">UNTRUSTED EVIDENCE MODE</span></div>'
    )


def get_case_details() -> Dict[str, str]:
    """Collect investigator/case fields from the sidebar."""
    keys = {"investigator": "case_investigator", "case_id": "case_id", "organization": "case_org", "notes": "case_notes"}
    return {name: str(st.session_state.get(key, "")).strip()[:500] for name, key in keys.items()}


def render_sidebar() -> None:
    """Sidebar: case details, project information, supported types, safety notice."""
    with st.sidebar:
        html_block('<div class="hero-title" style="font-size:1.15rem;letter-spacing:2px;">🔍 DFFA</div>'
                   '<div class="hero-sub">Digital Forensics File Analyzer</div>')
        st.markdown("### Case Details")
        st.text_input("Investigator name", key="case_investigator", placeholder="e.g. A. Sharma")
        st.text_input("Case ID", key="case_id", placeholder="e.g. CASE-2026-001")
        st.text_input("Organization / unit", key="case_org")
        st.text_area("Examiner notes", key="case_notes", height=80)
        st.caption("These details are printed in the exported reports.")
        st.markdown("### Project Information")
        st.write("An academic cybersecurity project that hashes evidence, reads metadata, flags suspicious "
                 "characteristics, visualises entropy and produces neutral forensic reports.")
        st.markdown("### Supported File Types")
        html_block("".join(badge(t.upper(), "ok") for t in UPLOAD_TYPES[:11]) +
                   "".join(badge(t.upper(), "muted") for t in UPLOAD_TYPES[11:]))
        st.caption("Muted types are extra formats for demonstrating the risky-extension detector.")
        st.markdown("### Safety Notice")
        html_block(banner("warn", "Authorized use only",
                          "Uploads are untrusted evidence: never executed, modified or sent to external services. "
                          "URLs/IPs found inside files are never contacted."))
        with st.expander("Library status"):
            for entry in (f"pypdf: {'ready' if PdfReader else 'missing'}", f"python-docx: {'ready' if DocxDocument else 'missing'}",
                          f"Pillow: {'ready' if Image else 'missing'}", f"ReportLab: {'ready' if REPORTLAB_OK else 'missing'}",
                          f"Plotly: {'ready' if PLOTLY_OK else 'missing'}"):
                st.write(entry)


def count_suspicious(findings: List[Dict[str, str]]) -> int:
    """Number of Warning / Critical findings."""
    return sum(1 for x in findings if x["level"] != "Information")


def render_overview_tab(analysis: Dict[str, Any]) -> None:
    """Tab 1: risk gauge, summary metrics, evidence cards and copyable hashes."""
    f, risk, integ, ind = analysis["file"], analysis["risk"], analysis["integrity"], analysis["indicators"]
    integrity_label = {"match": "Verified", "mismatch": "Mismatch", "invalid": "Invalid hash", "error": "Not comparable",
                       "not_provided": "Not checked"}[integ["status"]]
    left, right = st.columns([1.1, 1])
    with left:
        st.markdown("#### Forensic Risk Gauge")
        render_risk_gauge(risk)
    with right:
        st.markdown("#### Analysis Summary")
        m1, m2 = st.columns(2)
        m1.metric("Risk Score", f"{risk['score']} / 100")
        m2.metric("Risk Level", risk["level"])
        m3, m4 = st.columns(2)
        m3.metric("Integrity Status", integrity_label)
        m4.metric("Metadata Available", "Yes" if analysis["metadata"].get("available") else "No")
        m5, m6, m7 = st.columns(3)
        m5.metric("Suspicious Findings", count_suspicious(analysis["findings"]))
        m6.metric("URLs Found", ind["total_urls"] if ind["supported"] else "N/A")
        m7.metric("IP Addresses", ind["total_ips"] if ind["supported"] else "N/A")

    st.markdown("#### Evidence Details")
    c1, c2, c3 = st.columns(3)
    c1.markdown(card("File Name", f["name"]), unsafe_allow_html=True)
    c2.markdown(card("Extension", f["extension"], "violet"), unsafe_allow_html=True)
    c3.markdown(card("File Size", f["size_human"]), unsafe_allow_html=True)
    c4, c5, c6 = st.columns(3)
    c4.markdown(card("Detected Type", f["file_type"]), unsafe_allow_html=True)
    c5.markdown(card("MIME (by extension)", f["mime_by_extension"], "violet"), unsafe_allow_html=True)
    c6.markdown(card("MIME (by content)", f["mime_detected"], "violet"), unsafe_allow_html=True)
    c7, c8, c9 = st.columns(3)
    c7.markdown(card("Created", f["created"], "amber"), unsafe_allow_html=True)
    c8.markdown(card("Modified", f["modified"], "amber"), unsafe_allow_html=True)
    c9.markdown(card("Last Accessed", f["accessed"], "amber"), unsafe_allow_html=True)
    html_block(card("Temporary File Path (deleted after analysis)", f["path"]))
    st.caption(f["timestamp_note"])

    st.markdown("#### Cryptographic Hashes")
    h1, h2 = st.columns(2)
    with h1:
        html_block('<div class="card-label">MD5 (128-bit)</div>')
        st.code(analysis["hashes"].get("md5") or "Unavailable", language=None)
    with h2:
        html_block('<div class="card-label">SHA-256 (256-bit)</div>')
        st.code(analysis["hashes"].get("sha256") or "Unavailable", language=None)
    html_block(banner(
        "info", "Why hashes matter",
        f"A cryptographic hash is a digital fingerprint: changing even one bit changes the hash completely. Recording it at "
        f"acquisition lets an examiner later prove the evidence is unchanged. Hashes were streamed in {CHUNK_SIZE}-byte chunks. "
        "MD5 is shown for compatibility; SHA-256 is preferred because MD5 is vulnerable to deliberate collisions.",
    ))

    st.markdown("#### Risk Factors")
    if risk["reasons"]:
        show_table([{"Contributing factor": reason, "Points": f"+{points}"} for reason, points in risk["reasons"]])
    else:
        html_block(banner("ok", "No contributing factors", "No risk indicators were detected by the checks in this tool."))
    st.caption("A high score means more review-worthy indicators were found; it does not prove the file is malicious.")
    with st.expander("How the score is calculated (scoring methodology)"):
        show_table([{"Factor": label, "Points": RISK_POINTS[key]} for label, key in SCORING_RULES])
        st.write("The total is capped at 100. **0-29 Low Risk**, **30-69 Medium Risk**, **70-100 High Risk**. "
                 "Points come only from findings detected in this file; nothing is estimated or assumed.")


def render_integrity_tab(analysis: Dict[str, Any]) -> None:
    """Tab 2: expected-vs-calculated hash comparison with animated banners."""
    integ = analysis["integrity"]
    st.markdown("#### Integrity Verification")
    st.text_input("Expected / original hash (MD5 or SHA-256)", key="expected_hash",
                  placeholder="Paste the hash recorded when the evidence was first acquired")
    status = integ["status"]
    if status == "match":
        html_block(banner("ok", "Integrity Verified", "File has not changed according to the supplied hash."))
    elif status == "mismatch":
        html_block(banner("bad", "Integrity Warning", "The calculated hash does not match the supplied hash."))
    elif status in ("invalid", "error"):
        html_block(banner("bad", "Invalid input", integ["message"]))
    else:
        html_block(banner("info", "Awaiting expected hash", "Paste the original MD5 or SHA-256 value above to compare it with the calculated hash."))

    if status in ("match", "mismatch"):
        expected_html, calc_html, different = hash_diff_html(integ["expected"], integ["calculated"])
        col_a, col_b = st.columns(2)
        col_a.markdown(f'<div class="glass-card"><div class="card-label">Expected ({esc(integ["algorithm"])})</div>'
                       f'<div class="card-value hashbox">{expected_html}</div></div>', unsafe_allow_html=True)
        col_b.markdown(f'<div class="glass-card {"" if status == "match" else "accent-red"}"><div class="card-label">Calculated ({esc(integ["algorithm"])})</div>'
                       f'<div class="card-value hashbox">{calc_html}</div></div>', unsafe_allow_html=True)
        total = len(integ["calculated"])
        st.caption(f"Compared case-insensitively using {integ['algorithm']}: {total - different} of {total} characters match.")
        if status == "mismatch":
            st.info("A mismatch only shows that the file differs from the supplied hash. It does not prove malicious activity - "
                    "the wrong hash, or a different version of the file, may have been supplied.")
    st.markdown("#### Reference Values")
    r1, r2 = st.columns(2)
    r1.markdown(card("Calculated MD5", analysis["hashes"].get("md5") or "Unavailable"), unsafe_allow_html=True)
    r2.markdown(card("Calculated SHA-256", analysis["hashes"].get("sha256") or "Unavailable"), unsafe_allow_html=True)


def render_metadata_tab(meta: Dict[str, Any]) -> None:
    """Tab 3: structured metadata as tables or a JSON tree."""
    st.markdown("#### Metadata & EXIF Tree")
    if meta.get("error"):
        html_block(banner("bad", "Metadata error", meta["error"]))
    if meta.get("available"):
        html_block(banner("ok", "Readable metadata found", f"Source: {meta.get('type', 'file')}"))
    else:
        html_block(banner("info", "No readable metadata found.", "No metadata was invented; only fields present in the file are shown."))
    sections = meta.get("sections", {})
    if sections:
        view = st.radio("View", ["Table view", "JSON tree"], horizontal=True, key="meta_view")
        if view == "JSON tree":
            st.json({name: {k: safe_display(v) for k, v in fields.items()} for name, fields in sections.items()}, expanded=2)
        else:
            for name, fields in sections.items():
                with st.expander(name, expanded=name not in TECHNICAL_SECTIONS):
                    show_table(kv_rows(list(fields.items())))
    for note in meta.get("notes", []):
        st.caption("Note: " + note)


def collect_flag_badges(analysis: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Build (text, kind) badges summarising file-level indicators."""
    sec, integ = analysis["security"], analysis["integrity"]
    fn, mm, arc = sec["filename"], sec["mismatch"], sec["archive"]
    flags: List[Tuple[str, str]] = []
    if fn["double_extension"]:
        flags.append(("DOUBLE EXTENSION", "bad" if fn["double_extension_executable"] else "warn"))
    if fn["risky_extension"]:
        flags.append((f"RISKY FILE TYPE {fn['extension'].upper()}", "warn"))
    if mm["status"] == "mismatch":
        flags.append(("EXECUTABLE DISGUISED", "bad") if mm["executable_disguised"] else ("TYPE MISMATCH", "warn"))
    if sec["hidden"]["status"] == "Yes":
        flags.append(("HIDDEN FILE", "warn"))
    if fn["control_characters"]:
        flags.append(("CONTROL CHARACTERS IN NAME", "bad"))
    for anomaly in fn["anomalies"]:
        if not anomaly["title"].startswith("Hidden control"):
            flags.append((anomaly["title"].upper()[:60], "warn"))
    if integ["status"] == "mismatch":
        flags.append(("HASH MISMATCH", "bad"))
    if arc.get("analyzed"):
        if arc["executables"]:
            flags.append(("ARCHIVE HAS EXECUTABLES", "warn"))
        if arc["path_traversal"]:
            flags.append(("ARCHIVE PATH TRAVERSAL", "warn"))
        if arc["macro_parts"]:
            flags.append(("VBA MACRO PROJECT", "warn"))
    if analysis["entropy"].get("high_entropy") and analysis["signature"]["kind"] in EXECUTABLE_KINDS:
        flags.append(("HIGH-ENTROPY EXECUTABLE", "warn"))
    if not flags:
        flags.append(("NO FILE-LEVEL INDICATORS", "ok"))
    if mm["status"] == "match":
        flags.append(("TYPE MATCHES CONTENT", "ok"))
    elif mm["status"] == "inconclusive":
        flags.append(("TYPE CHECK INCONCLUSIVE", "muted"))
    if integ["status"] == "match":
        flags.append(("HASH VERIFIED", "ok"))
    return flags


def render_threat_tab(analysis: Dict[str, Any]) -> None:
    """Tab 4: indicator badges, URL/IP IOCs with filters, and categorised findings."""
    ind, findings = analysis["indicators"], analysis["findings"]
    st.markdown("#### File-Level Indicators")
    html_block("".join(badge(text, kind) for text, kind in collect_flag_badges(analysis)))
    html_block(card("Hidden file status", analysis["security"]["hidden"]["status"], "violet",
                    analysis["security"]["hidden"]["explanation"]))
    arc = analysis["security"]["archive"]
    if arc.get("analyzed") or arc.get("error"):
        with st.expander("Archive / container inspection (central directory only - nothing is extracted)"):
            if arc.get("error"):
                st.warning(arc["error"])
            else:
                a1, a2, a3, a4 = st.columns(4)
                a1.metric("Entries", arc["entries"])
                a2.metric("Executable-type", len(arc["executables"]))
                a3.metric("Encrypted", arc["encrypted"])
                a4.metric("Compression ratio", f"{arc['ratio']}x")
                if arc["listing"]:
                    show_table(arc["listing"])

    st.markdown("#### Indicators of Compromise (IOCs)")
    if not ind["supported"]:
        html_block(banner("info", "Not applicable", ind["note"]))
    else:
        i1, i2 = st.columns(2)
        i1.metric("URLs found (total)", ind["total_urls"])
        i2.metric("IPv4 addresses found (total)", ind["total_ips"])
        f1, f2 = st.columns([2, 1])
        query = f1.text_input("Filter indicators", key="ioc_filter", placeholder="Type part of a URL or IP address").strip().lower()
        types = sorted({i["type"] for i in ind["ips"]})
        chosen = f2.multiselect("IP category", types, default=types, key="ioc_types")
        urls = [u for u in ind["urls"] if query in u["url"].lower()]
        ips = [i for i in ind["ips"] if i["type"] in chosen and query in i["ip"]]
        st.markdown("**URLs** (plain text badges - never clickable, never visited)")
        if urls:
            html_block("".join(badge(f"{u['url']}  x{u['count']}", "url") for u in urls[:200]))
            if len(urls) > 200:
                st.caption(f"Showing the first 200 of {len(urls)} URLs; the CSV export contains all of them.")
        else:
            st.caption("No matching URLs.")
        st.markdown("**IPv4 addresses**")
        kind_map = {"Public": "warn", "Private": "ok", "Loopback": "muted", "Link-local": "muted"}
        if ips:
            html_block("".join(badge(f"{i['ip']}  [{i['type']}]  x{i['count']}", kind_map.get(i["type"], "muted")) for i in ips[:200]))
            show_table([{"IP Address": i["ip"], "Occurrences": i["count"], "Type": i["type"]} for i in ips])
        else:
            st.caption("No matching IPv4 addresses.")
        st.caption(ind["note"])
        st.download_button("Download IOC list (CSV)", data=build_ioc_csv(analysis), file_name="ioc_list.csv", mime="text/csv", key="dl_ioc")

    st.markdown("#### Forensic Findings")
    left, right = st.columns([1, 1.4])
    with left:
        render_severity_chart(findings)
    with right:
        levels = ["Critical / High Risk", "Warning", "Information"]
        selected = st.multiselect("Show severities", levels, default=levels, key="finding_levels")
        kinds = {"Critical / High Risk": "bad", "Warning": "warn", "Information": "info"}
        for level in levels:
            for item in [x for x in findings if x["level"] == level and level in selected]:
                html_block(banner(kinds[level], f"{level}: {item['title']}", f"Explanation: {item['explanation']}"))


def render_binary_tab(analysis: Dict[str, Any], uploaded: Any) -> None:
    """Tab 5: live hex viewer, byte distribution and entropy visualiser."""
    ent, sig, size = analysis["entropy"], analysis["signature"], analysis["file"]["size_bytes"]
    st.markdown("#### Binary Overview")
    b1, b2, b3, b4 = st.columns(4)
    b1.markdown(card("Overall Entropy", f"{ent['overall']:.3f} bits/byte", "amber", describe_entropy(ent["overall"]) if ent["scanned"] else ""), unsafe_allow_html=True)
    b2.markdown(card("Bytes Analysed", f"{ent['scanned']:,}", "violet", "first 32 MB only" if ent["truncated"] else "entire file"), unsafe_allow_html=True)
    b3.markdown(card("High-Entropy Blocks", ent["high_blocks"], "red" if ent["high_blocks"] else "neon", f"threshold {HIGH_ENTROPY_THRESHOLD} bits/byte"), unsafe_allow_html=True)
    b4.markdown(card("Signature", sig["description"]), unsafe_allow_html=True)

    st.markdown("#### Live Hex Viewer")
    if size == 0:
        st.info("The file is empty, so there is nothing to display.")
    else:
        c1, c2 = st.columns([2, 1])
        offset = int(c1.number_input("Start offset (bytes)", min_value=0, max_value=max(size - 1, 0), value=0, step=16, key="hex_offset"))
        length = int(c2.select_slider("Bytes to display", options=[128, 256, 512, 1024], value=256, key="hex_len"))
        try:
            data = read_slice(uploaded, offset, length)
            html_block(hex_dump_html(data, offset))
            st.caption(f"Showing {len(data)} byte(s) from offset 0x{offset:08X}. "
                       "Colours: cyan = printable, grey = 0x00, amber = control, violet = above 0x7F.")
        except Exception:
            st.error("The bytes could not be displayed for this file.")
    st.markdown("#### Byte Distribution")
    render_byte_distribution(ent)
    st.markdown("#### Entropy & Anomaly Visualizer")
    render_entropy_chart(ent)
    if ent["truncated"]:
        st.caption("Only the first 32 MB were analysed to keep the application responsive.")
    with st.expander("How to read entropy"):
        st.write(
            "Shannon entropy measures randomness from 0 to 8 bits per byte. Plain text is usually moderate (about 4-5), "
            "while compressed or encrypted data approaches 8. Executables with sustained very high entropy may be packed or "
            "encrypted, but legitimate compressed formats (ZIP, PNG, JPEG, DOCX) are naturally high, so entropy is an "
            "indicator for review, never proof of malware."
        )


def render_report_tab(analysis: Dict[str, Any], report_key: str) -> None:
    """Tab 6: executive report export (PDF, Markdown evidence file, plain text)."""
    st.markdown("#### Executive Report Export")
    case = analysis.get("case") or {}
    cc1, cc2, cc3 = st.columns(3)
    cc1.markdown(card("Investigator", case.get("investigator") or "Not provided", "violet"), unsafe_allow_html=True)
    cc2.markdown(card("Case ID", case.get("case_id") or "Not provided", "violet"), unsafe_allow_html=True)
    cc3.markdown(card("Risk", f"{analysis['risk']['score']} / 100 - {analysis['risk']['level']}", "amber"), unsafe_allow_html=True)
    st.write("Generate a neutral evidence package: executive summary, case details, hashes, integrity result, metadata, "
             "security analysis, IOC summary, entropy and a hex excerpt, risk assessment and final assessment.")
    if st.button("Generate Forensic Report", key="gen_report"):
        try:
            with st.spinner("Building evidence package..."):
                st.session_state["bundle"] = {"key": report_key, "items": generate_all_reports(analysis)}
        except Exception as exc:
            st.error(f"The report could not be generated ({type(exc).__name__}). Please try again.")
    bundle = st.session_state.get("bundle")
    if bundle and bundle["key"] == report_key:
        html_block(banner("ok", "Evidence package ready", "Download the formats you need. SHA-256 values below let you verify the exported files later."))
        for item in bundle["items"]:
            col_a, col_b = st.columns([1, 2.2])
            with col_a:
                st.download_button(f"Download {item['label']}", data=item["data"], file_name=item["file_name"],
                                   mime=item["mime"], key="dl_" + item["file_name"])
            with col_b:
                html_block(card(item["file_name"], f"SHA-256 {item['sha256']}", "violet", item["note"]))
        markdown_item = next((i for i in bundle["items"] if i["mime"] == "text/markdown"), None)
        if markdown_item:
            with st.expander("Preview Markdown evidence file"):
                st.code(markdown_item["data"].decode("utf-8", errors="replace"), language="markdown")
    elif bundle:
        st.info("The analysis inputs changed since the last package was generated. Click the button again to refresh it.")


def main() -> None:
    """Streamlit entry point."""
    st.set_page_config(page_title=PROJECT_NAME, page_icon="🔍", layout="wide")
    html_block(CUSTOM_CSS)
    render_sidebar()
    render_header()

    section_title("01", "Upload Evidence File")
    uploaded = st.file_uploader(
        "Select an evidence file to analyze", type=UPLOAD_TYPES,
        help="The file is analysed in a temporary copy; the original is never modified.",
    )
    if uploaded is None:
        html_block(banner("info", "Awaiting evidence", "Upload a file to begin the forensic analysis."))
        return

    file_key = f"{uploaded.name}|{uploaded.size}|{getattr(uploaded, 'file_id', '')}"
    if st.session_state.get("file_key") != file_key:
        try:
            with st.spinner("Analyzing evidence file..."):
                base = analyze_uploaded_file(uploaded)
        except Exception as exc:
            st.error(f"The file could not be analysed ({type(exc).__name__}). It may be unreadable or inaccessible.")
            return
        st.session_state["file_key"] = file_key
        st.session_state["base"] = base
        st.session_state["expected_hash"] = ""
        st.session_state.pop("bundle", None)
    base = st.session_state["base"]

    for message in base["errors"]:
        html_block(banner("warn", "Analysis notice", message))
    if base["file"]["size_bytes"] == 0:
        html_block(banner("warn", "Empty file", "The uploaded file is empty (0 bytes). Hashes are valid, but little else can be analysed."))
    html_block(banner("ok", "Evidence received", f"{base['file']['display_name']} - {base['file']['size_human']}"))

    expected = str(st.session_state.get("expected_hash", ""))
    case = get_case_details()
    analysis = build_analysis(base, expected, case)
    report_key = f"{file_key}|{expected.strip().lower()}|{json.dumps(case, sort_keys=True)}"

    tabs = st.tabs(["🔍 Overview & Hashes", "🛡️ Integrity", "📋 Metadata & EXIF", "⚠️ Threat Indicators & IOCs",
                    "💽 Hex / Binary", "📄 Executive Report"])
    with tabs[0]:
        render_overview_tab(analysis)
    with tabs[1]:
        render_integrity_tab(analysis)
    with tabs[2]:
        render_metadata_tab(analysis["metadata"])
    with tabs[3]:
        render_threat_tab(analysis)
    with tabs[4]:
        render_binary_tab(analysis, uploaded)
    with tabs[5]:
        render_report_tab(analysis, report_key)


if __name__ == "__main__":
    main()
