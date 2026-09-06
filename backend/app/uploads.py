import os
from pathlib import Path
from typing import BinaryIO

DEFAULT_MAX_UPLOAD_MB = 25
UPLOAD_CHUNK_SIZE = 1024 * 1024


def max_upload_bytes() -> int:
    raw_value = os.getenv("MAX_UPLOAD_MB", str(DEFAULT_MAX_UPLOAD_MB))
    try:
        megabytes = max(1, int(raw_value))
    except ValueError:
        megabytes = DEFAULT_MAX_UPLOAD_MB
    return megabytes * 1024 * 1024


def sanitize_upload_filename(filename: str | None) -> str:
    """Return a basename-only PDF filename safe for local storage."""
    normalized = (filename or "").replace("\\", "/")
    basename = Path(normalized).name.strip()
    if not basename:
        basename = "report.pdf"
    if not basename.lower().endswith(".pdf"):
        raise ValueError("Only PDF files are supported.")
    return basename


def unique_target(storage_dir: Path, filename: str) -> Path:
    target = storage_dir / filename
    counter = 1
    while target.exists():
        target = storage_dir / f"{target.stem}_{counter}{target.suffix}"
        counter += 1
    return target


def save_limited_upload(source: BinaryIO, target: Path, limit_bytes: int | None = None) -> int:
    limit = limit_bytes or max_upload_bytes()
    written = 0
    try:
        with target.open("wb") as destination:
            while chunk := source.read(UPLOAD_CHUNK_SIZE):
                written += len(chunk)
                if written > limit:
                    raise ValueError(f"PDF exceeds the configured upload limit of {limit // (1024 * 1024)} MB.")
                destination.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return written
