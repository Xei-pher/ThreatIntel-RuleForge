from pathlib import Path
import fitz


def extract_text_from_pdf(path: str) -> str:
    pdf_path = Path(path)
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {path}")

    text_parts = []
    with fitz.open(str(pdf_path)) as doc:
        for page_number, page in enumerate(doc, start=1):
            text = page.get_text("text") or ""
            text_parts.append(f"\n\n--- PAGE {page_number} ---\n{text.strip()}")

    text = "\n".join(text_parts).strip()
    if len(text) < 50:
        return "[OCR_REQUIRED] This PDF appears to be scanned or image-based. Add OCR in the next phase."
    return text
