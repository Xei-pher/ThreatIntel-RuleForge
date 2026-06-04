import logging

from .base import AgentContext, AgentResult, BaseAgent

logger = logging.getLogger("ruleforge.agents.pdf_reader")


class PDFReaderAgent(BaseAgent):
    """Extracts raw text from a PDF file using PyMuPDF.

    This agent never uses an LLM and is never re-run on redo iterations — its
    output is immutable once extracted.
    """

    name = "PDFReaderAgent"

    def run(self, context: AgentContext) -> AgentResult:
        from ..services.pdf_service import extract_text_from_pdf

        logger.info("PDFReaderAgent starting pdf_path=%s", context.pdf_path)
        try:
            text = extract_text_from_pdf(context.pdf_path)
        except Exception as exc:
            logger.exception("PDFReaderAgent extraction failed: %s", exc)
            context.raw_text = ""
            return AgentResult(
                agent_name=self.name,
                success=False,
                output=None,
                notes=f"extraction_failed: {exc}",
            )

        context.raw_text = text
        ocr_required = text.startswith("[OCR_REQUIRED]")
        notes = "ocr_required" if ocr_required else ""
        logger.info(
            "PDFReaderAgent complete text_chars=%s ocr_required=%s",
            len(text),
            ocr_required,
        )
        return AgentResult(
            agent_name=self.name,
            success=True,
            output=text,
            notes=notes,
        )
