"""Renderers: canonical findings to a human-readable document."""

from .html import render_fragment, render_html
from .pdf import PDFDocument
from .report import render_pdf

__all__ = ["render_html", "render_fragment", "render_pdf", "PDFDocument"]
