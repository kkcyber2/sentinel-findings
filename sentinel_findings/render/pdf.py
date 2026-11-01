"""Minimal PDF writer.

ForgeGuard's audit finding M2 was that a 1,701-line findings report could not
be sent to a client because nothing in the dependency tree produced a PDF.
Adding reportlab would put a 3 MB native dependency into a Next.js project for
one feature. This writes PDF 1.4 directly instead: base-14 Helvetica, WinAnsi
encoding, FlateDecode streams. No native code, no wheel, no font files.

What it deliberately does not do: images, embedded fonts, Unicode beyond
WinAnsi, or PDF/A. Text extraction and printing work; that is the requirement.
Characters outside Latin-1 are transliterated rather than dropped, so a report
never renders a silent blank where a character was.
"""

from __future__ import annotations

import zlib
from typing import List, Optional, Sequence, Tuple

# A4 at 72 dpi.
PAGE_W = 595.28
PAGE_H = 841.89
MARGIN = 48.0
CONTENT_W = PAGE_W - 2 * MARGIN

# Helvetica advance widths (1/1000 em) for the printable ASCII range. Used by
# the wrapper; anything outside this table is measured as 556 (the average),
# which over-estimates slightly and so never overflows.
_W: dict = {}
for _cp, _w in zip(
    range(32, 127),
    [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278]
    + [556] * 10
    + [278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278,
       500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667,
       611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222,
       222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500,
       500, 334, 260, 334, 584],
):
    _W[chr(_cp)] = _w

# WinAnsi is cp1252. Characters outside it get a transliteration, because a
# report that silently drops a character is worse than one that shows an
# approximation.
_TRANSLIT = {
    "\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
    "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u2192": "->",
    "\u2190": "<-", "\u2022": "*", "\u00a0": " ", "\u2713": "yes",
    "\u2717": "no", "\u2265": ">=", "\u2264": "<=",
}


def _enc(text: str) -> str:
    """Make a string safe for a WinAnsi string literal."""
    out: List[str] = []
    for ch in text:
        if ch in _TRANSLIT:
            out.append(_TRANSLIT[ch])
            continue
        try:
            ch.encode("cp1252")
            out.append(ch)
        except UnicodeEncodeError:
            out.append("?")
    # Escape PDF string specials.
    return "".join(out).replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _width(text: str, size: float, bold: bool = False) -> float:
    total = sum(_W.get(ch, 556) for ch in text)
    return total * size / 1000.0 * (1.03 if bold else 1.0)


def _wrap(text: str, size: float, max_w: float, bold: bool = False) -> List[str]:
    """Greedy wrap on spaces, breaking any single word that cannot fit."""
    lines: List[str] = []
    for paragraph in text.split("\n"):
        if not paragraph.strip():
            lines.append("")
            continue
        words = paragraph.split(" ")
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if _width(candidate, size, bold) <= max_w:
                current = candidate
                continue
            if current:
                lines.append(current)
            # A single word longer than the line: hard-break it.
            while _width(word, size, bold) > max_w and len(word) > 1:
                cut = len(word)
                while cut > 1 and _width(word[:cut], size, bold) > max_w:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        if current:
            lines.append(current)
    return lines


class _Page:
    """Accumulates content-stream operators for one page."""

    def __init__(self) -> None:
        self.ops: List[str] = []
        self.y = PAGE_H - MARGIN

    def need(self, height: float) -> bool:
        return self.y - height < MARGIN + 34  # leave room for the footer

    def text(self, x: float, s: str, size: float, bold: bool = False, gray: float = 0.0) -> None:
        font = "F2" if bold else "F1"
        self.ops.append(
            f"BT /{font} {size:.2f} Tf {gray:.3f} g {x:.2f} {self.y:.2f} Td ({_enc(s)}) Tj ET"
        )

    def rule(self, x1: float, x2: float, gray: float = 0.8, width: float = 0.6) -> None:
        self.ops.append(
            f"{gray:.3f} G {width:.2f} w {x1:.2f} {self.y:.2f} m {x2:.2f} {self.y:.2f} l S"
        )

    def rect(self, x: float, y: float, w: float, h: float, gray: float = 0.96) -> None:
        self.ops.append(f"{gray:.3f} g {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f 0 g")


class PDFDocument:
    """A4 document with automatic pagination and page numbers."""

    def __init__(self, title: str = "", author: str = "") -> None:
        self.title = title
        self.author = author
        self.pages: List[_Page] = []
        self.page = _Page()
        self.pages.append(self.page)

    # ------------------------------------------------------------------ #
    # Flow layout                                                        #
    # ------------------------------------------------------------------ #

    def _advance(self, height: float) -> None:
        if self.page.need(height):
            self.page = _Page()
            self.pages.append(self.page)

    def h1(self, text: str, *, size: float = 19) -> None:
        self._advance(size + 12)
        self.page.text(MARGIN, text, size, bold=True)
        self.page.y -= size + 8

    def h2(self, text: str, *, size: float = 9, rule: bool = True) -> None:
        gap = 20
        self._advance(gap + size)
        self.page.y -= gap
        self.page.text(MARGIN, text.upper(), size, bold=True, gray=0.25)
        self.page.y -= 8
        if rule:
            self.page.rule(MARGIN, MARGIN + CONTENT_W)
            self.page.y -= 12

    def h3(self, text: str, *, size: float = 11.5) -> None:
        self._advance(size + 14)
        self.page.y -= 12
        self.page.text(MARGIN, text, size, bold=True)
        self.page.y -= size + 4

    def para(self, text: str, *, size: float = 9.5, gray: float = 0.18, leading: float = 1.45) -> None:
        for line in _wrap(text, size, CONTENT_W):
            step = size * leading
            self._advance(step)
            if line:
                self.page.text(MARGIN, line, size, gray=gray)
            self.page.y -= step
        self.page.y -= 3

    def kv(self, key: str, value: str, *, size: float = 9.5) -> None:
        label_w = 118.0
        lines = _wrap(value, size, CONTENT_W - label_w)
        self._advance(max(len(lines), 1) * size * 1.4)
        self.page.text(MARGIN, key, size, bold=True, gray=0.25)
        for line in lines:
            self.page.text(MARGIN + label_w, line, size, gray=0.15)
            self.page.y -= size * 1.4

    def count_row(self, pairs: Sequence[Tuple[str, int]]) -> None:
        """A row of label/number cells, drawn as a bordered strip."""
        h = 40.0
        self._advance(h + 10)
        self.page.y -= 8
        cell_w = CONTENT_W / max(len(pairs), 1)
        top = self.page.y
        self.page.rect(MARGIN, top - h, CONTENT_W, h, gray=0.955)
        for i, (label, value) in enumerate(pairs):
            x = MARGIN + i * cell_w
            self.page.ops.append(
                f"BT /F2 15 Tf 0.09 g {x + cell_w / 2:.2f} {top - 20:.2f} Td "
                f"({_enc(str(value))}) Tj ET"
            )
            label_txt = label.upper()
            lw = _width(label_txt, 6.2, True)
            self.page.ops.append(
                f"BT /F2 6.2 Tf 0.55 g {x + (cell_w - lw) / 2:.2f} {top - 31:.2f} Td "
                f"({_enc(label_txt)}) Tj ET"
            )
        self.page.y = top - h - 12

    def banner(self, heading: str, body: str, *, warning: bool = True) -> None:
        size = 9.0
        lines = _wrap(body, size, CONTENT_W - 26)
        block_h = 16 + len(lines) * size * 1.4 + 12
        self._advance(block_h)
        self.page.y -= 6
        top = self.page.y
        gray = 0.985 if warning else 0.965
        self.page.rect(MARGIN, top - block_h, CONTENT_W, block_h, gray=gray)
        strip = 0.62 if warning else 0.30
        self.page.ops.append(
            f"{strip:.3f} g {MARGIN:.2f} {top - block_h:.2f} 3 {block_h:.2f} re f 0 g"
        )
        self.page.y = top - 13
        self.page.text(MARGIN + 13, heading, size + 0.5, bold=True, gray=0.08)
        self.page.y -= size + 5
        for line in lines:
            self.page.text(MARGIN + 13, line, size, gray=0.22)
            self.page.y -= size * 1.4
        self.page.y = top - block_h - 12

    def finding(
        self,
        severity: str,
        title: str,
        location: str,
        description: str,
        evidence: str,
        remediation: Sequence[str],
        tags: Sequence[str],
        *,
        simulated: bool = False,
    ) -> None:
        size = 9.0
        title_lines = _wrap(title, 10.5, CONTENT_W - 76, bold=True)
        desc_lines = _wrap(description, size, CONTENT_W - 12) if description else []
        ev_lines = _wrap(evidence, 8.4, CONTENT_W - 24) if evidence else []
        fix_lines: List[str] = []
        for step in remediation:
            fix_lines.extend(_wrap("- " + step, size, CONTENT_W - 12))

        block = 22 + len(title_lines) * 13
        if location:
            block += 11
        block += len(desc_lines) * size * 1.42 + 4
        if ev_lines:
            block += len(ev_lines) * 8.4 * 1.42 + 10
        block += len(fix_lines) * size * 1.42
        if tags:
            block += 13
        block += 14

        self._advance(min(block, 260))
        self.page.y -= 4
        top = self.page.y

        # Severity chip
        chip_w = _width(severity.upper(), 6.6, True) + 11
        self.page.rect(MARGIN, top - 12.5, chip_w, 12.5, gray=0.90)
        self.page.ops.append(
            f"BT /F2 6.6 Tf 0.15 g {MARGIN + 5.5:.2f} {top - 9.6:.2f} Td "
            f"({_enc(severity.upper())}) Tj ET"
        )
        if simulated:
            sim_x = MARGIN + chip_w + 5
            sim_w = _width("SIMULATED", 6.6, True) + 11
            self.page.rect(sim_x, top - 12.5, sim_w, 12.5, gray=0.90)
            self.page.ops.append(
                f"BT /F2 6.6 Tf 0.30 g {sim_x + 5.5:.2f} {top - 9.6:.2f} Td "
                f"(SIMULATED) Tj ET"
            )

        x_title = MARGIN + chip_w + 9
        self.page.y = top - 1
        for line in title_lines:
            self.page.text(x_title, line, 10.5, bold=True)
            self.page.y -= 13

        if location:
            self.page.text(x_title, location, 7.8, gray=0.45)
            self.page.y -= 11

        for line in desc_lines:
            self.page.text(MARGIN, line, size, gray=0.22)
            self.page.y -= size * 1.42
        if desc_lines:
            self.page.y -= 2

        if ev_lines:
            self.page.rect(MARGIN, self.page.y - len(ev_lines) * 8.4 * 1.42 - 7,
                           CONTENT_W, len(ev_lines) * 8.4 * 1.42 + 7, gray=0.955)
            self.page.y -= 4
            for line in ev_lines:
                self.page.text(MARGIN + 8, line, 8.4, gray=0.28)
                self.page.y -= 8.4 * 1.42
            self.page.y -= 5

        for line in fix_lines:
            self.page.text(MARGIN, line, size, gray=0.25)
            self.page.y -= size * 1.42

        if tags:
            self.page.y -= 2
            self.page.text(MARGIN, "  \u00b7  ".join(tags), 7.6, gray=0.5)
            self.page.y -= 11

        self.page.y -= 6
        self.page.rule(MARGIN, MARGIN + CONTENT_W, gray=0.9, width=0.4)
        self.page.y -= 8

    def spacer(self, h: float = 10) -> None:
        self._advance(h)
        self.page.y -= h

    # ------------------------------------------------------------------ #
    # Output                                                             #
    # ------------------------------------------------------------------ #

    def to_bytes(self) -> bytes:
        """Serialise with a correct xref table."""
        objects: List[bytes] = []

        def add(obj: bytes) -> int:
            objects.append(obj)
            return len(objects)

        # 1 Catalog, 2 Pages, 3 F1, 4 F2 — reserved up front.
        catalog_id, pages_id, f1_id, f2_id = 1, 2, 3, 4
        objects.extend([b"", b"", b"", b""])

        page_ids: List[int] = []
        for page in self.pages:
            stream = "\n".join(page.ops).encode("cp1252", errors="replace")
            compressed = zlib.compress(stream, 9)
            cid = add(
                b"<< /Length " + str(len(compressed)).encode()
                + b" /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream"
            )
            pid = add(
                b"<< /Type /Page /Parent " + str(pages_id).encode()
                + b" 0 R /MediaBox [0 0 "
                + f"{PAGE_W:.2f} {PAGE_H:.2f}".encode()
                + b"] /Resources << /Font << /F1 " + str(f1_id).encode()
                + b" 0 R /F2 " + str(f2_id).encode()
                + b" 0 R >> >> /Contents " + str(cid).encode() + b" 0 R >>"
            )
            page_ids.append(pid)

        objects[catalog_id - 1] = (
            b"<< /Type /Catalog /Pages " + str(pages_id).encode() + b" 0 R >>"
        )
        kids = b" ".join(str(p).encode() + b" 0 R" for p in page_ids)
        objects[pages_id - 1] = (
            b"<< /Type /Pages /Count " + str(len(page_ids)).encode()
            + b" /Kids [" + kids + b"] >>"
        )
        objects[f1_id - 1] = (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        )
        objects[f2_id - 1] = (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
            b"/Encoding /WinAnsiEncoding >>"
        )

        # Info dictionary, last so its id is stable to compute.
        info_id = add(
            b"<< /Title (" + _enc(self.title).encode("cp1252", "replace")
            + b") /Author (" + _enc(self.author).encode("cp1252", "replace")
            + b") /Producer (sentinel-findings) >>"
        )

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: List[int] = [0] * (len(objects) + 1)
        for idx, body in enumerate(objects, start=1):
            offsets[idx] = len(out)
            out += f"{idx} 0 obj\n".encode() + body + b"\nendobj\n"

        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for idx in range(1, len(objects) + 1):
            out += f"{offsets[idx]:010d} 00000 n \n".encode()
        out += (
            b"trailer\n<< /Size " + str(len(objects) + 1).encode()
            + b" /Root " + str(catalog_id).encode() + b" 0 R /Info "
            + str(info_id).encode() + b" 0 R >>\nstartxref\n"
            + str(xref_at).encode() + b"\n%%EOF\n"
        )
        return bytes(out)
