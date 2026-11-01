"""Renderer tests.

The PDF tests validate the actual byte structure — xref offsets, object count,
trailer — because a file that merely begins with ``%PDF`` can still be
unopenable, and this writer builds the format by hand.
"""

from __future__ import annotations

import re
import zlib

import pytest

from sentinel_findings.render.html import render_html
from sentinel_findings.render.pdf import PDFDocument, _enc, _width, _wrap
from sentinel_findings.render.report import render_pdf
from sentinel_findings.schema import Finding, FindingCollection, Provenance, Severity


def _f(**kw):
    base = dict(
        id="",
        title="Test finding",
        severity=Severity.HIGH,
        provenance=Provenance.OBSERVED,
        category="tls",
        description="Something is wrong.",
        evidence="proof line",
        location="host:443",
        tool="certwatch",
        remediation=["Fix it"],
    )
    base.update(kw)
    return Finding(**base)


def test_width_grows_with_length():
    assert _width("a", 10) < _width("aaaa", 10)


def test_width_bold_is_wider_than_regular():
    assert _width("hello", 10, bold=True) > _width("hello", 10, bold=False)


def test_wrap_splits_long_text():
    lines = _wrap("word " * 60, 9, 200)
    assert len(lines) > 1
    assert all(_width(line, 9) <= 200 + 1 for line in lines)


def test_wrap_hard_breaks_unbreakable_token():
    lines = _wrap("a" * 400, 9, 150)
    assert len(lines) > 1
    assert all(_width(line, 9) <= 150 + 1 for line in lines)


def test_wrap_preserves_blank_paragraphs():
    assert "" in _wrap("one\n\nthree", 9, 200)


def test_encoding_escapes_pdf_specials():
    out = _enc("a(b)c\\d")
    assert r"\(" in out and r"\)" in out and r"\\" in out


def test_encoding_transliterates_typographic_characters():
    assert _enc("a\u2014b") == "a-b"
    assert _enc("\u201cquoted\u201d") == '"quoted"'


def test_encoding_replaces_unrepresentable_with_question_mark():
    assert _enc("\u4f60") == "?"


def _parse_objects(blob: bytes) -> dict:
    """Minimal object reader: id -> body bytes."""
    out = {}
    for m in re.finditer(rb"(\d+) 0 obj\n(.*?)\nendobj", blob, re.S):
        out[int(m.group(1))] = m.group(2)
    return out


def _parse_xref(blob: bytes) -> dict:
    at = int(re.search(rb"startxref\n(\d+)", blob).group(1))
    table = blob[at:].split(b"\n")
    count = int(table[1].split()[1])
    offsets = {}
    for idx in range(1, count):
        entry = table[2 + idx].split()
        offsets[idx] = int(entry[0])
    return offsets


def test_pdf_header_and_eof():
    doc = PDFDocument(title="T")
    doc.h1("Hello")
    blob = doc.to_bytes()
    assert blob.startswith(b"%PDF-1.4")
    assert blob.rstrip().endswith(b"%%EOF")


def test_xref_offsets_point_at_real_objects():
    doc = PDFDocument(title="T")
    doc.h1("x")
    blob = doc.to_bytes()
    offsets = _parse_xref(blob)
    assert offsets, "xref table was empty"
    for obj_id, offset in offsets.items():
        marker = f"{obj_id} 0 obj".encode()
        assert blob[offset:offset + len(marker)] == marker, f"offset wrong for obj {obj_id}"


def test_catalog_and_pages_objects_exist():
    doc = PDFDocument(title="T")
    doc.h1("x")
    blob = doc.to_bytes()
    objs = _parse_objects(blob)
    assert any(b"/Type /Catalog" in b for b in objs.values())
    assert any(b"/Type /Pages" in b for b in objs.values())


def test_content_stream_is_valid_flate():
    doc = PDFDocument(title="T")
    doc.h1("compressed please")
    blob = doc.to_bytes()
    streams = re.findall(rb"stream\n(.*?)\nendstream", blob, re.S)
    assert streams
    for s in streams:
        assert b"compressed please" not in s
        assert zlib.decompress(s)


def test_long_document_paginates():
    doc = PDFDocument(title="T")
    for i in range(160):
        doc.para(f"Paragraph number {i} with enough text to take a line or so.")
    blob = doc.to_bytes()
    assert len(doc.pages) > 1
    page_count = int(re.search(rb"/Count (\d+)", blob).group(1))
    assert page_count == len(doc.pages)


def test_page_count_matches_kids_array():
    doc = PDFDocument(title="T")
    for i in range(80):
        doc.para(f"line {i} " * 20)
    blob = doc.to_bytes()
    kids = re.search(rb"/Kids \[(.*?)\]", blob, re.S).group(1)
    assert len(re.findall(rb"\d+ 0 R", kids)) == len(doc.pages)


def test_fonts_are_base14_helvetica():
    doc = PDFDocument(title="T")
    doc.h1("x")
    blob = doc.to_bytes()
    assert b"/BaseFont /Helvetica" in blob
    assert b"/WinAnsiEncoding" in blob


def test_special_characters_do_not_break_the_document():
    doc = PDFDocument(title="T")
    doc.para('quotes (parens) back\\slash \u2014 dash')
    blob = doc.to_bytes()
    assert _parse_xref(blob)


def test_count_row_renders_numbers():
    doc = PDFDocument(title="T")
    doc.count_row([("Total", 5), ("Critical", 2)])
    blob = doc.to_bytes()
    streams = re.findall(rb"stream\n(.*?)\nendstream", blob, re.S)
    text = b"".join(zlib.decompress(s) for s in streams)
    assert b"(5)" in text and b"(2)" in text


def test_render_pdf_refuses_simulated_by_default():
    c = FindingCollection([_f(provenance=Provenance.SIMULATED)])
    with pytest.raises(ValueError, match="simulated"):
        render_pdf(c)


def test_render_pdf_accepts_simulated_when_acknowledged_but_marks_it():
    c = FindingCollection([_f(provenance=Provenance.SIMULATED)])
    blob = render_pdf(c, acknowledge_simulated=True)
    streams = re.findall(rb"stream\n(.*?)\nendstream", blob, re.S)
    text = b"".join(zlib.decompress(s) for s in streams)
    assert b"SIMULATED" in text
    assert b"not wholly evidence" in text


def test_render_pdf_clean_set_says_it_is_evidence():
    c = FindingCollection([_f()])
    blob = render_pdf(c)
    streams = re.findall(rb"stream\n(.*?)\nendstream", blob, re.S)
    text = b"".join(zlib.decompress(s) for s in streams)
    assert b"All findings observed" in text


def test_render_pdf_empty_refused():
    with pytest.raises(ValueError, match="empty"):
        render_pdf(FindingCollection())


def test_render_pdf_includes_scope_limitation():
    c = FindingCollection([_f()])
    blob = render_pdf(c)
    streams = re.findall(rb"stream\n(.*?)\nendstream", blob, re.S)
    text = b"".join(zlib.decompress(s) for s in streams)
    assert b"scope" in text.lower()


def test_html_is_self_contained():
    doc = render_html(FindingCollection([_f()]))
    assert "<style>" in doc
    assert "http://" not in doc
    assert "https://" not in doc
    assert "<script" not in doc.lower()


def test_html_has_viewport_for_mobile():
    assert 'name="viewport"' in render_html(FindingCollection([_f()]))


def test_html_escapes_finding_content():
    doc = render_html(
        FindingCollection([_f(title="<script>alert(1)</script>", evidence="a & b")])
    )
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc
    assert "a &amp; b" in doc


def test_html_shows_simulated_banner_and_stamp():
    doc = render_html(FindingCollection([_f(provenance=Provenance.SIMULATED)]))
    assert "not all evidence" in doc
    assert "simstamp" in doc


def test_html_clean_set_shows_evidence_banner():
    doc = render_html(FindingCollection([_f()]))
    assert "All findings observed" in doc


def test_html_renders_all_severity_sections_present():
    c = FindingCollection(
        [
            _f(title="c", severity=Severity.CRITICAL),
            _f(title="h", severity=Severity.HIGH, location="b:1"),
            _f(title="m", severity=Severity.MEDIUM, location="c:1"),
            _f(title="l", severity=Severity.LOW, location="d:1"),
        ]
    )
    doc = render_html(c)
    for word in ("critical", "high", "medium", "low"):
        assert word in doc


def test_html_min_severity_filter_applies():
    c = FindingCollection(
        [
            _f(title="crit", severity=Severity.CRITICAL),
            _f(title="low", severity=Severity.LOW, location="z:1"),
        ]
    )
    doc = render_html(c, min_severity=Severity.HIGH)
    assert "crit" in doc
    assert 'finding low' not in doc
    assert 'class="sev low"' not in doc


def test_html_empty_state_message():
    doc = render_html(FindingCollection([_f()]), min_severity=Severity.CRITICAL)
    assert "No findings" in doc
