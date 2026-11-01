"""PDF report assembly: canonical findings in, a client-ready document out."""

from __future__ import annotations

from typing import Optional

from ..schema import FindingCollection, Provenance, Severity
from .pdf import PDFDocument

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render_pdf(
    collection: FindingCollection,
    *,
    title: str = "Security Assessment",
    org: str = "",
    target: str = "",
    generated_at: str = "",
    include_info: bool = True,
    acknowledge_simulated: bool = False,
) -> bytes:
    """Render a paginated PDF.

    ``acknowledge_simulated`` is the deliberate act the schema's
    ``assert_reportable`` gate demands. Without it, a collection containing
    simulated findings raises rather than producing a document that looks like
    an assessment. This is how the honesty layer reaches the output format most
    likely to be forwarded to a client.
    """
    if not acknowledge_simulated:
        collection.assert_reportable()

    doc = PDFDocument(title=title, author=org or "sentinel-findings")

    doc.h1(title)
    meta_bits = []
    if org:
        meta_bits.append(f"Prepared for: {org}")
    if target:
        meta_bits.append(f"Target: {target}")
    if generated_at:
        meta_bits.append(f"Generated: {generated_at}")
    if meta_bits:
        doc.para("   |   ".join(meta_bits), size=8.6, gray=0.42)

    # ---- summary ----
    counts = collection.counts
    doc.h2("Summary")
    doc.count_row(
        [
            ("Total", collection.total),
            ("Critical", counts["critical"]),
            ("High", counts["high"]),
            ("Medium", counts["medium"]),
            ("Low", counts["low"]),
            ("Info", counts["info"]),
        ]
    )

    sim = collection.simulated_count
    unk = collection.unknown_provenance_count
    if sim or unk:
        bits = []
        if sim:
            bits.append(f"{sim} simulated finding(s)")
        if unk:
            bits.append(f"{unk} finding(s) of unknown origin")
        doc.banner(
            "This document is not wholly evidence",
            "It includes "
            + " and ".join(bits)
            + ". Simulated findings were produced by a generator, not by the "
            "target. They are marked SIMULATED below. Do not present this "
            "document as the result of a real assessment.",
            warning=True,
        )
    elif collection.total:
        doc.banner(
            "All findings observed",
            "Every finding here came from a check that ran against the target. "
            "This document is evidence.",
            warning=False,
        )

    if collection.total == 0:
        doc.para("No findings were recorded.", gray=0.4)
        return doc.to_bytes()

    # ---- bodies ----
    shown = list(collection.sorted())
    if not include_info:
        shown = [f for f in shown if f.severity is not Severity.INFO]

    for sev in _SEV_ORDER:
        group = [f for f in shown if f.severity is sev]
        if not group:
            continue
        doc.h2(f"{sev.value}  -  {len(group)}")
        for f in group:
            tags = []
            if f.tool:
                tags.append(f.tool)
            tags.append(f"confidence {f.confidence.value}")
            if f.cvss is not None:
                tags.append(f"CVSS {f.cvss}")
            tags.extend(f.cwe)
            tags.extend(f.cve)
            doc.finding(
                severity=sev.value,
                title=f.title,
                location=f.location,
                description=f.description,
                evidence=f.evidence,
                remediation=f.remediation,
                tags=tags,
                simulated=f.provenance is Provenance.SIMULATED,
            )

    # ---- scope note ----
    doc.h2("Scope and limitations")
    doc.para(
        "This report covers only the findings listed above. A finding that is "
        "absent is not proof that the corresponding weakness is absent: it "
        "means no check in this run produced one. Checks have blind spots, "
        "documented per tool in each project's limitations section."
    )

    return doc.to_bytes()
