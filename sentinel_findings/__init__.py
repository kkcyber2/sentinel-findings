"""sentinel-findings — one canonical finding schema, many scanners.

Why this exists
---------------
ForgeGuard's findings report component is 1,701 lines because it reaches into
whatever shape each scanner happened to emit. Every new scanner makes it
longer. Normalising first is what lets the report be split, tested, and
rendered to a second format without touching a scanner.

And, separately: a scan that returns invented results while looking exactly
like a real one is the worst failure mode a security product can have. Every
finding here carries `provenance` from creation to output, and the PDF renderer
refuses to build a client document from simulated data unless the caller
explicitly acknowledges it.
"""

from .adapters import ADAPTERS, convert, from_forgeguard, to_beaconhunt, to_certwatch, to_spydetect
from .schema import (
    Confidence,
    Finding,
    FindingCollection,
    Provenance,
    Severity,
)

__version__ = "1.0.0"

__all__ = [
    "Confidence",
    "Finding",
    "FindingCollection",
    "Provenance",
    "Severity",
    "ADAPTERS",
    "convert",
    "from_forgeguard",
    "to_beaconhunt",
    "to_certwatch",
    "to_spydetect",
    "render_html",
    "render_pdf",
]


def render_html(*args, **kwargs):  # noqa: ANN002, ANN003
    """Lazy import: the renderer pulls in nothing heavy, but keeping it here
    means importing the schema alone does not load the HTML CSS string."""
    from .render.html import render_html as _impl

    return _impl(*args, **kwargs)


def render_pdf(*args, **kwargs):  # noqa: ANN002, ANN003
    from .render.report import render_pdf as _impl

    return _impl(*args, **kwargs)
