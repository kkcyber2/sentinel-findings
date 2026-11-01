"""HTML report renderer.

Consumes only the canonical schema. It has never heard of certwatch,
beaconhunt or spydetect, and it does not need to — that is the point of
normalising first.

Two deliberate properties:

* **Self-contained.** No CDN, no web font, no external stylesheet. A report is
  a document someone forwards; it must open with no network and still look
  right in three years.
* **Provenance is unmissable.** If any finding is simulated or unsourced, a
  banner appears above the findings and the affected rows are marked. It is
  not a footnote.
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional

from ..schema import Finding, FindingCollection, Provenance, Severity

_CSS = """
:root{
  --ink:#16181d; --ink-2:#4a5059; --ink-3:#78808c; --rule:#e2e5ea;
  --bg:#ffffff; --bg-2:#f7f8fa; --bg-3:#eef0f4;
  --crit:#a4232b; --crit-bg:#fdf2f3;
  --high:#a85a12; --high-bg:#fdf6ee;
  --med:#7a6410; --med-bg:#fbf8ea;
  --low:#3d5a7a; --low-bg:#f1f5f9;
  --info:#586070; --info-bg:#f5f6f8;
  --ok:#1f6b45;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.62 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-feature-settings:"tnum";
}
.wrap{max-width:860px;margin:0 auto;padding:0 20px 80px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
code{background:var(--bg-3);padding:.12em .38em;border-radius:3px;word-break:break-word}

/* ---------- masthead ---------- */
header.mast{border-bottom:2px solid var(--ink);padding:34px 0 18px;margin-bottom:30px}
.kicker{
  font:600 10.5px/1 ui-monospace,monospace;letter-spacing:.16em;text-transform:uppercase;
  color:var(--ink-3);margin:0 0 12px
}
h1{font-size:clamp(24px,6vw,34px);line-height:1.15;margin:0 0 10px;letter-spacing:-.02em}
.sub{color:var(--ink-2);margin:0;font-size:14.5px;max-width:62ch}
.meta{
  display:flex;flex-wrap:wrap;gap:6px 22px;margin-top:18px;
  font:500 11px/1.5 ui-monospace,monospace;color:var(--ink-3)
}
.meta b{color:var(--ink-2);font-weight:600}

/* ---------- sections ---------- */
section{margin:0 0 42px}
h2{
  font-size:12px;letter-spacing:.13em;text-transform:uppercase;color:var(--ink);
  margin:0 0 16px;padding-bottom:8px;border-bottom:1px solid var(--rule)
}
h2 .n{color:var(--ink-3);margin-right:9px;font-weight:600}
h3{font-size:15.5px;margin:22px 0 8px;line-height:1.35}
p{margin:0 0 12px;color:var(--ink-2)}
p.tight{margin-bottom:6px}

/* ---------- headline counts ---------- */
.counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(86px,1fr));gap:1px;background:var(--rule);border:1px solid var(--rule);margin:0 0 18px}
.counts div{background:var(--bg);padding:13px 10px;text-align:center}
.counts .v{font:700 23px/1 ui-monospace,monospace;display:block;margin-bottom:5px}
.counts .k{font:600 9.5px/1 ui-monospace,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3)}
.v.critical{color:var(--crit)} .v.high{color:var(--high)} .v.medium{color:var(--med)}
.v.low{color:var(--low)} .v.info{color:var(--info)} .v.total{color:var(--ink)}

/* ---------- provenance banner ---------- */
.banner{
  border-left:3px solid var(--high);background:var(--high-bg);
  padding:13px 15px;margin:0 0 20px;font-size:13.5px;color:#6d430f
}
.banner strong{display:block;margin-bottom:4px;font-size:13px;letter-spacing:.02em}
.banner.ok{border-left-color:var(--ok);background:#f1f8f3;color:#1c5940}

/* ---------- finding ---------- */
.finding{border:1px solid var(--rule);border-left-width:3px;margin:0 0 10px;background:var(--bg)}
.finding.critical{border-left-color:var(--crit)}
.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)}
.finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)}
.fhead{padding:13px 15px 11px;display:flex;gap:11px;align-items:flex-start;flex-wrap:wrap}
.sev{
  font:700 9.5px/1 ui-monospace,monospace;letter-spacing:.09em;text-transform:uppercase;
  padding:4px 7px;border-radius:2px;white-space:nowrap;flex-shrink:0;margin-top:2px
}
.sev.critical{background:var(--crit-bg);color:var(--crit)}
.sev.high{background:var(--high-bg);color:var(--high)}
.sev.medium{background:var(--med-bg);color:var(--med)}
.sev.low{background:var(--low-bg);color:var(--low)}
.sev.info{background:var(--info-bg);color:var(--info)}
.ftitle{font-weight:600;font-size:14.5px;flex:1;min-width:180px;line-height:1.4}
.fbody{padding:0 15px 14px}
.loc{
  font:500 11px/1.5 ui-monospace,monospace;color:var(--ink-3);
  margin:0 0 9px;word-break:break-all
}
.desc{margin:0 0 11px;font-size:13.5px;color:var(--ink-2)}
.evidence{
  background:var(--bg-2);border:1px solid var(--rule);padding:9px 11px;margin:0 0 11px;
  font:12px/1.55 ui-monospace,monospace;color:var(--ink-2);
  white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere
}
.fix{margin:0;padding:0;list-style:none}
.fix li{position:relative;padding-left:19px;font-size:13px;color:var(--ink-2);margin-bottom:4px}
.fix li:before{content:"\\2192";position:absolute;left:0;color:var(--ink-3);font-size:12px}
.tags{margin-top:9px;display:flex;flex-wrap:wrap;gap:5px}
.tag{
  font:500 10px/1 ui-monospace,monospace;background:var(--bg-3);color:var(--ink-2);
  padding:4px 6px;border-radius:2px;letter-spacing:.03em
}
.simstamp{
  font:700 9.5px/1 ui-monospace,monospace;letter-spacing:.09em;text-transform:uppercase;
  background:var(--high-bg);color:var(--high);padding:4px 7px;border-radius:2px
}

/* ---------- tables ---------- */
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 0 16px;border:1px solid var(--rule)}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:420px}
th,td{text-align:left;padding:8px 11px;border-bottom:1px solid var(--rule);vertical-align:top}
th{
  font:600 9.5px/1.4 ui-monospace,monospace;letter-spacing:.09em;text-transform:uppercase;
  color:var(--ink-3);background:var(--bg-2);white-space:nowrap
}
tr:last-child td{border-bottom:none}
td.num{font-family:ui-monospace,monospace;font-size:11.5px;white-space:nowrap}

/* ---------- misc ---------- */
.empty{padding:26px;text-align:center;color:var(--ink-3);border:1px dashed var(--rule);font-size:13.5px}
footer{border-top:1px solid var(--rule);padding-top:16px;margin-top:44px;font-size:12px;color:var(--ink-3)}
footer p{color:var(--ink-3);font-size:12px}

@media (max-width:560px){
  .wrap{padding:0 14px 60px}
  header.mast{padding-top:24px}
  .fhead{padding:11px 12px 9px}
  .fbody{padding:0 12px 12px}
  .counts{grid-template-columns:repeat(3,1fr)}
  h2{margin-bottom:13px}
}
"""


def render_html(
    collection: FindingCollection,
    *,
    title: str = "Security Report",
    org: str = "",
    target: str = "",
    generated_at: str = "",
    min_severity: Optional[Severity] = None,
    include_info: bool = True,
) -> str:
    """Render a complete standalone HTML document."""
    shown = collection.filter(min_severity=min_severity) if min_severity else collection
    findings = list(shown.sorted())
    if not include_info:
        findings = [f for f in findings if f.severity is not Severity.INFO]

    counts = _counts(findings)
    esc = html.escape

    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append(f"<title>{esc(title)}</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head><body><div class=\"wrap\">")

    # ---- masthead ----
    parts.append('<header class="mast">')
    parts.append('<p class="kicker">Security Assessment</p>')
    parts.append(f"<h1>{esc(title)}</h1>")
    if org:
        parts.append(f'<p class="sub">Prepared for {esc(org)}.</p>')
    parts.append('<div class="meta">')
    if target:
        parts.append(f"<span>Target <b>{esc(target)}</b></span>")
    if generated_at:
        parts.append(f"<span>Generated <b>{esc(generated_at)}</b></span>")
    parts.append(f"<span>Findings <b>{len(findings)}</b></span>")
    parts.append("</div></header>")

    # ---- summary ----
    parts.append("<section>")
    parts.append('<h2><span class="n">01</span>Summary</h2>')
    parts.append('<div class="counts">')
    parts.append(f'<div><span class="v total">{len(findings)}</span><span class="k">Total</span></div>')
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        parts.append(
            f'<div><span class="v {sev.value}">{counts[sev.value]}</span>'
            f'<span class="k">{sev.value}</span></div>'
        )
    parts.append("</div>")
    parts.append(_provenance_banner(shown))
    parts.append("</section>")

    # ---- per-severity bodies ----
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    if include_info:
        order.append(Severity.INFO)

    num = 2
    for sev in order:
        group = [f for f in findings if f.severity is sev]
        if not group:
            continue
        parts.append("<section>")
        parts.append(f'<h2><span class="n">{num:02d}</span>{sev.value} — {len(group)}</h2>')
        for f in group:
            parts.append(_finding_html(f))
        parts.append("</section>")
        num += 1

    if not findings:
        parts.append('<section><div class="empty">No findings at or above the '
                     "selected severity.</div></section>")

    parts.append("<footer>")
    parts.append(
        "<p><strong>Scope.</strong> This report covers only the findings listed. "
        "An absent finding is not proof of absence: it means no check in this "
        "run produced one.</p>"
    )
    if shown.simulated_count or shown.unknown_provenance_count:
        parts.append(
            f"<p><strong>Provenance.</strong> {shown.simulated_count} simulated, "
            f"{shown.unknown_provenance_count} unsourced. Do not present this "
            "document as evidence of a real assessment.</p>"
        )
    parts.append("</footer>")

    parts.append("</div></body></html>")
    return "\n".join(parts)


def _finding_html(f: Finding) -> str:
    esc = html.escape
    out: List[str] = []
    out.append(f'<article class="finding {f.severity.value}">')
    out.append('<div class="fhead">')
    out.append(f'<span class="sev {f.severity.value}">{f.severity.value}</span>')
    out.append(f'<span class="ftitle">{esc(f.title)}</span>')
    if f.provenance is Provenance.SIMULATED:
        out.append('<span class="simstamp">Simulated</span>')
    elif f.provenance is Provenance.UNKNOWN:
        out.append('<span class="simstamp">Unsourced</span>')
    out.append("</div>")
    out.append('<div class="fbody">')

    if f.location:
        out.append(f'<p class="loc">{esc(f.location)}</p>')
    if f.description:
        out.append(f'<p class="desc">{esc(f.description)}</p>')
    if f.evidence:
        out.append(f'<div class="evidence">{esc(f.evidence)}</div>')
    if f.remediation:
        out.append('<ul class="fix">')
        for step in f.remediation:
            out.append(f"<li>{esc(step)}</li>")
        out.append("</ul>")

    tags: List[str] = []
    if f.tool:
        tags.append(f.tool)
    if f.confidence:
        tags.append(f"confidence: {f.confidence.value}")
    if f.cvss is not None:
        tags.append(f"CVSS {f.cvss}")
    tags.extend(f.cwe)
    tags.extend(f.cve)
    if tags:
        out.append('<div class="tags">')
        for t in tags:
            out.append(f'<span class="tag">{esc(t)}</span>')
        out.append("</div>")

    out.append("</div></article>")
    return "".join(out)


def _provenance_banner(shown: FindingCollection) -> str:
    sim = shown.simulated_count
    unk = shown.unknown_provenance_count
    if not sim and not unk:
        if shown.total:
            return (
                '<div class="banner ok"><strong>All findings observed</strong>'
                "Every finding in this report came from a check that ran against "
                "the target. This document is evidence.</div>"
            )
        return ""
    bits = []
    if sim:
        bits.append(f"{sim} simulated")
    if unk:
        bits.append(f"{unk} unsourced")
    return (
        '<div class="banner"><strong>This report is not all evidence</strong>'
        + " and ".join(bits)
        + " finding(s) are included. Simulated findings come from a generator, "
        "not from the target. Rows below are marked; do not send this document "
        "to a client as an assessment result.</div>"
    )


def _counts(findings: List[Finding]) -> Dict[str, int]:
    tally = {sev.value: 0 for sev in Severity}
    for f in findings:
        tally[f.severity.value] += 1
    return tally


def render_fragment(collection: FindingCollection, **kwargs: Any) -> str:  # noqa: ANN401
    """The body of a report, for embedding inside an existing page."""
    doc = render_html(collection, **kwargs)
    match = re.search(r"<body>(.*)</body>", doc, re.S)
    return match.group(1) if match else doc
