# sentinel-findings

One canonical finding schema, adapters for the scanners you already run, and a
report renderer that produces an HTML page or a real PDF — no browser, no
reportlab, no headless Chrome.

Built to close a specific gap in [ForgeGuard](https://github.com/kkcyber2/Forgeguard-ai):
a 1,701-line findings component that could neither be split nor tested, and a
product that could compute a full security report but never hand a client a
document.

```
scanner output ──> adapter ──> Finding ──> FindingCollection ──> HTML / PDF
   (any dialect)                (canonical)
```

## Why this exists

Every scanner invents its own output shape. certwatch emits a finding list per
host, spydetect emits `"clean"` as if it were a severity band, beaconhunt packs
a score and its evidence reasons into separate fields. A report renderer that
knows about all of them is unmaintainable; a renderer that knows about none of
them renders nothing.

The schema is the seam. Add a tool by writing one adapter; write one renderer
and every tool benefits.

## Install

```bash
pip install -e .
# or with test deps
pip install -e ".[dev]"
pip install pypdf   # only for the PDF round-trip test
```

Python 3.9+. Zero runtime dependencies.

## The schema

```python
from sentinel_findings import Finding, FindingCollection, Severity, Provenance

f = Finding(
    title="TLS 1.0 accepted",
    severity=Severity.HIGH,
    provenance=Provenance.OBSERVED,
    category="tls",
    location="example.com:443",
    cwe=["CWE-326"],
    description="The server completed a TLS 1.0 handshake.",
    remediation=["Disable TLS 1.0 and 1.1."],
    evidence="negotiated_protocol = TLSv1",
    tool="certwatch",
)
```

`severity` and `confidence` are deliberately separate. A critical-severity
finding at low confidence is a lead; a medium at high confidence is a fix.
Collapsing the two produces reports that are either alarmist or useless.

### Provenance is the point

Every finding carries `provenance`, and it is not decoration:

| value | meaning |
|---|---|
| `observed` | a check ran against the target and produced this |
| `imported` | read from another tool's saved output — that tool observed it, this pipeline did not |
| `simulated` | generated, not measured — **never** claimed as evidence |
| `unknown` | no source recorded; rendered with a warning |

Adapters default to `imported`, because this pipeline did not touch the target.
The ForgeGuard adapter defaults to `simulated`, because ForgeGuard's synthetic
generator emits that exact shape — marking it `observed` has to be a deliberate
argument, not an oversight.

`FindingCollection` deduplicates on a content fingerprint (tool + category +
title + location + CWE), keeping the worse severity and the stronger
provenance. If a real check confirms something a simulation guessed at, the
merged result is evidence.

## Convert scanner output

```bash
sentinel-findings tools
sentinel-findings convert --tool certwatch --in certwatch.json --out normalized.json
sentinel-findings convert --tool beaconhunt --in beacon.json --out b.json
sentinel-findings merge a.json b.json --out all.json
sentinel-findings summary --in all.json
```

Adapters: `certwatch`, `beaconhunt`, `spydetect`, `forgeguard`.

`tools` prints exactly that list — a fourth adapter is added by writing a
function and registering it, nothing else.

Real output:

```
$ sentinel-findings convert --tool certwatch --in cw.json --out n.json
converted 2 raw -> 2 unique ({'critical': 1, 'high': 0, 'medium': 1, 'low': 0, 'info': 0})

$ sentinel-findings summary --in n.json
total      2
critical   1
high       0
medium     1
low        0
info       0
evidence   yes
```

## Render a report

```bash
sentinel-findings report --in all.json --html report.html
sentinel-findings report --in all.json --pdf report.pdf --title "Acme Q4 Assessment"
```

The PDF is written directly — ~400 lines in `render/pdf.py` emit a PDF 1.4
document with base-14 Helvetica, WinAnsi encoding and FlateDecode-compressed
content streams. No native dependency, no font files. It is deliberately
boring, and it is verified: the test suite parses the xref table and asserts
every offset points at the object it claims.

```
wrote PDF (1951 bytes) -> report.pdf
```

### The honesty gate

A report containing `simulated` findings is **refused** unless the caller
acknowledges it:

```
$ sentinel-findings report --in sim.json --pdf out.pdf
refused: 1 simulated finding(s) in a client report; filter them out or acknowledge explicitly. ids=['x1']
This is the honesty gate. Simulated findings cannot become a client PDF by accident. Pass --acknowledge-simulated if this is a demo and you accept it will be marked.
$ echo $?
2
```

With `--acknowledge-simulated` the document renders, and the simulated findings
stay visibly labelled — a `SIMULATED` chip on each row and a banner above the
summary reading *"This document is not wholly evidence"*. Verified by
extracting the text back out of the finished PDF:

| document | banner |
|---|---|
| clean set | `All findings observed` |
| mixed set | `This document is not wholly evidence` + `SIMULATED` chip |

This is the whole point: a scan cannot silently return fabricated results,
because the renderer will not produce a clean-looking client deliverable from
them. ForgeGuard's `REVENUE_SIMULATION_MODE` is exactly that failure mode.

## Tests

```bash
python -m pytest -q
```

**83 passing.** Coverage includes:

- **Schema** — severity coercion from every spelling a scanner emits (an
  unknown word becomes `info`, never `critical`), rank ordering checked against
  the alphabetical ordering bug certwatch once shipped, fingerprint dedupe,
  merge precedence, CVSS range rejection, unknown-key preservation.
- **Adapters** — each one run against a fixture mirroring that tool's real
  `to_dict` output, including the "clean is not a severity" drop for spydetect
  and the simulated-by-default rule for ForgeGuard.
- **Honesty gate** — refused without acknowledgement, rendered and marked with
  it, and filtering by provenance de-escalates a mixed set to reportable.
- **PDF structure** — xref offsets resolved and checked against real object
  headers, page count matched to the `/Kids` array, Flate streams decompressed,
  unrepresentable characters replaced rather than silently dropped.
- **HTML** — self-contained (no `http://`, no `<script>`), hostile titles
  escaped, simulated rows stamped.

## Limitations

- **The PDF writer has no font embedding and no Unicode.** Characters outside
  WinAnsi are transliterated to ASCII (`—` becomes `-`) or replaced with `?`.
  Cyrillic or CJK titles will not render. Fine for English-language reports; a
  reason to reach for WeasyPrint if you need more.
- **No images, no page-break control, no CSS.** It produces a clean linear
  document. It is not a layout engine, and a single finding taller than a page
  will not split across pages cleanly.
- **No SARIF adapter yet.** The schema carries `cwe` and would map cleanly; the
  adapter simply is not written.
- **Fingerprint dedupe is content-based**, so renaming a check changes the
  fingerprint and the same issue can appear twice across a version change.
- **Hostnames are not re-resolved at dispatch.** For findings this is
  irrelevant — nothing here touches a network. For anything that acts on a
  finding, see [scopeguard](https://github.com/kkcyber2/scopeguard).

## Legal

Defensive tooling for authorized security work. Adapters process output you
already produced. Nothing here scans a target.

MIT licensed.
