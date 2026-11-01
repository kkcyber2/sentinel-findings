"""Adapters: one per input dialect.

Each adapter is a pure function from a decoded JSON payload to a list of
canonical findings. No network, no filesystem, no clock beyond what the caller
passes — so every one is testable against a fixture and cheap to keep honest.

The field names below were read off each tool's own ``to_dict``/``as_dict``,
not guessed:

certwatch     {"id", "title", "severity", "detail", "remediation"}
beaconhunt    {"dest", "port", "count", "score", "confidence", "reasons", "metrics"}
spydetect     {"pid", "name", "score", "severity", "reasons", "metrics"}
forgeguard    Finding interface from src/app/dashboard/scans/[id]/findings-report-types.ts

Two rules every adapter follows:

1. Provenance defaults to IMPORTED, never OBSERVED. This pipeline did not run
   the check; it read someone else's output. Claiming otherwise is exactly the
   dishonesty the whole package exists to prevent.
2. Anything the source said that has no canonical field goes into ``extra``
   rather than being dropped. Conversion should not lose data.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Callable, Dict, List, Optional

from .schema import Confidence, Finding, Provenance, Severity

# --------------------------------------------------------------------------- #
# certwatch — TLS / certificate auditor                                       #
# --------------------------------------------------------------------------- #

# certwatch finding ids, mapped to a CWE where one genuinely applies.
# Only ids that exist in certwatch/findings.py are listed; the fallback is
# "no CWE", which is honest, rather than a plausible-looking wrong one.
_CERTWATCH_CWE: Dict[str, List[str]] = {
    "ssl-v3": ["CWE-327"],
    "protocol-tlsv1": ["CWE-327"],
    "protocol-tlsv1_1": ["CWE-327"],
    "weak-cipher": ["CWE-327"],
    "cert-expired": ["CWE-298"],
    "cert-expiring": ["CWE-298"],
    "cert-expired-long": ["CWE-298"],
    "self-signed": ["CWE-295"],
    "chain-untrusted": ["CWE-295"],
    "hostname-mismatch": ["CWE-297"],
    "weak-key": ["CWE-326"],
    "no-san": ["CWE-295"],
}


def to_certwatch(payload: Any, *, target: str = "", now: Optional[str] = None) -> List[Finding]:
    """Convert ``certwatch --json`` output.

    Accepts the full ledger (a list of per-host results, each with a
    ``findings`` array) or a single bare list of findings.
    """
    rows = payload if isinstance(payload, list) else [payload]
    out: List[Finding] = []
    observed_at = now or _utcnow()

    for row in rows:
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or target or "")
        port = row.get("port")
        where = f"{host}:{port}" if port else host

        findings = row.get("findings")
        if findings is None:
            # A bare finding list was passed in.
            findings = [row]

        for raw in findings or []:
            if not isinstance(raw, dict):
                continue
            fid = str(raw.get("id") or "")
            title = str(raw.get("title") or fid or "TLS issue")
            detail = str(raw.get("detail") or "")
            remediation = str(raw.get("remediation") or "").strip()

            extra: Dict[str, Any] = {}
            if row.get("negotiated_protocol"):
                extra["negotiated_protocol"] = row["negotiated_protocol"]
            if row.get("negotiated_cipher"):
                extra["negotiated_cipher"] = row["negotiated_cipher"]
            if row.get("weak_ciphers_accepted"):
                extra["weak_ciphers_accepted"] = row["weak_ciphers_accepted"]
            cert = row.get("cert")
            if isinstance(cert, dict):
                for key in ("issuer", "not_after", "days_remaining", "key_bits"):
                    if cert.get(key) is not None:
                        extra[f"cert_{key}"] = cert[key]

            out.append(
                Finding(
                    id=f"certwatch:{fid}:{where}",
                    title=title,
                    severity=Severity.parse(raw.get("severity")),
                    provenance=Provenance.IMPORTED,
                    category="tls",
                    description=detail,
                    evidence=detail,
                    location=where,
                    cwe=list(_CERTWATCH_CWE.get(fid, [])),
                    confidence=Confidence.HIGH,
                    remediation=[remediation] if remediation else [],
                    tool="certwatch",
                    target=where,
                    observed_at=observed_at,
                    extra=extra,
                )
            )

    return out


# --------------------------------------------------------------------------- #
# beaconhunt — C2 beaconing detector                                          #
# --------------------------------------------------------------------------- #

_BEACON_CWE = ["CWE-514"]  # covert channel


def to_beaconhunt(payload: Any, *, target: str = "", now: Optional[str] = None) -> List[Finding]:
    """Convert ``beaconhunt --json`` output (a list of destination scores).

    A destination that scored below the tool's own floor is passed over: the
    CLI already filtered it, and re-admitting it here would inflate counts.
    """
    rows = payload if isinstance(payload, list) else [payload]
    out: List[Finding] = []
    observed_at = now or _utcnow()

    for row in rows:
        if not isinstance(row, dict):
            continue
        dest = str(row.get("dest") or "")
        port = row.get("port")
        if not dest:
            continue
        where = f"{dest}:{port}" if port else dest
        score = float(row.get("score") or 0.0)
        confidence_word = str(row.get("confidence") or "").lower()

        reasons = [str(r) for r in (row.get("reasons") or []) if str(r).strip()]
        metrics = row.get("metrics") or {}

        out.append(
            Finding(
                id=f"beaconhunt:{where}",
                title=f"Possible C2 beaconing to {where}",
                severity=_beacon_severity(score, confidence_word),
                provenance=Provenance.IMPORTED,
                category="c2",
                description=(
                    f"{int(row.get('count') or 0)} connection(s) to {where} scored "
                    f"{score:.1f} on interval regularity, jitter, autocorrelation, "
                    "payload constancy and span."
                ),
                evidence="; ".join(reasons),
                location=where,
                cwe=list(_BEACON_CWE),
                confidence=_beacon_confidence(confidence_word),
                remediation=[
                    "Confirm the destination is legitimate; check with the process owner "
                    "before blocking.",
                    "If unsanctioned, block the destination at egress and identify the "
                    "process on the host making the connections.",
                    "Capture a packet sample for the record before blocking — the beacon "
                    "pattern is the evidence.",
                ],
                tool="beaconhunt",
                target=where,
                observed_at=observed_at,
                extra={"score": score, "metrics": metrics, "sample_count": row.get("count")},
            )
        )

    return out


def _beacon_severity(score: float, confidence: str) -> Severity:
    """Map the tool's 0-100 score onto a band.

    Deliberately conservative at the top: beaconing is an inference, not an
    observation of compromise, so only a near-perfect score earns CRITICAL.
    """
    if score >= 85 and confidence.startswith("high"):
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    return Severity.LOW


def _beacon_confidence(confidence: str) -> Confidence:
    if confidence.startswith("high"):
        return Confidence.HIGH
    if confidence.startswith("low"):
        return Confidence.LOW
    return Confidence.MEDIUM


# --------------------------------------------------------------------------- #
# spydetect — host surveillance detector                                      #
# --------------------------------------------------------------------------- #


def to_spydetect(payload: Any, *, target: str = "", now: Optional[str] = None) -> List[Finding]:
    """Convert ``spydetect --json`` output.

    ``severity == "clean"`` is the tool saying "nothing here". It is dropped
    rather than converted to INFO, because an INFO finding counts as a result
    and would make a clean host look like it had findings.
    """
    rows = payload if isinstance(payload, list) else [payload]
    out: List[Finding] = []
    observed_at = now or _utcnow()

    for row in rows:
        if not isinstance(row, dict):
            continue
        severity_word = str(row.get("severity") or "").strip().lower()
        if severity_word in ("clean", "none", ""):
            continue

        name = str(row.get("name") or "unknown")
        pid = row.get("pid")
        score = float(row.get("score") or 0.0)
        where = f"pid {pid} ({name})" if pid is not None else name
        reasons = [str(r) for r in (row.get("reasons") or []) if str(r).strip()]

        out.append(
            Finding(
                id=f"spydetect:{pid}:{name}",
                title=f"Suspicious host process: {name}",
                severity=Severity.parse(severity_word),
                provenance=Provenance.IMPORTED,
                category="surveillance",
                description=(
                    f"Process {name} scored {score:.1f}. "
                    + ("Signals: " + "; ".join(reasons) if reasons else "No signals recorded.")
                ),
                evidence="; ".join(reasons),
                location=where,
                cwe=["CWE-506"],  # embedded malicious functionality
                confidence=Confidence.MEDIUM,
                remediation=[
                    "Verify the binary's origin and signature before acting; a high score "
                    "is triage, not a verdict.",
                    "If it is confirmed unwanted, isolate the host and image it before "
                    "removing anything.",
                    "Check whether the process holds a camera or microphone device handle "
                    "and whether it has an outbound connection.",
                ],
                tool="spydetect",
                target=target or where,
                observed_at=observed_at,
                extra={"pid": pid, "score": score, "metrics": row.get("metrics") or {}},
            )
        )

    return out


# --------------------------------------------------------------------------- #
# ForgeGuard — the app's own report shape                                     #
# --------------------------------------------------------------------------- #


def from_forgeguard(
    payload: Any,
    *,
    target: str = "",
    provenance: Provenance = Provenance.SIMULATED,
    now: Optional[str] = None,
) -> List[Finding]:
    """Convert a ForgeGuard ``ScanReport.findings`` array.

    ``provenance`` is a required-ish decision, not a default anyone can forget:
    it defaults to SIMULATED because ForgeGuard's synthetic generator emits
    this exact shape. Callers running against the real engine must pass
    ``Provenance.OBSERVED`` explicitly. Getting that backwards should be a
    deliberate act, not an oversight.
    """
    if isinstance(payload, dict):
        rows = payload.get("findings") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []

    out: List[Finding] = []
    observed_at = now or _utcnow()

    for raw in rows:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("attack") or raw.get("summary") or "Finding")
        remediation = list(raw.get("remediation_suggestions") or [])
        if not remediation and raw.get("remediation"):
            remediation = [str(raw["remediation"])]
        poc = raw.get("proof_of_concept") or {}

        out.append(
            Finding(
                id=str(raw.get("id") or ""),
                title=title,
                severity=Severity.parse(raw.get("severity")),
                provenance=provenance,
                category=str(raw.get("family") or "general"),
                description=str(raw.get("summary") or raw.get("rationale") or ""),
                evidence=str(raw.get("evidence") or ""),
                location=str(raw.get("attack") or ""),
                cwe=[str(c) for c in (raw.get("cwe_references") or [])],
                cvss=raw.get("cvss") if isinstance(raw.get("cvss"), (int, float)) else None,
                confidence=Confidence.MEDIUM,
                remediation=[str(r) for r in remediation if str(r).strip()],
                tool="forgeguard",
                target=target,
                observed_at=str(raw.get("observed_at") or observed_at),
                extra={
                    k: v
                    for k, v in (("proof_of_concept", poc), ("ale_usd", raw.get("ale_usd")))
                    if v
                },
            )
        )

    return out


# --------------------------------------------------------------------------- #
# Registry                                                                     #
# --------------------------------------------------------------------------- #

ADAPTERS: Dict[str, Callable[..., List[Finding]]] = {
    "certwatch": to_certwatch,
    "beaconhunt": to_beaconhunt,
    "spydetect": to_spydetect,
    "forgeguard": from_forgeguard,
}


def convert(tool: str, payload: Any, **kwargs: Any) -> List[Finding]:
    """Look up an adapter by tool name and run it.

    Raises KeyError with the known names rather than silently returning [] —
    an unknown tool should not look like a clean scan.
    """
    try:
        adapter = ADAPTERS[tool]
    except KeyError:
        raise KeyError(
            f"no adapter for {tool!r}; known adapters: {sorted(ADAPTERS)}"
        ) from None
    return adapter(payload, **kwargs)


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
