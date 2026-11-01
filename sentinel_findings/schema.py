"""The canonical finding.

Every scanner speaks its own dialect. certwatch says ``{"id": "ssl-v3",
"detail": ...}``; beaconhunt says ``{"dest": ..., "score": 78.4}``; spydetect
says ``{"pid": 1234, "name": ..., "severity": "high"}``. A report renderer that
consumes any of those directly is welded to that scanner forever.

This module defines the one shape everything is converted into, so the renderer
never learns a scanner's name and the scanners never learn the report's.

The second job of this module is honesty. ``Provenance`` travels with every
finding from the moment it is created to the moment it is rendered, and the
collection refuses to be silently mixed. A simulated finding cannot become a
real one by omission, because there is no code path that drops the field.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class Severity(str, Enum):
    """Five bands, matching ForgeGuard's existing ``Finding.severity`` union."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is worse. Used for sorting and for dedupe tie-breaks."""
        return _RANK[self]

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        """Accept what real scanners actually emit.

        Handles ``"CRITICAL"``, ``"Critical"``, ``"crit"``, ``"med"``,
        ``Severity.HIGH`` and ``None``. Unknown text becomes ``INFO`` rather
        than raising: a scanner that invents a severity band should not crash
        a report run, but it also should not be able to claim ``CRITICAL`` by
        being unparseable.
        """
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.INFO
        text = str(value).strip().lower()
        if not text:
            return cls.INFO
        for sev in cls:
            if text == sev.value:
                return sev
        return _ALIASES.get(text, cls.INFO)


_RANK: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_ALIASES: Dict[str, Severity] = {
    "crit": Severity.CRITICAL,
    "c": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "high": Severity.HIGH,
    "h": Severity.HIGH,
    "important": Severity.HIGH,
    "med": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "m": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "l": Severity.LOW,
    "minor": Severity.LOW,
    "note": Severity.INFO,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "none": Severity.INFO,
}


class Provenance(str, Enum):
    """Where a finding came from. This is the honesty layer.

    OBSERVED   a real check touched a real target and saw this.
    SIMULATED  a generator produced this. It may be shaped exactly like a real
               finding and it is still not evidence.
    IMPORTED   converted from another tool's stored output; the original tool
               observed it, this pipeline did not re-run it.
    UNKNOWN    nobody recorded the source. Rendered as a warning.
    """

    OBSERVED = "observed"
    SIMULATED = "simulated"
    IMPORTED = "imported"
    UNKNOWN = "unknown"

    @property
    def is_evidence(self) -> bool:
        """Only observations may be presented as facts about a target."""
        return self in (Provenance.OBSERVED, Provenance.IMPORTED)


class Confidence(str, Enum):
    """How sure the *producing tool* was, independent of severity.

    Kept separate from severity on purpose: a critical-severity finding at low
    confidence is a lead, and a medium at high confidence is a fix. Collapsing
    the two is how reports end up either alarmist or useless.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def parse(cls, value: Any) -> "Confidence":
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        if text in ("high", "h", "certain", "confirmed"):
            return cls.HIGH
        if text in ("low", "l", "speculative", "weak"):
            return cls.LOW
        return cls.MEDIUM


@dataclass
class Finding:
    """One normalised result.

    Field names follow ForgeGuard's ``Finding`` interface where one exists so
    that ``to_forgeguard()`` is a rename-free mapping rather than a translation.
    """

    id: str
    title: str
    severity: Severity = Severity.INFO
    provenance: Provenance = Provenance.UNKNOWN

    # What it is
    category: str = "general"
    description: str = ""
    evidence: str = ""
    location: str = ""

    # Classification
    cwe: List[str] = field(default_factory=list)
    cve: List[str] = field(default_factory=list)
    cvss: Optional[float] = None

    # How sure, and how to fix
    confidence: Confidence = Confidence.MEDIUM
    remediation: List[str] = field(default_factory=list)

    # Provenance detail
    tool: str = ""
    tool_version: str = ""
    target: str = ""
    observed_at: str = ""

    # Anything the producing tool said that has no canonical home. Never
    # rendered by default; kept so information is not destroyed on conversion.
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if not isinstance(self.provenance, Provenance):
            self.provenance = Provenance(str(self.provenance).strip().lower())
        self.confidence = Confidence.parse(self.confidence)
        self.cwe = [str(c).strip() for c in self.cwe if str(c).strip()]
        self.cve = [str(c).strip() for c in self.cve if str(c).strip()]
        self.remediation = [str(r).strip() for r in self.remediation if str(r).strip()]
        if self.cvss is not None:
            score = float(self.cvss)
            if not 0.0 <= score <= 10.0:
                raise ValueError(f"cvss {score} outside 0.0-10.0")
            self.cvss = round(score, 1)
        if not self.id:
            self.id = self.fingerprint

    # ------------------------------------------------------------------ #
    # Identity                                                           #
    # ------------------------------------------------------------------ #

    @property
    def fingerprint(self) -> str:
        """Stable across runs, so re-scanning the same target dedupes.

        Deliberately excludes severity and evidence: if a check reports the
        same defect twice with different wording, that is one defect.
        """
        basis = "|".join(
            [
                _slug(self.tool),
                _slug(self.category),
                _slug(self.title),
                _slug(self.location),
                ",".join(sorted(self.cwe)),
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------ #
    # Serialisation                                                      #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "provenance": self.provenance.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "cwe": list(self.cwe),
            "cve": list(self.cve),
            "cvss": self.cvss,
            "confidence": self.confidence.value,
            "remediation": list(self.remediation),
            "tool": self.tool,
            "tool_version": self.tool_version,
            "target": self.target,
            "observed_at": self.observed_at,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}
        payload = {k: v for k, v in data.items() if k in known}
        extra = dict(data.get("extra") or {})
        # Preserve unknown keys rather than dropping them.
        for key, value in data.items():
            if key not in known and key != "extra":
                extra.setdefault(key, value)
        payload["extra"] = extra
        # Every required field is defaulted here. Third-party output and
        # hand-written fixtures never carry an id, and requiring one turned a
        # perfectly readable finding file into a TypeError.
        payload.setdefault("id", "")
        payload.setdefault("title", "")
        payload.setdefault("severity", Severity.MEDIUM)
        payload.setdefault("provenance", Provenance.OBSERVED)
        return cls(**payload)

    def to_forgeguard(self) -> Dict[str, Any]:
        """Project onto ForgeGuard's ``Finding`` interface.

        ``remediation_suggestions`` is a list there too, and ``attack`` is the
        human label the report component prints as the finding name.
        """
        return {
            "id": self.id,
            "attack": self.title,
            "family": self.category,
            "severity": self.severity.value,
            "cvss": self.cvss if self.cvss is not None else 0.0,
            "summary": self.description,
            "evidence": self.evidence,
            "cwe_references": list(self.cwe),
            "remediation": self.remediation[0] if self.remediation else None,
            "remediation_suggestions": list(self.remediation),
            "verdict": self.provenance is Provenance.OBSERVED,
            "observed_at": self.observed_at or None,
        }

    def with_severity(self, severity: Severity) -> "Finding":
        return replace(self, severity=Severity.parse(severity))


def _slug(text: str) -> str:
    """Lowercase, collapse runs of non-alphanumerics to one dash."""
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").strip().lower()).strip("-")


class FindingCollection:
    """An ordered set of findings with the operations a report needs.

    Additions that share a fingerprint are merged: the higher severity wins,
    remediation lists union, and any observed provenance beats a simulated one.
    That last rule matters — if a real check confirms something a simulation
    guessed at, the result is evidence, not a guess.
    """

    def __init__(self, findings: Optional[Iterable[Finding]] = None) -> None:
        self._items: Dict[str, Finding] = {}
        if findings:
            self.extend(findings)

    # ------------------------------------------------------------------ #
    # Mutation                                                           #
    # ------------------------------------------------------------------ #

    def add(self, finding: Finding) -> Finding:
        existing = self._items.get(finding.fingerprint)
        if existing is None:
            self._items[finding.fingerprint] = finding
            return finding
        merged = _merge(existing, finding)
        self._items[finding.fingerprint] = merged
        return merged

    def extend(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.add(finding)

    # ------------------------------------------------------------------ #
    # Access                                                             #
    # ------------------------------------------------------------------ #

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self.sorted())

    def sorted(self) -> List[Finding]:
        """Worst first, then by confidence, then by title for stability."""
        return sorted(
            self._items.values(),
            key=lambda f: (
                -f.severity.rank,
                -_CONF_RANK[f.confidence],
                f.title.lower(),
                f.location,
            ),
        )

    def filter(
        self,
        *,
        min_severity: Optional[Severity] = None,
        provenance: Optional[Provenance] = None,
        tool: Optional[str] = None,
    ) -> "FindingCollection":
        out = FindingCollection()
        floor = min_severity.rank if min_severity else None
        for finding in self._items.values():
            if floor is not None and finding.severity.rank < floor:
                continue
            if provenance is not None and finding.provenance is not provenance:
                continue
            if tool is not None and finding.tool != tool:
                continue
            out.add(finding)
        return out

    # ------------------------------------------------------------------ #
    # Aggregate properties                                               #
    # ------------------------------------------------------------------ #

    @property
    def counts(self) -> Dict[str, int]:
        """Every band always present, so a report never renders a blank cell."""
        tally = {sev.value: 0 for sev in Severity}
        for finding in self._items.values():
            tally[finding.severity.value] += 1
        return tally

    @property
    def total(self) -> int:
        return len(self._items)

    @property
    def simulated_count(self) -> int:
        return sum(
            1 for f in self._items.values() if f.provenance is Provenance.SIMULATED
        )

    @property
    def unknown_provenance_count(self) -> int:
        return sum(
            1 for f in self._items.values() if f.provenance is Provenance.UNKNOWN
        )

    @property
    def highest(self) -> Optional[Severity]:
        if not self._items:
            return None
        return max((f.severity for f in self._items.values()), key=lambda s: s.rank)

    @property
    def is_pure_evidence(self) -> bool:
        """True only when every finding came from a real check."""
        return self.total > 0 and all(
            f.provenance.is_evidence for f in self._items.values()
        )

    def assert_reportable(self) -> None:
        """Refuse to let a simulated or unsourced set be shipped as an audit.

        Call this from anything that produces a client-facing document. It is
        the one gate that makes "we never silently returned fake results" a
        property of the code rather than a promise in a README.
        """
        if self.total == 0:
            raise ValueError("empty collection cannot be reported")
        simulated = [f.id for f in self._items.values() if f.provenance is Provenance.SIMULATED]
        if simulated:
            raise ValueError(
                f"{len(simulated)} simulated finding(s) in a client report; "
                f"filter them out or acknowledge explicitly. ids={simulated[:5]}"
            )
        unsourced = [
            f.id for f in self._items.values() if f.provenance is Provenance.UNKNOWN
        ]
        if unsourced:
            raise ValueError(
                f"{len(unsourced)} finding(s) with unknown provenance; "
                f"ids={unsourced[:5]}"
            )

    # ------------------------------------------------------------------ #
    # Serialisation                                                      #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "sentinel-findings/1",
            "counts": self.counts,
            "total": self.total,
            "simulated_count": self.simulated_count,
            "findings": [f.to_dict() for f in self.sorted()],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FindingCollection":
        if isinstance(data, list):
            rows = data
        else:
            rows = data.get("findings") or []
        return cls(Finding.from_dict(row) for row in rows)


_CONF_RANK: Dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}

_PROV_RANK: Dict[Provenance, int] = {
    Provenance.UNKNOWN: 0,
    Provenance.SIMULATED: 1,
    Provenance.IMPORTED: 2,
    Provenance.OBSERVED: 3,
}


def _merge(a: Finding, b: Finding) -> Finding:
    """Combine two findings that share a fingerprint.

    Severity takes the worse of the two (a defect does not become safer because
    a second tool was less impressed). Provenance takes the stronger evidence.
    """
    stronger = b if _PROV_RANK[b.provenance] > _PROV_RANK[a.provenance] else a
    worse = b if b.severity.rank > a.severity.rank else a

    remediation: List[str] = []
    for step in list(a.remediation) + list(b.remediation):
        if step not in remediation:
            remediation.append(step)

    evidence_parts = [e for e in (a.evidence, b.evidence) if e]
    evidence = evidence_parts[0] if len(evidence_parts) == 1 else "\n".join(
        dict.fromkeys(evidence_parts)
    )

    merged = replace(
        stronger,
        severity=worse.severity,
        remediation=remediation,
        evidence=evidence,
        cwe=list(dict.fromkeys(a.cwe + b.cwe)),
        cve=list(dict.fromkeys(a.cve + b.cve)),
        cvss=max(
            (c for c in (a.cvss, b.cvss) if c is not None), default=None
        ),
        extra={**a.extra, **b.extra},
    )
    return merged
