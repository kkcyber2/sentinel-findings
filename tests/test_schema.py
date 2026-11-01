"""Schema, merge and honesty-gate tests."""

from __future__ import annotations

import pytest

from sentinel_findings.schema import (
    Confidence,
    Finding,
    FindingCollection,
    Provenance,
    Severity,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("Crit", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("med", Severity.MEDIUM),
        ("informational", Severity.INFO),
        ("", Severity.INFO),
        (None, Severity.INFO),
        ("banana", Severity.INFO),
    ],
)
def test_severity_parsing(raw, expected):
    assert Severity.parse(raw) is expected


def test_severity_ordering_is_by_rank_not_alphabetical():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    assert Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.INFO.rank < Severity.LOW.rank


def _f(**kw):
    base = dict(
        id="",
        title="TLSv1 is accepted",
        severity=Severity.HIGH,
        provenance=Provenance.OBSERVED,
        category="tls",
        location="example.com:443",
        tool="certwatch",
    )
    base.update(kw)
    return Finding(**base)


def test_fingerprint_stable_across_severity_and_evidence():
    a = _f(severity=Severity.HIGH, evidence="one")
    b = _f(severity=Severity.CRITICAL, evidence="two")
    assert a.fingerprint == b.fingerprint


def test_fingerprint_differs_by_location():
    assert _f(location="a.example.com:443").fingerprint != _f(location="b.example.com:443").fingerprint


def test_dedupe_keeps_worse_severity():
    c = FindingCollection()
    c.add(_f(severity=Severity.MEDIUM))
    c.add(_f(severity=Severity.CRITICAL))
    assert c.total == 1
    assert c.sorted()[0].severity is Severity.CRITICAL


def test_dedupe_merges_remediation_without_duplicates():
    c = FindingCollection()
    c.add(_f(remediation=["Require TLS 1.2", "Retest the listener"]))
    c.add(_f(remediation=["Require TLS 1.2", "Update the LB config"]))
    merged = c.sorted()[0].remediation
    assert merged.count("Require TLS 1.2") == 1
    assert "Update the LB config" in merged


def test_observed_beats_simulated_on_merge():
    c = FindingCollection()
    c.add(_f(provenance=Provenance.SIMULATED))
    c.add(_f(provenance=Provenance.OBSERVED))
    assert c.sorted()[0].provenance is Provenance.OBSERVED
    assert c.is_pure_evidence


def test_counts_always_contains_every_band():
    c = FindingCollection([_f()])
    assert set(c.counts) == {"critical", "high", "medium", "low", "info"}
    assert c.counts["high"] == 1
    assert c.counts["critical"] == 0


def test_empty_collection_counts_are_zero_not_missing():
    c = FindingCollection()
    assert c.total == 0
    assert c.counts["critical"] == 0
    assert c.highest is None


def test_sorting_is_worst_first():
    c = FindingCollection(
        [
            _f(title="low one", severity=Severity.LOW),
            _f(title="crit one", severity=Severity.CRITICAL),
            _f(title="med one", severity=Severity.MEDIUM),
        ]
    )
    order = [f.title for f in c.sorted()]
    assert order[0] == "crit one"
    assert order[-1] == "low one"


def test_pure_evidence_collection_passes_gate():
    c = FindingCollection([_f(provenance=Provenance.OBSERVED)])
    c.assert_reportable()
    assert c.is_pure_evidence


def test_simulated_collection_is_refused_by_gate():
    c = FindingCollection([_f(provenance=Provenance.SIMULATED)])
    assert c.simulated_count == 1
    assert not c.is_pure_evidence
    with pytest.raises(ValueError, match="simulated"):
        c.assert_reportable()


def test_unknown_provenance_is_refused_by_gate():
    c = FindingCollection([_f(provenance=Provenance.UNKNOWN)])
    assert c.unknown_provenance_count == 1
    with pytest.raises(ValueError, match="unknown provenance"):
        c.assert_reportable()


def test_empty_collection_cannot_be_reported():
    with pytest.raises(ValueError, match="empty"):
        FindingCollection().assert_reportable()


def test_mixed_collection_reports_which_are_simulated():
    c = FindingCollection(
        [
            _f(title="real", provenance=Provenance.OBSERVED),
            _f(title="fake", provenance=Provenance.SIMULATED),
        ]
    )
    assert not c.is_pure_evidence
    with pytest.raises(ValueError):
        c.assert_reportable()


def test_filter_by_provenance_can_make_a_set_reportable():
    c = FindingCollection(
        [
            _f(title="real", provenance=Provenance.OBSERVED, location="a:443"),
            _f(title="fake", provenance=Provenance.SIMULATED, location="b:443"),
        ]
    )
    clean = c.filter(provenance=Provenance.OBSERVED)
    clean.assert_reportable()
    assert clean.total == 1


def test_round_trip_preserves_fields_and_provenance():
    original = FindingCollection(
        [
            _f(
                severity=Severity.MEDIUM,
                provenance=Provenance.IMPORTED,
                cwe=["CWE-326"],
                cvss=5.3,
                confidence=Confidence.LOW,
                remediation=["Do the thing"],
                extra={"custom": 42},
            )
        ]
    )
    revived = FindingCollection.from_dict(original.to_dict())
    f = revived.sorted()[0]
    assert f.severity is Severity.MEDIUM
    assert f.provenance is Provenance.IMPORTED
    assert f.cvss == 5.3
    assert f.confidence is Confidence.LOW
    assert f.extra["custom"] == 42
    assert f.cwe == ["CWE-326"]


def test_unknown_keys_survive_round_trip():
    data = FindingCollection([_f()]).to_dict()
    data["findings"][0]["something_new"] = "kept"
    revived = FindingCollection.from_dict(data)
    assert revived.sorted()[0].extra["something_new"] == "kept"


def test_cvss_out_of_range_rejected():
    with pytest.raises(ValueError, match="cvss"):
        _f(cvss=11.0)


def test_forgeguard_projection_uses_its_field_names():
    f = _f(remediation=["A", "B"], cwe=["CWE-326"], cvss=7.4)
    out = f.to_forgeguard()
    assert out["attack"] == f.title
    assert out["family"] == "tls"
    assert out["cwe_references"] == ["CWE-326"]
    assert out["remediation_suggestions"] == ["A", "B"]
    assert out["verdict"] is True


def test_forgeguard_projection_marks_simulated_not_a_verdict():
    out = _f(provenance=Provenance.SIMULATED).to_forgeguard()
    assert out["verdict"] is False
