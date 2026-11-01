"""Adapter tests, run against the shapes the tools actually emit.

Each fixture mirrors a real tool's ``to_dict``/``as_dict`` output, read from
that tool's source rather than invented.
"""

from __future__ import annotations

import pytest

from sentinel_findings.adapters import (
    ADAPTERS,
    convert,
    from_forgeguard,
    to_beaconhunt,
    to_certwatch,
    to_spydetect,
)
from sentinel_findings.schema import FindingCollection, Provenance, Severity

CERTWATCH = [
    {
        "host": "example.com",
        "port": 443,
        "reachable": True,
        "error": "",
        "protocols": {"TLSv1": True},
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "weak_ciphers_accepted": [],
        "cert": {"issuer": "CN=R3", "days_remaining": 74, "key_bits": 2048},
        "findings": [
            {
                "id": "ssl-v3",
                "title": "SSLv3 is accepted",
                "severity": "critical",
                "detail": "Server completes an SSLv3 handshake.",
                "remediation": "Disable SSLv3 on the listener.",
            },
            {
                "id": "cert-expiring",
                "title": "Certificate expires soon",
                "severity": "medium",
                "detail": "74 days remaining.",
                "remediation": "Renew before expiry.",
            },
        ],
    }
]


def test_certwatch_converts_both_findings():
    out = to_certwatch(CERTWATCH)
    assert len(out) == 2
    assert {f.severity for f in out} == {Severity.CRITICAL, Severity.MEDIUM}


def test_certwatch_location_includes_port():
    assert to_certwatch(CERTWATCH)[0].location == "example.com:443"


def test_certwatch_maps_cwe_for_known_ids():
    out = to_certwatch(CERTWATCH, target="example.com")
    by_id = {f.title: f for f in out}
    assert by_id["SSLv3 is accepted"].cwe == ["CWE-327"]


def test_certwatch_metadata_goes_to_extra_not_lost():
    f = to_certwatch(CERTWATCH)[0]
    assert f.extra["negotiated_protocol"] == "TLSv1.3"
    assert f.extra["cert_days_remaining"] == 74


def test_certwatch_provenance_is_imported_not_observed():
    assert all(f.provenance is Provenance.IMPORTED for f in to_certwatch(CERTWATCH))


def test_certwatch_accepts_bare_finding_list():
    bare = [{"id": "weak-key", "title": "RSA-1024", "severity": "high", "detail": "x"}]
    out = to_certwatch(bare)
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH


def test_certwatch_empty_findings_yields_nothing():
    assert to_certwatch([{"host": "a", "port": 443, "findings": []}]) == []


BEACON = [
    {
        "dest": "203.0.113.9",
        "port": 443,
        "count": 62,
        "score": 91.0,
        "confidence": "high",
        "reasons": ["interval regularity 0.98", "jitter MAD 0.4s"],
        "metrics": {"cv": 0.012, "mad": 0.4},
    },
    {
        "dest": "198.51.100.4",
        "port": 8080,
        "count": 20,
        "score": 48.0,
        "confidence": "medium",
        "reasons": ["moderate regularity"],
        "metrics": {"cv": 0.2},
    },
]


def test_beaconhunt_converts_all_rows():
    assert len(to_beaconhunt(BEACON)) == 2


def test_beaconhunt_score_maps_to_severity():
    out = {f.location: f for f in to_beaconhunt(BEACON)}
    assert out["203.0.113.9:443"].severity is Severity.CRITICAL
    assert out["198.51.100.4:8080"].severity is Severity.MEDIUM


def test_beaconhunt_high_score_without_high_confidence_is_not_critical():
    row = dict(BEACON[0], confidence="medium")
    assert to_beaconhunt([row])[0].severity is Severity.HIGH


def test_beaconhunt_keeps_reasons_as_evidence():
    f = to_beaconhunt(BEACON)[0]
    assert "interval regularity" in f.evidence
    assert f.extra["metrics"]["cv"] == 0.012


def test_beaconhunt_confidence_word_maps():
    from sentinel_findings.schema import Confidence

    out = {f.location: f for f in to_beaconhunt(BEACON)}
    assert out["203.0.113.9:443"].confidence is Confidence.HIGH


SPY = [
    {
        "pid": 4821,
        "name": "mspy-agent",
        "score": 100.0,
        "severity": "critical",
        "reasons": ["known stalkerware family name"],
        "metrics": {"entropy": 2.1},
    },
    {
        "pid": 99,
        "name": "bash",
        "score": 0.0,
        "severity": "clean",
        "reasons": [],
        "metrics": {},
    },
]


def test_spydetect_drops_clean_rows():
    out = to_spydetect(SPY)
    assert len(out) == 1
    assert out[0].title.endswith("mspy-agent")


def test_spydetect_location_is_pid_and_name():
    assert to_spydetect(SPY)[0].location == "pid 4821 (mspy-agent)"


def test_spydetect_severity_preserved():
    assert to_spydetect(SPY)[0].severity is Severity.CRITICAL


def test_spydetect_all_clean_yields_empty():
    assert to_spydetect([SPY[1]]) == []


FORGEGUARD = {
    "findings": [
        {
            "id": "a1",
            "attack": "system_prompt_extraction",
            "family": "extraction",
            "severity": "high",
            "cvss": 7.1,
            "summary": "Model echoed its system prompt.",
            "evidence": "You are a helpful assistant...",
            "cwe_references": ["CWE-200"],
            "remediation_suggestions": ["Add a refusal."],
        }
    ]
}


def test_forgeguard_defaults_to_simulated():
    out = from_forgeguard(FORGEGUARD)
    assert out[0].provenance is Provenance.SIMULATED


def test_forgeguard_can_be_marked_observed_explicitly():
    out = from_forgeguard(FORGEGUARD, provenance=Provenance.OBSERVED)
    assert out[0].provenance is Provenance.OBSERVED


def test_forgeguard_field_mapping():
    f = from_forgeguard(FORGEGUARD)[0]
    assert f.title == "system_prompt_extraction"
    assert f.category == "extraction"
    assert f.cvss == 7.1
    assert f.cwe == ["CWE-200"]
    assert f.remediation == ["Add a refusal."]


def test_forgeguard_single_remediation_string_becomes_list():
    row = dict(FORGEGUARD["findings"][0])
    row.pop("remediation_suggestions")
    row["remediation"] = "Do the single thing"
    assert from_forgeguard([row])[0].remediation == ["Do the single thing"]


def test_registry_has_every_adapter():
    assert set(ADAPTERS) == {"certwatch", "beaconhunt", "spydetect", "forgeguard"}


def test_unknown_tool_raises_with_the_known_list():
    with pytest.raises(KeyError, match="no adapter"):
        convert("nmap", [])


def test_end_to_end_mixed_sources_dedupe_and_count():
    c = FindingCollection()
    c.extend(to_certwatch(CERTWATCH))
    c.extend(to_beaconhunt(BEACON))
    c.extend(to_spydetect(SPY))
    c.extend(from_forgeguard(FORGEGUARD))
    assert c.total == 2 + 2 + 1 + 1
    assert c.counts["critical"] == 3
    assert c.simulated_count == 1
    assert not c.is_pure_evidence
