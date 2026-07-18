from ptflow.core import evidence


def test_normalize_finding_maps_class_confidence_and_references():
    finding = evidence.normalize_finding(
        finding_id="f-1",
        category="dast",
        record={
            "template-id": "reflected-xss",
            "confidence": "high",
            "scanner": "nuclei",
            "request_ref": "scans/app/request.txt",
            "evidence_refs": ["poc/response.txt"],
        },
        target="https://example.test/search",
        source_refs=("findings/dast.jsonl:1",),
    )

    assert finding.class_name == "xss"
    assert finding.confidence == "probable"
    assert finding.detector == "nuclei"
    assert finding.request_ref == "scans/app/request.txt"
    assert finding.evidence_refs == ("findings/dast.jsonl:1", "poc/response.txt")


def test_verified_signal_wins_and_unknown_class_falls_back_to_category():
    finding = evidence.normalize_finding(
        finding_id="f-2",
        category="cve_verified",
        record={"cve": "CVE-2026-1000", "verification": "safe-http"},
        target=None,
    )

    assert finding.class_name == "cve"
    assert finding.confidence == "verified"
    assert evidence.strongest_confidence("lead", "probable") == "probable"


def test_specific_native_type_becomes_class_but_generic_transport_does_not():
    smb = evidence.normalize_finding(
        finding_id="smb-1",
        category="smb",
        record={"type": "smb-signing-disabled", "source": "raw-banner"},
        target="10.0.0.2:445",
    )
    generic = evidence.normalize_finding(
        finding_id="dast-1",
        category="dast",
        record={"type": "http", "template-id": "custom-check"},
        target="https://example.test/",
    )

    assert smb.class_name == "smb-signing-disabled"
    assert smb.detector == "smb"
    assert generic.class_name == "dast"
    assert generic.detector == "nuclei"
