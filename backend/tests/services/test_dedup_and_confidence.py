from app.models.enums import Severity
from app.scanners.base import NormalizedFinding, compute_normalized_fingerprint
from app.services.confidence import adjust_confidence
from app.services.dedup import deduplicate_findings


def test_deduplicate_same_scanner_duplicates():
    fp = compute_normalized_fingerprint(
        cve="CVE-2019-10744", package_name="lodash", title="Prototype Pollution"
    )
    f1 = NormalizedFinding(
        title="Prototype Pollution in lodash",
        description="Reported by npm #1",
        severity=Severity.HIGH,
        confidence=0.7,
        scanner_name="npm-audit",
        cve="CVE-2019-10744",
        package_name="lodash",
        raw_data={"occ": 1},
        normalized_fingerprint=fp,
    )
    f2 = NormalizedFinding(
        title="Prototype Pollution in lodash",
        description="Reported by npm #2",
        severity=Severity.HIGH,
        confidence=0.7,
        scanner_name="npm-audit",
        cve="CVE-2019-10744",
        package_name="lodash",
        raw_data={"occ": 2},
        normalized_fingerprint=fp,
    )
    result = deduplicate_findings([f1, f2])
    assert len(result) == 1
    assert result[0].confidence == 0.7
    assert len(result[0].evidences) == 2


def test_deduplicate_cross_scanner_preserves_both():
    fp = compute_normalized_fingerprint(
        cve="CVE-2019-10744", package_name="lodash", title="Prototype Pollution"
    )
    f1 = NormalizedFinding(
        title="Prototype Pollution in lodash",
        description="Reported by npm",
        severity=Severity.HIGH,
        confidence=0.7,
        scanner_name="npm-audit",
        cve="CVE-2019-10744",
        package_name="lodash",
        normalized_fingerprint=fp,
    )
    f2 = NormalizedFinding(
        title="Prototype Pollution in lodash",
        description="Reported by trivy",
        severity=Severity.HIGH,
        confidence=0.7,
        scanner_name="trivy",
        cve="CVE-2019-10744",
        package_name="lodash",
        normalized_fingerprint=fp,
    )
    result = deduplicate_findings([f1, f2])
    assert len(result) == 2


def test_adjust_confidence_cve():
    f = NormalizedFinding(
        title="Vulnerability",
        description="Desc",
        severity=Severity.HIGH,
        confidence=0.5,
        scanner_name="semgrep",
        cve="CVE-2023-1234",
    )
    adjusted = adjust_confidence([f])
    assert adjusted[0].confidence == 0.7


def test_adjust_confidence_cap():
    f = NormalizedFinding(
        title="Vulnerability",
        description="Desc",
        severity=Severity.CRITICAL,
        confidence=0.9,
        scanner_name="trivy",
        cve="CVE-2023-1234",
    )
    adjusted = adjust_confidence([f])
    assert adjusted[0].confidence == 1.0  # Capped at 1.0
