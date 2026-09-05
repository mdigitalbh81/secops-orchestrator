"""Tests for finding disposition service and related functionality."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.disposition import FindingDisposition
from app.models.enums import (
    EvidenceLevel,
    FindingStatus,
    RiskGate,
    ScanStatus,
    Severity,
)
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.scanners.base import NormalizedFinding
from app.services.finding_disposition import (
    NON_ACTIONABLE,
    PERSISTENT_STATUSES,
    apply_dispositions_to_findings,
    compute_risk_gate_with_dispositions,
    effective_status,
    get_disposition_history,
    get_finding_disposition,
    is_actionable,
    resolve_dispositions_batch,
    resolve_expired_dispositions,
    set_disposition,
)

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

async def _make_project(db: AsyncSession, name: str = "TestProject") -> Project:
    p = Project(name=name)
    db.add(p)
    await db.flush()
    return p


async def _make_scan(
    db: AsyncSession,
    project: Project,
    risk_gate: RiskGate = RiskGate.PASS,
) -> Scan:
    s = Scan(
        project_id=project.id,
        source_path="/tmp/test",
        status=ScanStatus.COMPLETED,
        risk_gate=risk_gate,
    )
    db.add(s)
    await db.flush()
    return s


async def _make_finding(
    db: AsyncSession,
    scan: Scan,
    *,
    scanner_name: str = "semgrep",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    evidence_level: EvidenceLevel = EvidenceLevel.SINGLE_SOURCE,
    normalized_fingerprint: str = "fp_abc123",
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    f = Finding(
        scan_id=scan.id,
        scanner_name=scanner_name,
        title="Test Finding",
        description="A test finding",
        severity=severity,
        confidence=confidence,
        evidence_level=evidence_level,
        raw_fingerprint=f"raw|{scanner_name}|{normalized_fingerprint}",
        normalized_fingerprint=normalized_fingerprint,
        status=status,
    )
    db.add(f)
    await db.flush()
    return f


def _nf(
    scanner_name: str = "semgrep",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    normalized_fingerprint: str = "fp_abc123",
    evidence_level: EvidenceLevel = EvidenceLevel.SINGLE_SOURCE,
) -> NormalizedFinding:
    return NormalizedFinding(
        title="Test",
        description="desc",
        severity=severity,
        confidence=confidence,
        scanner_name=scanner_name,
        evidence_level=evidence_level,
        raw_fingerprint=f"raw|{scanner_name}|{normalized_fingerprint}",
        normalized_fingerprint=normalized_fingerprint,
    )


# ==================================================================
# ENUM
# ==================================================================

class TestEnum:
    def test_accepted_by_design_exists(self):
        assert FindingStatus.ACCEPTED_BY_DESIGN == "ACCEPTED_BY_DESIGN"

    def test_all_statuses(self):
        expected = {"OPEN", "FIXED", "FALSE_POSITIVE", "ACCEPTED_RISK", "ACCEPTED_BY_DESIGN"}
        actual = {s.value for s in FindingStatus}
        assert expected == actual


# ==================================================================
# SERVICE — basic disposition lifecycle
# ==================================================================

class TestDispositionService:
    @pytest.mark.asyncio
    async def test_create_disposition(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj, RiskGate.BLOCKED)
        finding = await _make_finding(db_session, scan)

        f, disp, event, gate = await set_disposition(
            db_session, finding, FindingStatus.ACCEPTED_BY_DESIGN,
            "Intentional by design", "felipe.reis",
        )
        assert f.status == FindingStatus.ACCEPTED_BY_DESIGN
        assert disp is not None
        assert disp.status == FindingStatus.ACCEPTED_BY_DESIGN
        assert event.previous_status == FindingStatus.OPEN
        assert event.new_status == FindingStatus.ACCEPTED_BY_DESIGN
        assert event.actor == "felipe.reis"
        assert gate == RiskGate.PASS  # only finding, now non-actionable

    @pytest.mark.asyncio
    async def test_update_disposition(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)

        await set_disposition(
            db_session, finding, FindingStatus.FALSE_POSITIVE,
            "FP confirmed", "analyst1",
        )
        _, disp2, event2, _ = await set_disposition(
            db_session, finding, FindingStatus.ACCEPTED_RISK,
            "Actually accepted risk", "analyst2",
        )
        assert disp2.status == FindingStatus.ACCEPTED_RISK
        assert event2.previous_status == FindingStatus.FALSE_POSITIVE
        assert event2.new_status == FindingStatus.ACCEPTED_RISK

    @pytest.mark.asyncio
    async def test_reopen_removes_disposition(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)

        await set_disposition(
            db_session, finding, FindingStatus.ACCEPTED_RISK,
            "Accepted", "actor1",
        )
        f, disp, event, _ = await set_disposition(
            db_session, finding, FindingStatus.OPEN,
            "Reopening", "actor2",
        )
        assert f.status == FindingStatus.OPEN
        assert disp is None
        assert event.new_status == FindingStatus.OPEN

    @pytest.mark.asyncio
    async def test_fixed_no_persistent_disposition(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)

        _, disp, event, _ = await set_disposition(
            db_session, finding, FindingStatus.FIXED,
            "Patched in v2.1", "dev1",
        )
        assert finding.status == FindingStatus.FIXED
        assert disp is None  # FIXED must NOT create persistent disposition
        assert event.new_status == FindingStatus.FIXED

    @pytest.mark.asyncio
    async def test_audit_trail(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)

        await set_disposition(
            db_session, finding, FindingStatus.FALSE_POSITIVE,
            "FP", "a1",
        )
        await set_disposition(
            db_session, finding, FindingStatus.OPEN,
            "Reopen", "a2",
        )

        history = await get_disposition_history(db_session, finding.id)
        assert len(history) == 2
        assert history[0].previous_status == FindingStatus.OPEN
        assert history[0].new_status == FindingStatus.FALSE_POSITIVE
        assert history[0].actor == "a1"
        assert history[1].previous_status == FindingStatus.FALSE_POSITIVE
        assert history[1].new_status == FindingStatus.OPEN
        assert history[1].actor == "a2"
        # Timestamps are ordered
        assert history[0].created_at <= history[1].created_at

    @pytest.mark.asyncio
    async def test_expiry_auto_reopen(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)

        past = datetime.now(UTC) - timedelta(hours=1)
        # Manually create an expired disposition
        disp = FindingDisposition(
            project_id=proj.id,
            scanner_name=finding.scanner_name,
            normalized_fingerprint=finding.normalized_fingerprint,
            status=FindingStatus.ACCEPTED_RISK,
            justification="Temporary acceptance",
            actor="actor1",
            expires_at=past,
            source_finding_id=finding.id,
        )
        db_session.add(disp)
        await db_session.flush()

        events = await resolve_expired_dispositions(db_session, proj.id)
        assert len(events) == 1
        assert events[0].previous_status == FindingStatus.ACCEPTED_RISK
        assert events[0].new_status == FindingStatus.OPEN
        assert events[0].actor == "system"


# ==================================================================
# RISK ENGINE with dispositions
# ==================================================================


    @pytest.mark.asyncio
    async def test_full_expiry_lifecycle_reverts_scan_risk_gate(self, db_session: AsyncSession):
        """Full lifecycle: T0 BLOCKED -> ACCEPTED_RISK PASS -> Expiry -> BLOCKED + single audit event."""
        proj = await _make_project(db_session, "LifecycleProj")
        scan = await _make_scan(db_session, proj, RiskGate.BLOCKED)
        finding = await _make_finding(
            db_session,
            scan,
            scanner_name="semgrep",
            severity=Severity.HIGH,
            confidence=0.9,
            normalized_fingerprint="fp_lifecycle",
        )

        # 1. Accept risk with future expiry -> gate becomes PASS
        future = datetime.now(UTC) + timedelta(days=7)
        finding, disp, event, gate = await set_disposition(
            session=db_session,
            finding=finding,
            new_status=FindingStatus.ACCEPTED_RISK,
            justification="Temporary exception for release",
            actor="secops-lead",
            expires_at=future,
        )
        assert finding.status == FindingStatus.ACCEPTED_RISK
        assert gate == RiskGate.PASS
        assert scan.risk_gate == RiskGate.PASS

        # 2. Simulate time passage by setting expires_at to past
        past = datetime.now(UTC) - timedelta(hours=2)
        disp.expires_at = past
        await db_session.flush()

        # 3. First resolution
        events = await resolve_expired_dispositions(db_session, proj.id)
        assert len(events) == 1
        assert events[0].previous_status == FindingStatus.ACCEPTED_RISK
        assert events[0].new_status == FindingStatus.OPEN
        assert events[0].actor == "system"
        assert "Auto-reopened: disposition expired" in events[0].justification

        # Verify persistent disposition was removed
        remaining_disp = await get_finding_disposition(db_session, finding)
        assert remaining_disp is None

        # Verify finding status returned to OPEN
        await db_session.refresh(finding)
        assert finding.status == FindingStatus.OPEN

        # Verify scan risk gate reverted to BLOCKED
        await db_session.refresh(scan)
        assert scan.risk_gate == RiskGate.BLOCKED

        # 4. Second resolution -> idempotent, zero new events
        events_second = await resolve_expired_dispositions(db_session, proj.id)
        assert len(events_second) == 0

        # Total history has exactly 2 events: initial ACCEPT + auto OPEN
        history = await get_disposition_history(db_session, finding.id)
        assert len(history) == 2
        assert history[0].new_status == FindingStatus.ACCEPTED_RISK
        assert history[1].new_status == FindingStatus.OPEN
        assert history[1].actor == "system"

class TestRiskEngineWithDispositions:
    def test_open_high_blocks(self):
        findings = [_nf(severity=Severity.HIGH, confidence=0.9)]
        assert compute_risk_gate_with_dispositions(findings) == RiskGate.BLOCKED

    def test_false_positive_high_ignored(self):
        f = _nf(severity=Severity.HIGH, confidence=0.9)
        f.status = FindingStatus.FALSE_POSITIVE  # type: ignore[attr-defined]
        assert compute_risk_gate_with_dispositions([f]) == RiskGate.PASS

    def test_accepted_risk_high_ignored(self):
        f = _nf(severity=Severity.HIGH, confidence=0.9)
        f.status = FindingStatus.ACCEPTED_RISK  # type: ignore[attr-defined]
        assert compute_risk_gate_with_dispositions([f]) == RiskGate.PASS

    def test_accepted_by_design_high_ignored(self):
        f = _nf(severity=Severity.HIGH, confidence=0.9)
        f.status = FindingStatus.ACCEPTED_BY_DESIGN  # type: ignore[attr-defined]
        assert compute_risk_gate_with_dispositions([f]) == RiskGate.PASS

    def test_fixed_ignored(self):
        f = _nf(severity=Severity.HIGH, confidence=0.9)
        f.status = FindingStatus.FIXED  # type: ignore[attr-defined]
        assert compute_risk_gate_with_dispositions([f]) == RiskGate.PASS

    def test_expired_accepted_risk_blocks(self):
        # Finding without status attribute = OPEN (default)
        f = _nf(severity=Severity.HIGH, confidence=0.9)
        assert compute_risk_gate_with_dispositions([f]) == RiskGate.BLOCKED

    def test_zero_actionable_pass(self):
        assert compute_risk_gate_with_dispositions([]) == RiskGate.PASS

    def test_medium_accepted_no_review(self):
        f = _nf(severity=Severity.MEDIUM, confidence=0.8)
        f.status = FindingStatus.ACCEPTED_RISK  # type: ignore[attr-defined]
        assert compute_risk_gate_with_dispositions([f]) == RiskGate.PASS

    def test_mixed_actionable_and_nonactionable(self):
        f1 = _nf(severity=Severity.HIGH, confidence=0.9, normalized_fingerprint="a")
        f1.status = FindingStatus.FALSE_POSITIVE  # type: ignore[attr-defined]
        f2 = _nf(severity=Severity.LOW, confidence=0.5, normalized_fingerprint="b")
        # f2 has no status attr → OPEN
        assert compute_risk_gate_with_dispositions([f1, f2]) == RiskGate.PASS


# ==================================================================
# BATCH RESOLUTION & CARRYOVER
# ==================================================================

class TestBatchResolution:
    @pytest.mark.asyncio
    async def test_same_project_scanner_fingerprint_inherits(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan, normalized_fingerprint="fp1")

        await set_disposition(
            db_session, finding, FindingStatus.FALSE_POSITIVE,
            "Confirmed FP", "analyst",
        )
        await db_session.flush()

        keys = [("semgrep", "fp1")]
        result = await resolve_dispositions_batch(db_session, proj.id, keys)
        assert ("semgrep", "fp1") in result
        assert result[("semgrep", "fp1")].status == FindingStatus.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_different_project_does_not_inherit(self, db_session: AsyncSession):
        proj1 = await _make_project(db_session, "Proj1")
        proj2 = await _make_project(db_session, "Proj2")
        scan1 = await _make_scan(db_session, proj1)
        finding = await _make_finding(db_session, scan1, normalized_fingerprint="fp1")

        await set_disposition(
            db_session, finding, FindingStatus.FALSE_POSITIVE,
            "FP", "analyst",
        )
        await db_session.flush()

        keys = [("semgrep", "fp1")]
        result = await resolve_dispositions_batch(db_session, proj2.id, keys)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_different_scanner_does_not_inherit(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(
            db_session, scan, scanner_name="semgrep", normalized_fingerprint="fp1",
        )

        await set_disposition(
            db_session, finding, FindingStatus.FALSE_POSITIVE,
            "FP", "analyst",
        )
        await db_session.flush()

        keys = [("zap", "fp1")]
        result = await resolve_dispositions_batch(db_session, proj.id, keys)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_fixed_does_not_inherit(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan, normalized_fingerprint="fp1")

        await set_disposition(
            db_session, finding, FindingStatus.FIXED,
            "Patched", "dev",
        )
        await db_session.flush()

        keys = [("semgrep", "fp1")]
        result = await resolve_dispositions_batch(db_session, proj.id, keys)
        assert len(result) == 0  # FIXED must not carry over

    @pytest.mark.asyncio
    async def test_expired_does_not_inherit(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        past = datetime.now(UTC) - timedelta(hours=1)
        disp = FindingDisposition(
            project_id=proj.id,
            scanner_name="semgrep",
            normalized_fingerprint="fp_expired",
            status=FindingStatus.ACCEPTED_RISK,
            justification="temp",
            actor="a",
            expires_at=past,
        )
        db_session.add(disp)
        await db_session.flush()

        keys = [("semgrep", "fp_expired")]
        result = await resolve_dispositions_batch(db_session, proj.id, keys)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_apply_dispositions_to_findings(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan, normalized_fingerprint="fp1")

        await set_disposition(
            db_session, finding, FindingStatus.ACCEPTED_BY_DESIGN,
            "By design", "arch",
        )
        await db_session.flush()

        keys = [("semgrep", "fp1")]
        dispositions = await resolve_dispositions_batch(db_session, proj.id, keys)

        nf = _nf(normalized_fingerprint="fp1")
        apply_dispositions_to_findings([nf], dispositions)
        assert getattr(nf, "status", None) == FindingStatus.ACCEPTED_BY_DESIGN


# ==================================================================
# API TESTS
# ==================================================================

class TestDispositionAPI:
    @pytest.mark.asyncio
    async def test_patch_valid(self, client, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj, RiskGate.BLOCKED)
        finding = await _make_finding(db_session, scan)
        await db_session.commit()

        resp = await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "ACCEPTED_BY_DESIGN",
                "justification": "JWT in HttpOnly cookie by design",
                "actor": "felipe.reis",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["finding_id"] == finding.id
        assert data["status"] == "ACCEPTED_BY_DESIGN"
        assert data["scan_risk_gate"] == "PASS"

    @pytest.mark.asyncio
    async def test_patch_actor_required(self, client, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)
        await db_session.commit()

        resp = await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "FALSE_POSITIVE",
                "justification": "FP",
                "actor": "   ",
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_patch_justification_required(self, client, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)
        await db_session.commit()

        resp = await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "FALSE_POSITIVE",
                "justification": "",
                "actor": "user1",
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_patch_expires_at_past(self, client, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)
        await db_session.commit()

        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        resp = await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "ACCEPTED_RISK",
                "justification": "temp",
                "actor": "user1",
                "expires_at": past,
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_patch_404(self, client):
        resp = await client.patch(
            "/api/findings/nonexistent-id/disposition",
            json={
                "status": "FALSE_POSITIVE",
                "justification": "test",
                "actor": "user1",
            },
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_disposition_history(self, client, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)
        await db_session.commit()

        await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "ACCEPTED_RISK",
                "justification": "Accepted temporarily",
                "actor": "user1",
            },
        )
        await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "OPEN",
                "justification": "Reopened",
                "actor": "user2",
            },
        )

        resp = await client.get(f"/api/findings/{finding.id}/disposition-history")
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) == 2
        assert events[0]["previous_status"] == "OPEN"
        assert events[0]["new_status"] == "ACCEPTED_RISK"
        assert events[1]["previous_status"] == "ACCEPTED_RISK"
        assert events[1]["new_status"] == "OPEN"

    @pytest.mark.asyncio
    async def test_risk_gate_recomputation(self, client, db_session: AsyncSession):
        """Scan with 1 HIGH OPEN → BLOCKED. Accept → PASS. Reopen → BLOCKED."""
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj, RiskGate.BLOCKED)
        finding = await _make_finding(db_session, scan)
        await db_session.commit()

        # Accept → PASS
        resp1 = await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "ACCEPTED_BY_DESIGN",
                "justification": "By design",
                "actor": "felipe",
            },
        )
        assert resp1.json()["scan_risk_gate"] == "PASS"

        # Reopen → BLOCKED
        resp2 = await client.patch(
            f"/api/findings/{finding.id}/disposition",
            json={
                "status": "OPEN",
                "justification": "Reassessing",
                "actor": "felipe",
            },
        )
        assert resp2.json()["scan_risk_gate"] == "BLOCKED"


# ==================================================================
# AUDIT EVENT details
# ==================================================================


    @pytest.mark.asyncio
    async def test_get_summary_triggers_expiry_resolution(self, client, db_session: AsyncSession):
        """GET /api/scans/{scan_id}/summary lazily resolves expired dispositions."""
        proj = await _make_project(db_session, "ApiExpiryProj")
        scan = await _make_scan(db_session, proj, RiskGate.BLOCKED)
        finding = await _make_finding(
            db_session,
            scan,
            scanner_name="semgrep",
            severity=Severity.HIGH,
            confidence=0.9,
            normalized_fingerprint="fp_api_exp",
        )
        await db_session.commit()

        # Patch with past expiry manually via DB
        past = datetime.now(UTC) - timedelta(hours=1)
        disp = FindingDisposition(
            project_id=proj.id,
            scanner_name="semgrep",
            normalized_fingerprint="fp_api_exp",
            status=FindingStatus.ACCEPTED_RISK,
            justification="Expiring soon",
            actor="lead",
            expires_at=past,
            source_finding_id=finding.id,
        )
        finding.status = FindingStatus.ACCEPTED_RISK
        scan.risk_gate = RiskGate.PASS
        db_session.add(disp)
        await db_session.commit()

        # GET summary should resolve expired disposition and recompute risk_gate to BLOCKED
        resp = await client.get(f"/api/scans/{scan.id}/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_gate"] == "BLOCKED"
        assert data["actionable_count"] == 1
        assert data["accepted_risk_count"] == 0

class TestAuditEvents:
    @pytest.mark.asyncio
    async def test_event_fields(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        scan = await _make_scan(db_session, proj)
        finding = await _make_finding(db_session, scan)

        _, _, event, _ = await set_disposition(
            db_session, finding, FindingStatus.FALSE_POSITIVE,
            "Confirmed false positive", "security-team",
        )
        assert event.previous_status == FindingStatus.OPEN
        assert event.new_status == FindingStatus.FALSE_POSITIVE
        assert event.actor == "security-team"
        assert event.justification == "Confirmed false positive"
        assert event.created_at is not None
        assert event.scanner_name == finding.scanner_name
        assert event.normalized_fingerprint == finding.normalized_fingerprint

    @pytest.mark.asyncio
    async def test_expiry_event_fields(self, db_session: AsyncSession):
        proj = await _make_project(db_session)
        future = datetime.now(UTC) + timedelta(days=30)

        _, _, event, _ = await set_disposition(
            db_session,
            await _make_finding(
                db_session,
                await _make_scan(db_session, proj),
            ),
            FindingStatus.ACCEPTED_RISK,
            "30-day acceptance",
            "risk-owner",
            expires_at=future,
        )
        assert event.expires_at == future


# ==================================================================
# is_actionable / effective_status helpers
# ==================================================================

class TestHelpers:
    def test_is_actionable(self):
        assert is_actionable(FindingStatus.OPEN) is True
        assert is_actionable(FindingStatus.FALSE_POSITIVE) is False
        assert is_actionable(FindingStatus.ACCEPTED_RISK) is False
        assert is_actionable(FindingStatus.ACCEPTED_BY_DESIGN) is False
        assert is_actionable(FindingStatus.FIXED) is False

    def test_effective_status_none(self):
        assert effective_status(None) == FindingStatus.OPEN

    def test_effective_status_expired(self):
        disp = FindingDisposition(
            project_id="x",
            scanner_name="s",
            normalized_fingerprint="fp",
            status=FindingStatus.ACCEPTED_RISK,
            justification="j",
            actor="a",
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert effective_status(disp) == FindingStatus.OPEN

    def test_effective_status_active(self):
        disp = FindingDisposition(
            project_id="x",
            scanner_name="s",
            normalized_fingerprint="fp",
            status=FindingStatus.FALSE_POSITIVE,
            justification="j",
            actor="a",
            expires_at=None,
        )
        assert effective_status(disp) == FindingStatus.FALSE_POSITIVE

    def test_constants(self):
        assert FindingStatus.FIXED not in PERSISTENT_STATUSES
        assert FindingStatus.FALSE_POSITIVE in PERSISTENT_STATUSES
        assert FindingStatus.ACCEPTED_RISK in PERSISTENT_STATUSES
        assert FindingStatus.ACCEPTED_BY_DESIGN in PERSISTENT_STATUSES
        assert FindingStatus.OPEN not in NON_ACTIONABLE
