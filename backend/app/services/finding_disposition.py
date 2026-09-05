"""Finding disposition service.

Centralises all disposition logic: validation, persistence, audit trail,
batch resolution for scan pipelines, and risk-gate recomputation.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.disposition import FindingDisposition, FindingDispositionEvent
from app.models.enums import FindingStatus, RiskGate
from app.models.finding import Finding
from app.models.scan import Scan
from app.scanners.base import NormalizedFinding
from app.services.risk_engine import compute_risk_gate

logger = logging.getLogger(__name__)

# Statuses considered non-actionable for risk gate purposes
NON_ACTIONABLE = frozenset({
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
    FindingStatus.ACCEPTED_BY_DESIGN,
    FindingStatus.FIXED,
})

# Statuses that create persistent suppress policies (inherited by future scans)
PERSISTENT_STATUSES = frozenset({
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
    FindingStatus.ACCEPTED_BY_DESIGN,
})

# Valid disposition targets from API
ALLOWED_DISPOSITIONS = frozenset({
    FindingStatus.OPEN,
    FindingStatus.FIXED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
    FindingStatus.ACCEPTED_BY_DESIGN,
})


def is_actionable(status: FindingStatus) -> bool:
    """Return True if the finding status should participate in the risk gate."""
    return status not in NON_ACTIONABLE


def _disposition_expired(disp: FindingDisposition) -> bool:
    if disp.expires_at is None:
        return False
    return disp.expires_at <= datetime.now(UTC)


def effective_status(disp: FindingDisposition | None) -> FindingStatus:
    """Resolve effective status from a disposition record."""
    if disp is None:
        return FindingStatus.OPEN
    if _disposition_expired(disp):
        return FindingStatus.OPEN
    return disp.status


# ------------------------------------------------------------------
# Batch resolution for scan pipeline
# ------------------------------------------------------------------

async def resolve_dispositions_batch(
    session: AsyncSession,
    project_id: str,
    keys: list[tuple[str, str]],
) -> dict[tuple[str, str], FindingDisposition]:
    """Load active dispositions in a batch of (scanner_name, normalized_fingerprint).

    Returns only dispositions whose status is in PERSISTENT_STATUSES and not expired.
    FIXED dispositions are intentionally excluded and must not carry over.
    """
    if not keys:
        return {}

    await resolve_expired_dispositions(session, project_id)

    result = await session.execute(
        select(FindingDisposition).where(
            FindingDisposition.project_id == project_id,
            FindingDisposition.status.in_([s.value for s in PERSISTENT_STATUSES]),
        )
    )
    dispositions = list(result.scalars().all())
    key_set = set(keys)
    out: dict[tuple[str, str], FindingDisposition] = {}
    for d in dispositions:
        k = (d.scanner_name, d.normalized_fingerprint)
        if k in key_set and not _disposition_expired(d):
            out[k] = d
    return out


def apply_dispositions_to_findings(
    findings: list[NormalizedFinding],
    dispositions: dict[tuple[str, str], FindingDisposition],
) -> list[NormalizedFinding]:
    """Mutate findings in-place, applying inherited disposition statuses.
    Returns the same list for convenience.
    """
    for f in findings:
        key = (f.scanner_name, f.normalized_fingerprint)
        disp = dispositions.get(key)
        if disp is not None:
            eff = effective_status(disp)
            if eff != FindingStatus.OPEN:
                f.status = eff
    return findings


def compute_risk_gate_with_dispositions(
    findings: list[NormalizedFinding],
) -> RiskGate:
    """Compute risk gate directly delegating to authoritative risk engine."""
    return compute_risk_gate(findings)


# ------------------------------------------------------------------
# Manual disposition (API-driven)
# ------------------------------------------------------------------

async def set_disposition(
    session: AsyncSession,
    finding: Finding,
    new_status: FindingStatus,
    justification: str,
    actor: str,
    expires_at: datetime | None = None,
) -> tuple[Finding, FindingDisposition | None, FindingDispositionEvent, RiskGate]:
    """Apply a disposition to a finding, persist audit event, and recompute risk gate.

    Returns (updated_finding, disposition_record_or_None, audit_event, new_risk_gate).
    """
    scan = await session.get(Scan, finding.scan_id)
    project_id = scan.project_id  # type: ignore[union-attr]
    previous_status = FindingStatus(finding.status)

    # Update finding status
    finding.status = new_status

    # Manage persistent disposition record
    disposition: FindingDisposition | None = None
    if new_status in PERSISTENT_STATUSES:
        # Upsert disposition
        result = await session.execute(
            select(FindingDisposition).where(
                FindingDisposition.project_id == project_id,
                FindingDisposition.scanner_name == finding.scanner_name,
                FindingDisposition.normalized_fingerprint == finding.normalized_fingerprint,
            )
        )
        disposition = result.scalar_one_or_none()
        if disposition is None:
            disposition = FindingDisposition(
                project_id=project_id,
                scanner_name=finding.scanner_name,
                normalized_fingerprint=finding.normalized_fingerprint,
                status=new_status,
                justification=justification,
                actor=actor,
                expires_at=expires_at,
                source_finding_id=finding.id,
            )
            session.add(disposition)
        else:
            disposition.status = new_status
            disposition.justification = justification
            disposition.actor = actor
            disposition.expires_at = expires_at
            disposition.source_finding_id = finding.id
            disposition.updated_at = datetime.now(UTC)

    elif new_status == FindingStatus.OPEN:
        # Remove persistent disposition when reopening
        result = await session.execute(
            select(FindingDisposition).where(
                FindingDisposition.project_id == project_id,
                FindingDisposition.scanner_name == finding.scanner_name,
                FindingDisposition.normalized_fingerprint == finding.normalized_fingerprint,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            await session.delete(existing)

    elif new_status == FindingStatus.FIXED:
        # Clear any prior persistent suppress policy
        result = await session.execute(
            select(FindingDisposition).where(
                FindingDisposition.project_id == project_id,
                FindingDisposition.scanner_name == finding.scanner_name,
                FindingDisposition.normalized_fingerprint == finding.normalized_fingerprint,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            await session.delete(existing)

    # Audit event
    event = FindingDispositionEvent(
        project_id=project_id,
        scan_id=finding.scan_id,
        finding_id=finding.id,
        scanner_name=finding.scanner_name,
        normalized_fingerprint=finding.normalized_fingerprint,
        previous_status=previous_status,
        new_status=new_status,
        justification=justification,
        actor=actor,
        expires_at=expires_at,
    )
    session.add(event)

    # Recompute risk gate for the scan
    new_risk_gate = await _recompute_scan_risk_gate(session, scan)  # type: ignore[arg-type]

    await session.flush()
    return finding, disposition, event, new_risk_gate


async def get_disposition_history(
    session: AsyncSession,
    finding_id: str,
) -> list[FindingDispositionEvent]:
    """Return audit events for a finding, chronologically."""
    result = await session.execute(
        select(FindingDispositionEvent)
        .where(FindingDispositionEvent.finding_id == finding_id)
        .order_by(FindingDispositionEvent.created_at.asc())
    )
    return list(result.scalars().all())


async def get_finding_disposition(
    session: AsyncSession,
    finding: Finding,
) -> FindingDisposition | None:
    """Return current persistent disposition for a finding identity."""
    scan = await session.get(Scan, finding.scan_id)
    if scan is None:
        return None
    result = await session.execute(
        select(FindingDisposition).where(
            FindingDisposition.project_id == scan.project_id,
            FindingDisposition.scanner_name == finding.scanner_name,
            FindingDisposition.normalized_fingerprint == finding.normalized_fingerprint,
        )
    )
    return result.scalar_one_or_none()


# ------------------------------------------------------------------
# Expiry handling
# ------------------------------------------------------------------

async def resolve_expired_dispositions(
    session: AsyncSession,
    project_id: str,
) -> list[FindingDispositionEvent]:
    """Find expired dispositions, auto-reopen them, and recompute affected scan risk gates.
    Returns generated events.
    """
    now = datetime.now(UTC)
    result = await session.execute(
        select(FindingDisposition).where(
            FindingDisposition.project_id == project_id,
            FindingDisposition.expires_at <= now,
            FindingDisposition.status.in_([s.value for s in PERSISTENT_STATUSES]),
        )
    )
    expired = list(result.scalars().all())
    events: list[FindingDispositionEvent] = []

    for disp in expired:
        event = FindingDispositionEvent(
            project_id=disp.project_id,
            finding_id=disp.source_finding_id,
            scanner_name=disp.scanner_name,
            normalized_fingerprint=disp.normalized_fingerprint,
            previous_status=disp.status,
            new_status=FindingStatus.OPEN,
            justification=f"Auto-reopened: disposition expired at {disp.expires_at.isoformat()}",
            actor="system",
            expires_at=None,
        )
        if disp.source_finding_id:
            src_finding = await session.get(Finding, disp.source_finding_id)
            if src_finding:
                event.scan_id = src_finding.scan_id

        session.add(event)
        events.append(event)

        # Reset matching findings in the project
        findings_res = await session.execute(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(
                Scan.project_id == disp.project_id,
                Finding.scanner_name == disp.scanner_name,
                Finding.normalized_fingerprint == disp.normalized_fingerprint,
                Finding.status == disp.status,
            )
        )
        affected_findings = list(findings_res.scalars().all())
        scans_to_recompute: set[str] = set()
        for f in affected_findings:
            f.status = FindingStatus.OPEN
            scans_to_recompute.add(f.scan_id)

        for s_id in scans_to_recompute:
            scan_obj = await session.get(Scan, s_id)
            if scan_obj:
                await _recompute_scan_risk_gate(session, scan_obj)

        await session.delete(disp)

    if events:
        await session.flush()

    return events


# ------------------------------------------------------------------
# Risk gate recomputation
# ------------------------------------------------------------------

async def _recompute_scan_risk_gate(
    session: AsyncSession,
    scan: Scan,
) -> RiskGate:
    """Recompute risk gate for a scan based on current finding statuses."""
    findings_result = await session.execute(
        select(Finding).where(Finding.scan_id == scan.id)
    )
    all_findings = list(findings_result.scalars().all())

    proxies = [
        NormalizedFinding(
            title=f.title,
            description=f.description or "",
            severity=f.severity,
            confidence=f.confidence,
            scanner_name=f.scanner_name,
            evidence_level=f.evidence_level,
            raw_fingerprint=f.raw_fingerprint,
            normalized_fingerprint=f.normalized_fingerprint,
            status=FindingStatus(f.status),
        )
        for f in all_findings
    ]

    new_gate = compute_risk_gate(proxies)
    scan.risk_gate = new_gate
    return new_gate
