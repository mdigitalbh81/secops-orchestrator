"""CodeQL SAST scanner adapter.

Performs multi-language static analysis using CodeQL CLI and SARIF 2.1.0 output.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import shutil
import uuid
from pathlib import Path

from app.core.config import get_settings
from app.models.enums import EvidenceLevel, Severity
from app.scanners.base import (
    NormalizedFinding,
    ScannerAdapter,
    compute_fingerprint,
    compute_normalized_fingerprint,
)
from app.security.runner import RunnerConfig, RunResult, run_command

logger = logging.getLogger(__name__)

PYTHON_EXTS = {".py", ".pyw"}
JS_TS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
IGNORED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".ruff_cache",
}


def map_sarif_severity(
    level: str | None,
    problem_severity: str | None = None,
    security_severity: float | None = None,
) -> Severity:
    """Deterministic mapping of SARIF / CodeQL rule severity to Severity enum."""
    if security_severity is not None:
        if security_severity >= 9.0:
            return Severity.CRITICAL
        if security_severity >= 7.0:
            return Severity.HIGH
        if security_severity >= 4.0:
            return Severity.MEDIUM
        if security_severity > 0.0:
            return Severity.LOW
        return Severity.INFO

    prob_sev = (problem_severity or "").lower()
    if prob_sev == "critical":
        return Severity.CRITICAL
    if prob_sev in ("error", "high"):
        return Severity.HIGH
    if prob_sev in ("warning", "medium", "recommendation"):
        return Severity.MEDIUM
    if prob_sev in ("recommendation", "low", "note"):
        return Severity.LOW

    lvl = (level or "").lower()
    if lvl == "error":
        return Severity.HIGH
    if lvl == "warning":
        return Severity.MEDIUM
    if lvl in ("note", "none"):
        return Severity.LOW

    return Severity.UNKNOWN


def extract_cwe_from_tags(tags: list[str]) -> str | None:
    """Extract CWE identifier from SARIF rule tags."""
    for tag in tags:
        if not isinstance(tag, str):
            continue
        # Examples: "external/cwe/cwe-89", "cwe-79", "cwe/cwe-089"
        match = re.search(r"cwe[/-](?:cwe-)?(\d+)", tag, re.IGNORECASE)
        if match:
            cwe_num = int(match.group(1))
            return f"CWE-{cwe_num}"
    return None


class CodeQLScanner(ScannerAdapter):
    """CodeQL scanner adapter for deep SAST analysis across multiple languages."""

    @property
    def name(self) -> str:
        return "codeql"

    async def is_available(self) -> bool:
        result = await run_command(
            ["codeql", "version", "--format=json"],
            config=RunnerConfig(timeout=10, max_output_bytes=4096, allowed_roots=[]),
        )
        return result.return_code == 0

    def detect_languages(self, project_path: Path) -> list[str]:
        """Detect supported languages in the target directory."""
        languages: set[str] = set()
        try:
            for item in project_path.rglob("*"):
                if any(part in IGNORED_DIRS for part in item.parts):
                    continue
                if item.is_file():
                    suffix = item.suffix.lower()
                    if suffix in PYTHON_EXTS:
                        languages.add("python")
                    elif suffix in JS_TS_EXTS or item.name == "package.json":
                        languages.add("javascript")
        except Exception:
            logger.warning("Error scanning project files for CodeQL languages")
        return sorted(languages)

    def detect_applicability(self, project_path: Path, target_url: str | None = None) -> bool:
        """Return True if Python or JS/TS code is detected."""
        return len(self.detect_languages(project_path)) > 0

    def build_command(self, project_path: Path, target_url: str | None = None) -> list[str]:
        """Return default command for single execution fallback."""
        return ["codeql", "version"]

    async def execute(
        self, project_path: Path, target_url: str | None = None, config: RunnerConfig | None = None
    ) -> RunResult:
        """Execute CodeQL database creation and analysis per detected language."""
        settings = get_settings()
        languages = self.detect_languages(project_path)
        if not languages:
            return RunResult(return_code=0, stdout=json.dumps({"runs": []}), stderr="")

        scan_uuid = uuid.uuid4().hex[:12]
        temp_workdir = Path(f"/tmp/secops-codeql-{scan_uuid}")
        temp_workdir.mkdir(parents=True, exist_ok=True)

        all_runs: list[dict] = []
        stderr_parts: list[str] = []
        overall_timed_out = False

        allowed_roots = list(config.allowed_roots) if config else [settings.allowed_workspace_root]
        if temp_workdir not in allowed_roots:
            allowed_roots.append(temp_workdir)
        if project_path not in allowed_roots:
            allowed_roots.append(project_path)

        runner_config = RunnerConfig(
            timeout=config.timeout if config else settings.scanner_timeout,
            max_output_bytes=config.max_output_bytes
            if config
            else settings.scanner_max_output_bytes,
            allowed_roots=allowed_roots,
        )

        try:
            for lang in languages:
                db_dir = temp_workdir / f"db-{lang}"
                sarif_file = temp_workdir / f"results-{lang}.sarif"

                # 1. Create database
                create_cmd = [
                    "codeql",
                    "database",
                    "create",
                    str(db_dir),
                    f"--language={lang}",
                    f"--source-root={project_path}",
                    "--overwrite",
                ]
                create_res = await run_command(
                    create_cmd,
                    cwd=project_path,
                    config=runner_config,
                )

                if create_res.timed_out:
                    overall_timed_out = True
                    stderr_parts.append(f"CodeQL database creation timed out for {lang}")
                    continue
                if create_res.return_code != 0:
                    stderr_parts.append(
                        f"CodeQL database creation failed for {lang}: {create_res.stderr}"
                    )
                    continue

                # 2. Analyze database
                analyze_cmd = [
                    "codeql",
               "database",
               "analyze",
               str(db_dir),
                f"codeql/{lang}-queries:codeql-suites/{lang}-security-and-quality.qls",
               "--format=sarif-latest",
                    f"--output={sarif_file}",
                    f"--threads={settings.codeql_threads}",
                ]
                if settings.codeql_ram_mb:
                    analyze_cmd.append(f"--ram={settings.codeql_ram_mb}")
                analyze_res = await run_command(
                    analyze_cmd,
                    cwd=project_path,
                    config=runner_config,
                )

                # Fallback if standard suite name is different
                if analyze_res.return_code != 0 or not sarif_file.exists():
                    analyze_cmd_fallback = [
                        "codeql",
                        "database",
                        "analyze",
                        str(db_dir),
                        "--format=sarif-latest",
                        f"--output={sarif_file}",
                        f"--threads={settings.codeql_threads}",
                    ]
                    if settings.codeql_ram_mb:
                        analyze_cmd_fallback.append(f"--ram={settings.codeql_ram_mb}")
                    analyze_res = await run_command(
                        analyze_cmd_fallback,
                        cwd=project_path,
                        config=runner_config,
                    )

                if analyze_res.timed_out:
                    overall_timed_out = True
                    stderr_parts.append(f"CodeQL analysis timed out for {lang}")
                    continue

                if sarif_file.exists():
                    try:
                        sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
                        runs = sarif_data.get("runs", [])
                        all_runs.extend(runs)
                    except Exception as e:
                        stderr_parts.append(f"Failed to read SARIF output for {lang}: {e}")
                else:
                    stderr_parts.append(
                        f"CodeQL analysis produced no SARIF for {lang}: {analyze_res.stderr}"
                    )
        finally:
            shutil.rmtree(temp_workdir, ignore_errors=True)

        combined_sarif = {"version": "2.1.0", "runs": all_runs}
        return RunResult(
            return_code=0 if all_runs or not stderr_parts else 1,
            stdout=json.dumps(combined_sarif),
            stderr="\n".join(stderr_parts),
            timed_out=overall_timed_out,
        )

    def parse_result(self, result: RunResult) -> list[dict]:
        """Parse canonical SARIF output and extract findings with rule metadata."""
        if not result.stdout.strip():
            return []
        try:
            sarif_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse CodeQL SARIF JSON output")
            return []

        parsed_findings: list[dict] = []
        runs = sarif_data.get("runs", [])
        for run in runs:
            driver = run.get("tool", {}).get("driver", {})
            rules_list = driver.get("rules", [])
            rules_map: dict[str, dict] = {
                r.get("id", ""): r for r in rules_list if isinstance(r, dict)
            }

            for res in run.get("results", []):
                if not isinstance(res, dict):
                    continue
                rule_id = res.get("ruleId", "unknown")
                rule_meta = rules_map.get(rule_id, {})
                parsed_findings.append(
                    {
                        "result": res,
                        "rule": rule_meta,
                        "tool": driver.get("name", "codeql"),
                    }
                )
        return parsed_findings

    def normalize_findings(self, raw_findings: list[dict]) -> list[NormalizedFinding]:
        """Convert parsed SARIF findings into NormalizedFinding instances."""
        findings: list[NormalizedFinding] = []
        for item in raw_findings:
            res = item.get("result", {})
            rule = item.get("rule", {})

            rule_id = res.get("ruleId", rule.get("id", "codeql-finding"))
            msg = res.get("message", {}).get("text", "")
            rule_short_desc = rule.get("shortDescription", {}).get("text", "")
            rule_full_desc = rule.get("fullDescription", {}).get("text", "")
            title = rule_short_desc or rule_id
            description = msg or rule_full_desc or title

            rule_props = rule.get("properties", {})
            problem_severity = rule_props.get("problem.severity")
            security_severity_raw = rule_props.get("security-severity")
            security_severity = None
            if security_severity_raw is not None:
                with contextlib.suppress(ValueError, TypeError):
                    security_severity = float(security_severity_raw)

            sarif_level = res.get("level")
            severity = map_sarif_severity(
                sarif_level,
                problem_severity=problem_severity,
                security_severity=security_severity,
            )

            # File & line location
            file_path = None
            line_start = None
            line_end = None
            locations = res.get("locations", [])
            if locations and isinstance(locations[0], dict):
                phys = locations[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                if uri.startswith("file://"):
                    uri = uri[7:]
                file_path = uri if uri else None
                region = phys.get("region", {})
                line_start = region.get("startLine")
                line_end = region.get("endLine", line_start)

            # CWE and CVE extraction
            tags = rule_props.get("tags", [])
            cwe = extract_cwe_from_tags(tags)
            if not cwe:
                # Check rule id or description for CWE
                combined_text = f"{rule_id} {title} {description}"
                cwe_match = re.search(r"cwe[/-](?:cwe-)?(\d+)", combined_text, re.IGNORECASE)
                if cwe_match:
                    cwe = f"CWE-{int(cwe_match.group(1))}"

            cve_match = re.search(r"(CVE-\d{4}-\d{4,8})", f"{rule_id} {description}", re.IGNORECASE)
            cve = cve_match.group(1).upper() if cve_match else None

            raw_fp = compute_fingerprint(
                scanner=self.name,
                cve=cve,
                cwe=cwe,
                file_path=file_path,
                line_start=line_start,
                title=rule_id,
            )
            norm_fp = compute_normalized_fingerprint(
                cve=cve,
                cwe=cwe,
                file_path=file_path,
                title=rule_id,
            )

            findings.append(
                NormalizedFinding(
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=0.70,
                    scanner_name=self.name,
                    cwe=cwe,
                    cve=cve,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    url=rule.get("helpUri"),
                    evidence_level=EvidenceLevel.SINGLE_SOURCE,
                    raw_data=item,
                    raw_fingerprint=raw_fp,
                    normalized_fingerprint=norm_fp,
                )
            )
        return findings
