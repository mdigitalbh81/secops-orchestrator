"""Security toolchain inventory manager and health checker."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from app.security.runner import RunnerConfig, run_command_sync
from app.toolchain.models import RuntimeSource, ToolCategory, ToolInfo, ToolStatus

logger = logging.getLogger(__name__)


def get_repo_root() -> Path | None:
    """Locate the SecOps Orchestrator repository root directory."""
    env_root = os.environ.get("SECOPS_REPO_ROOT")
    if env_root:
        p = Path(env_root).resolve()
        if (p / "docker-compose.yml").is_file():
            return p

    try:
        mod_root = Path(__file__).resolve().parents[3]
        if (mod_root / "docker-compose.yml").is_file():
            return mod_root
    except (IndexError, ValueError):
        pass

    cwd = Path.cwd().resolve()
    if (cwd / "docker-compose.yml").is_file():
        return cwd

    return None


def parse_semantic_version(text: str) -> str | None:
    """Extract semantic version (e.g. 1.2.3, 1.2.3-beta) from arbitrary output."""
    if not text:
        return None
    match = re.search(r"\bv?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)\b", text)
    if match:
        return match.group(1).lstrip("v")
    return None


def compare_versions(installed: str | None, available: str | None) -> int | None:
    """Compare two semantic version strings.

    Returns:
        -1 if installed < available
         0 if installed == available
         1 if installed > available
      None if versions cannot be compared
    """
    if not installed or not available:
        return None

    installed_clean = installed.lstrip("v").strip()
    available_clean = available.lstrip("v").strip()

    if installed_clean == available_clean:
        return 0

    nums_inst = [int(p) for p in re.findall(r"\d+", installed_clean)]
    nums_avail = [int(p) for p in re.findall(r"\d+", available_clean)]

    if nums_inst and nums_avail:
        max_len = max(len(nums_inst), len(nums_avail))
        p_inst = nums_inst + [0] * (max_len - len(nums_inst))
        p_avail = nums_avail + [0] * (max_len - len(nums_avail))
        if p_inst < p_avail:
            return -1
        if p_inst > p_avail:
            return 1
        return 0

    return None


def _unpack_detection(res: tuple) -> tuple[str | None, str | None, ToolStatus | None]:
    """Normalize 2-tuple or 3-tuple return from detection methods into (ver, notes, status)."""
    if len(res) >= 3:
        return res[0], res[1], res[2]
    ver, notes = res[0], res[1]
    status = None
    if ver is None and notes:
        n_low = notes.lower()
        if "not running" in n_low or "unavailable" in n_low:
            status = ToolStatus.UNKNOWN
        elif "not found" in n_low or "not installed" in n_low or "not detected" in n_low:
            status = ToolStatus.NOT_INSTALLED
        elif any(k in n_low for k in ("error", "fail", "malformed", "timed out", "crash", "invalid")):
            status = ToolStatus.ERROR
        else:
            status = ToolStatus.NOT_INSTALLED
    return ver, notes, status


class ToolchainManager:
    """Discovers, inventories, and verifies security toolchain components."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = repo_root or get_repo_root()
        self._worker_running: bool | None = None

    def _get_compose_base(self) -> list[str]:
        base = ["docker", "compose"]
        if self.repo_root and (self.repo_root / "docker-compose.yml").is_file():
            base += ["-f", str(self.repo_root / "docker-compose.yml")]
        return base

    def is_worker_running(self) -> bool:
        """Check whether the SecOps worker container is running."""
        if self._worker_running is not None:
            return self._worker_running
        if not shutil.which("docker"):
            self._worker_running = False
            return False
        try:
            cmd = self._get_compose_base() + ["ps", "-q", "worker"]
            res = run_command_sync(cmd, config=RunnerConfig(timeout=5))
            self._worker_running = bool(res.return_code == 0 and res.stdout.strip())
        except Exception as exc:
            logger.debug("Worker status check failed: %s", exc)
            self._worker_running = False
        return self._worker_running

    def run_worker_command(
        self,
        argv: list[str],
        timeout: int = 10,
    ) -> tuple[int, str, str]:
        """Execute a command securely inside the running SecOps worker container.
        Returns: (return_code, stdout, stderr)
        """
        if not self.is_worker_running():
            return -1, "", "SecOps worker container is not running"
        full_cmd = self._get_compose_base() + ["exec", "-T", "worker"] + argv
        res = run_command_sync(full_cmd, config=RunnerConfig(timeout=timeout))
        return res.return_code, res.stdout, res.stderr

    def run_safe_tool_command(
        self,
        cmd_argv: list[str],
        worker_argv: list[str] | None = None,
        timeout: int = 5,
    ) -> tuple[int, str, str]:
        """Execute version command inside worker if running, or via secure runner."""
        if self.is_worker_running():
            exec_args = worker_argv or cmd_argv
            return self.run_worker_command(exec_args, timeout=timeout)
        return -1, "", f"Binary '{cmd_argv[0]}' not found locally or in running worker"

    def detect_configured_versions(self) -> dict[str, str]:
        """Extract configured tool versions directly from repo manifests/build files."""
        configured: dict[str, str] = {
            "semgrep": "unpinned",
            "codeql": "external (optional)",
            "trivy": "unpinned",
            "pip-audit": "unpinned",
            "npm": "system package",
            "nuclei": "3.3.2",
            "zap": "2.17.0",
            "nuclei_templates": "10.4.8",
            "trivy_db": "dynamic / cached",
            "mantis": "disabled (contract only)",
        }

        if not self.repo_root:
            return configured

        worker_df = self.repo_root / "docker" / "Dockerfile.worker"
        if worker_df.is_file():
            try:
                content = worker_df.read_text(encoding="utf-8", errors="replace")
                n_match = re.search(r"ARG\s+NUCLEI_VERSION=v?([\d.]+)", content)
                if n_match:
                    configured["nuclei"] = n_match.group(1)
                t_match = re.search(r"ARG\s+NUCLEI_TEMPLATES_VERSION=v?([\d.]+)", content)
                if t_match:
                    configured["nuclei_templates"] = t_match.group(1)
            except Exception as exc:
                logger.debug("Failed reading Dockerfile.worker configured versions: %s", exc)

        compose_f = self.repo_root / "docker-compose.yml"
        if compose_f.is_file():
            try:
                content = compose_f.read_text(encoding="utf-8", errors="replace")
                z_match = re.search(r"zaproxy/zap-stable:([\w.-]+)", content)
                if z_match:
                    configured["zap"] = z_match.group(1)
            except Exception as exc:
                logger.debug("Failed reading docker-compose.yml configured versions: %s", exc)

        return configured

    def _detect_worker_tool(
        self,
        tool_name: str,
        cmd_argv: list[str],
    ) -> tuple[str | None, str | None, ToolStatus | None]:
        """Execute detection inside authoritative worker runtime."""
        if not self.is_worker_running():
            return None, "SecOps worker container not running", ToolStatus.UNKNOWN

        rc, stdout, stderr = self.run_worker_command(cmd_argv)
        if rc != 0:
            combined_err = (stderr + " " + stdout).lower()
            if "not found" in combined_err or rc == 127:
                return None, f"{tool_name} not installed in worker container", ToolStatus.NOT_INSTALLED
            err_msg = stderr.strip() or stdout.strip() or f"exit code {rc}"
            return None, f"Execution failed in worker: {err_msg[:100]}", ToolStatus.ERROR

        combined_out = (stdout + "\n" + stderr).strip()
        ver = parse_semantic_version(combined_out)
        if ver:
            return ver, None, None
        return None, f"Could not parse version from output: {combined_out[:100]}", ToolStatus.ERROR

    def detect_semgrep(self) -> tuple[str | None, str | None, ToolStatus | None]:
        return self._detect_worker_tool("semgrep", ["semgrep", "--version"])

    def detect_pip_audit(self) -> tuple[str | None, str | None, ToolStatus | None]:
        return self._detect_worker_tool("pip-audit", ["pip-audit", "--version"])

    def detect_trivy(self) -> tuple[str | None, str | None, ToolStatus | None]:
        return self._detect_worker_tool("trivy", ["trivy", "--version"])

    def detect_npm(self) -> tuple[str | None, str | None, ToolStatus | None]:
        return self._detect_worker_tool("npm", ["npm", "--version"])

    def detect_nuclei(self) -> tuple[str | None, str | None, ToolStatus | None]:
        return self._detect_worker_tool("nuclei", ["nuclei", "-version"])

    def detect_codeql(self) -> tuple[str | None, str | None, ToolStatus | None]:
        """Inspect GitHub CodeQL availability inside the SecOps worker container.

        CodeQL is an optional external scanner mounted by the user into the worker.
        """
        if not self.is_worker_running():
            return None, "SecOps worker container not running", ToolStatus.OPTIONAL

        rc, stdout, stderr = self.run_worker_command(
            ["which", "codeql"],
            timeout=5,
        )
        worker_codeql = stdout.strip() if rc == 0 else ""
        if not worker_codeql:
            if shutil.which("codeql"):
                return None, "CodeQL detected on host but not mounted in worker; optional external", ToolStatus.OPTIONAL
            return None, "Optional external CodeQL not detected in worker", ToolStatus.OPTIONAL

        v_rc, v_stdout, v_stderr = self.run_worker_command(
            ["codeql", "version", "--format=json"],
            timeout=10,
        )
        if v_rc != 0:
            return None, f"CodeQL execution failed in worker: {v_stderr.strip()[:100] or f'exit {v_rc}'}", ToolStatus.ERROR

        ver = None
        try:
            data = json.loads(v_stdout.strip())
            if isinstance(data, dict):
                v = data.get("version") or data.get("codeql_version") or data.get("appVersion")
                if v:
                    ver = str(v).strip()
        except Exception as exc:
            logger.debug("Failed parsing CodeQL json: %s", exc)

        if not ver:
            ver = parse_semantic_version(v_stdout)

        if not ver:
            return None, "Malformed CodeQL version output in worker", ToolStatus.ERROR

        return ver, "User-provided mount (worker)", ToolStatus.UNKNOWN

    def detect_zap(self) -> tuple[str | None, str | None, ToolStatus | None]:
        """Inspect zaproxy container running in Docker."""
        if not shutil.which("docker"):
            return None, "Docker CLI not found", ToolStatus.UNKNOWN

        res = run_command_sync(
            ["docker", "inspect", "secops-zap", "--format", "{{.Config.Image}}"],
            config=RunnerConfig(timeout=5),
        )
        if res.return_code == 0 and res.stdout.strip():
            img = res.stdout.strip()
            ver = img.split(":")[-1] if ":" in img else img
            return ver, "container secops-zap", None

        combined = (res.stderr + " " + res.stdout).lower()
        if "no such object" in combined or "not found" in combined:
            return None, "ZAP container secops-zap not running", ToolStatus.NOT_INSTALLED
        return None, f"Docker inspect failed: {res.stderr.strip()[:100]}", ToolStatus.ERROR

    def detect_nuclei_templates(self) -> tuple[str | None, str | None, ToolStatus | None]:
        """Read Nuclei templates version explicitly from worker container."""
        if not self.is_worker_running():
            return None, "SecOps worker container not running", ToolStatus.UNKNOWN

        rc, stdout, stderr = self.run_worker_command(
            ["cat", "/home/secops/.config/nuclei/.templates-config.json"],
            timeout=5,
        )
        if rc != 0:
            combined = (stderr + " " + stdout).lower()
            if "no such file" in combined or "not found" in combined:
                return None, "Nuclei templates config not found in worker", ToolStatus.NOT_INSTALLED
            return None, f"Failed reading templates config in worker: {stderr.strip()[:100]}", ToolStatus.ERROR

        try:
            cfg = json.loads(stdout.strip())
            ver = cfg.get("nuclei-templates-version")
            if ver:
                return str(ver).lstrip("v"), None, None
            return None, "Malformed templates config: missing version", ToolStatus.ERROR
        except Exception as exc:
            return None, f"Failed parsing templates config JSON: {exc}", ToolStatus.ERROR

    def detect_trivy_db(self) -> tuple[str | None, str | None, ToolStatus | None]:
        """Read Trivy vulnerability DB cache metadata explicitly from worker container."""
        if not self.is_worker_running():
            return None, "SecOps worker container not running", ToolStatus.UNKNOWN

        rc, stdout, stderr = self.run_worker_command(
            ["cat", "/home/secops/.cache/trivy/db/metadata.json"],
            timeout=5,
        )
        if rc != 0:
            combined = (stderr + " " + stdout).lower()
            if "no such file" in combined or "not found" in combined:
                return None, "Trivy DB cache not found in worker", ToolStatus.NOT_INSTALLED
            return None, f"Failed reading Trivy DB metadata in worker: {stderr.strip()[:100]}", ToolStatus.ERROR

        try:
            meta = json.loads(stdout.strip())
            schema = meta.get("Version", 2)
            updated = meta.get("UpdatedAt", "")
            next_update = meta.get("NextUpdate", "")
            ver_str = f"v{schema}"
            if updated:
                ver_str += f" ({str(updated)[:10]})"

            db_status = ToolStatus.UNKNOWN
            db_notes = None
            if next_update:
                try:
                    nu_clean = str(next_update)
                    if nu_clean.endswith("Z"):
                        nu_clean = nu_clean[:-1] + "+00:00"
                    nu_clean = re.sub(r"(\.\d{6})\d+", r"\1", nu_clean)
                    next_dt = datetime.fromisoformat(nu_clean)
                    now_dt = datetime.now(UTC)
                    if now_dt <= next_dt:
                        db_status = ToolStatus.CURRENT
                        db_notes = f"DB cache fresh until {str(next_update)[:10]}"
                    else:
                        db_status = ToolStatus.UPDATE_AVAILABLE
                        db_notes = f"DB cache expired on {str(next_update)[:10]}"
                except Exception as exc:
                    logger.debug("Could not calculate Trivy DB freshness: %s", exc)
                    db_status = ToolStatus.UNKNOWN

            return ver_str, db_notes, db_status
        except Exception as exc:
            return None, f"Failed parsing Trivy metadata JSON: {exc}", ToolStatus.ERROR

    def _check_mantis_upstream(self) -> str | None:
        """Query https://github.com/google/mantis read-only to discover current refs/heads/main."""
        if shutil.which("git"):
            try:
                res = run_command_sync(
                    ["git", "ls-remote", "https://github.com/google/mantis", "refs/heads/main"],
                    config=RunnerConfig(timeout=5),
                )
                if res.return_code == 0 and res.stdout.strip():
                    sha = res.stdout.strip().split()[0]
                    if re.match(r"^[0-9a-fA-F]{40}$", sha):
                        return sha
            except Exception as exc:
                logger.debug("git ls-remote failed for mantis: %s", exc)

        try:
            url = "https://api.github.com/repos/google/mantis/commits/main"
            req = urllib.request.Request(url, headers={"User-Agent": "secops-toolchain-manager"})  # noqa: S310
            with urllib.request.urlopen(req, timeout=3.0) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
                sha = str(data.get("sha", "")).strip()
                if sha:
                    return sha
        except Exception as exc:
            logger.debug("GitHub API commit check failed for mantis: %s", exc)

        return None

    def check_upstream_version(self, tool_id: str) -> str | None:
        """Fetch latest upstream release version gracefully. Returns None on network error."""
        if tool_id == "mantis":
            return self._check_mantis_upstream()

        endpoints = {
            "semgrep": ("https://pypi.org/pypi/semgrep/json", "pypi"),
            "pip-audit": ("https://pypi.org/pypi/pip-audit/json", "pypi"),
            "trivy": ("https://api.github.com/repos/aquasecurity/trivy/releases/latest", "github"),
            "nuclei": ("https://api.github.com/repos/projectdiscovery/nuclei/releases/latest", "github"),
            "nuclei_templates": (
                "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest",
                "github",
            ),
            "zap": ("https://api.github.com/repos/zaproxy/zaproxy/releases/latest", "github"),
        }
        if tool_id not in endpoints:
            return None

        url, kind = endpoints[tool_id]
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "secops-toolchain-manager"})  # noqa: S310
            with urllib.request.urlopen(req, timeout=3.0) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
                if kind == "pypi":
                    return str(data.get("info", {}).get("version", "")).strip() or None
                if kind == "github":
                    tag = str(data.get("tag_name", "")).lstrip("v").strip()
                    return tag or None
        except Exception as exc:
            logger.debug("Upstream check failed for %s: %s", tool_id, exc)
            return None

        return None

    def _evaluate_status(
        self,
        installed: str | None,
        available: str | None,
        check_upstream: bool,
        detected_status: ToolStatus | None = None,
    ) -> ToolStatus:
        if detected_status is not None:
            return detected_status
        if not installed:
            return ToolStatus.NOT_INSTALLED
        if not check_upstream or not available:
            return ToolStatus.UNKNOWN
        cmp = compare_versions(installed, available)
        if cmp is None:
            return ToolStatus.UNKNOWN
        if cmp < 0:
            return ToolStatus.UPDATE_AVAILABLE
        return ToolStatus.CURRENT

    def get_inventory(self, check_upstream: bool = False) -> list[ToolInfo]:
        """Build full structured inventory of all monitored security tools."""
        configured = self.detect_configured_versions()
        tools: list[ToolInfo] = []

        # 1. Semgrep
        sg_res = self.detect_semgrep()
        sg_ver, sg_notes, sg_st = _unpack_detection(sg_res)
        avail_sg = self.check_upstream_version("semgrep") if check_upstream else None
        sg_status = self._evaluate_status(sg_ver, avail_sg, check_upstream, detected_status=sg_st)
        tools.append(
            ToolInfo(
                name="Semgrep",
                category=ToolCategory.ENGINE,
                installed_version=sg_ver,
                configured_version=configured.get("semgrep", "unpinned"),
                available_version=avail_sg,
                source="pypi (worker)",
                update_policy="manual / build",
                availability="available" if sg_ver else ("error" if sg_status == ToolStatus.ERROR else "unavailable"),
                status=sg_status,
                notes=sg_notes,
                runtime_source=RuntimeSource.WORKER,
            )
        )

        # 2. CodeQL
        cql_res = self.detect_codeql()
        cql_ver, cql_notes, cql_st = _unpack_detection(cql_res)
        if cql_ver:
            cql_status = ToolStatus.UNKNOWN
            cql_avail = "available"
            cql_note = cql_notes or "Proprietary GitHub terms; user-managed mount"
        elif cql_st == ToolStatus.ERROR:
            cql_status = ToolStatus.ERROR
            cql_avail = "error"
            cql_note = cql_notes
        else:
            cql_status = ToolStatus.OPTIONAL
            cql_avail = "optional"
            cql_note = cql_notes or "Proprietary GitHub terms; optional integration"

        tools.append(
            ToolInfo(
                name="CodeQL",
                category=ToolCategory.ENGINE,
                installed_version=cql_ver,
                configured_version=configured.get("codeql", "external (optional)"),
                available_version=None,
                source="user-provided mount",
                update_policy="user-managed",
                availability=cql_avail,
                status=cql_status,
                notes=cql_note,
                runtime_source=RuntimeSource.EXTERNAL,
            )
        )

        # 3. Trivy
        trivy_res = self.detect_trivy()
        trivy_ver, trivy_notes, trivy_st = _unpack_detection(trivy_res)
        avail_trivy = self.check_upstream_version("trivy") if check_upstream else None
        trivy_status = self._evaluate_status(trivy_ver, avail_trivy, check_upstream, detected_status=trivy_st)
        tools.append(
            ToolInfo(
                name="Trivy",
                category=ToolCategory.ENGINE,
                installed_version=trivy_ver,
                configured_version=configured.get("trivy", "unpinned"),
                available_version=avail_trivy,
                source="aquasecurity binary (worker)",
                update_policy="manual / build",
                availability="available" if trivy_ver else ("error" if trivy_status == ToolStatus.ERROR else "unavailable"),
                status=trivy_status,
                notes=trivy_notes,
                runtime_source=RuntimeSource.WORKER,
            )
        )

        # 4. pip-audit
        pa_res = self.detect_pip_audit()
        pa_ver, pa_notes, pa_st = _unpack_detection(pa_res)
        avail_pa = self.check_upstream_version("pip-audit") if check_upstream else None
        pa_status = self._evaluate_status(pa_ver, avail_pa, check_upstream, detected_status=pa_st)
        tools.append(
            ToolInfo(
                name="pip-audit",
                category=ToolCategory.ENGINE,
                installed_version=pa_ver,
                configured_version=configured.get("pip-audit", "unpinned"),
                available_version=avail_pa,
                source="pypi (worker)",
                update_policy="manual / build",
                availability="available" if pa_ver else ("error" if pa_status == ToolStatus.ERROR else "unavailable"),
                status=pa_status,
                notes=pa_notes,
                runtime_source=RuntimeSource.WORKER,
            )
        )

        # 5. npm
        npm_res = self.detect_npm()
        npm_ver, npm_notes, npm_st = _unpack_detection(npm_res)
        npm_status = npm_st if npm_st is not None else (ToolStatus.UNKNOWN if npm_ver else ToolStatus.NOT_INSTALLED)
        tools.append(
            ToolInfo(
                name="npm",
                category=ToolCategory.ENGINE,
                installed_version=npm_ver,
                configured_version=configured.get("npm", "system package"),
                available_version=None,
                source="debian apt (worker)",
                update_policy="base-image",
                availability="available" if npm_ver else ("error" if npm_status == ToolStatus.ERROR else "unavailable"),
                status=npm_status,
                notes=npm_notes,
                runtime_source=RuntimeSource.WORKER,
            )
        )

        # 6. Nuclei
        nuclei_res = self.detect_nuclei()
        nuclei_ver, nuclei_notes, nuclei_st = _unpack_detection(nuclei_res)
        avail_nuclei = self.check_upstream_version("nuclei") if check_upstream else None
        nuclei_status = self._evaluate_status(nuclei_ver, avail_nuclei, check_upstream, detected_status=nuclei_st)
        tools.append(
            ToolInfo(
                name="Nuclei",
                category=ToolCategory.ENGINE,
                installed_version=nuclei_ver,
                configured_version=configured.get("nuclei", "3.3.2"),
                available_version=avail_nuclei,
                source="projectdiscovery binary (worker)",
                update_policy="pinned",
                availability="available" if nuclei_ver else ("error" if nuclei_status == ToolStatus.ERROR else "unavailable"),
                status=nuclei_status,
                notes=nuclei_notes,
                runtime_source=RuntimeSource.WORKER,
            )
        )

        # 7. ZAP
        zap_res = self.detect_zap()
        zap_ver, zap_notes, zap_st = _unpack_detection(zap_res)
        avail_zap = self.check_upstream_version("zap") if check_upstream else None
        zap_status = self._evaluate_status(zap_ver, avail_zap, check_upstream, detected_status=zap_st)
        tools.append(
            ToolInfo(
                name="ZAP",
                category=ToolCategory.ENGINE,
                installed_version=zap_ver,
                configured_version=configured.get("zap", "2.17.0"),
                available_version=avail_zap,
                source="zaproxy/zap-stable container",
                update_policy="pinned container",
                availability="available" if zap_ver else ("error" if zap_status == ToolStatus.ERROR else "unavailable"),
                status=zap_status,
                notes=zap_notes,
                runtime_source=RuntimeSource.CONTAINER,
            )
        )

        # 8. Nuclei Templates
        nt_res = self.detect_nuclei_templates()
        nt_ver, nt_notes, nt_st = _unpack_detection(nt_res)
        avail_nt = self.check_upstream_version("nuclei_templates") if check_upstream else None
        nt_status = self._evaluate_status(nt_ver, avail_nt, check_upstream, detected_status=nt_st)
        tools.append(
            ToolInfo(
                name="Nuclei Templates",
                category=ToolCategory.KNOWLEDGE,
                installed_version=nt_ver,
                configured_version=configured.get("nuclei_templates", "10.4.8"),
                available_version=avail_nt,
                source="projectdiscovery release (worker)",
                update_policy="pinned archive",
                availability="available" if nt_ver else ("error" if nt_status == ToolStatus.ERROR else "unavailable"),
                status=nt_status,
                notes=nt_notes,
                runtime_source=RuntimeSource.WORKER,
            )
        )

        # 9. Trivy Vulnerability DB
        tdb_res = self.detect_trivy_db()
        tdb_ver, tdb_notes, tdb_st = _unpack_detection(tdb_res)
        tdb_status = tdb_st if tdb_st is not None else (ToolStatus.UNKNOWN if tdb_ver else ToolStatus.NOT_INSTALLED)
        tools.append(
            ToolInfo(
                name="Trivy DB",
                category=ToolCategory.KNOWLEDGE,
                installed_version=tdb_ver,
                configured_version=configured.get("trivy_db", "dynamic / cached"),
                available_version=None,
                source="aquasecurity ghcr.io (worker cache)",
                update_policy="build-cached / runtime",
                availability="available" if tdb_ver else ("error" if tdb_status == ToolStatus.ERROR else "unavailable"),
                status=tdb_status,
                notes=tdb_notes,
                runtime_source=RuntimeSource.WORKER,
            )
        )

        # 10. Google Mantis
        from app.agents.mantis import DEFAULT_REVISION

        avail_mantis = self.check_upstream_version("mantis") if check_upstream else None
        mantis_avail_ver = avail_mantis[:8] if (check_upstream and avail_mantis) else None
        tools.append(
            ToolInfo(
                name="Mantis",
                category=ToolCategory.AGENT,
                installed_version=None,
                configured_version=configured.get("mantis", "disabled (contract only)"),
                available_version=mantis_avail_ver,
                source="google/mantis",
                update_policy="manual contract",
                availability="contract_only",
                status=ToolStatus.OPTIONAL,
                notes=f"Observed contract: {DEFAULT_REVISION[:8]}; active reproduction disabled",
                runtime_source=RuntimeSource.CONFIG_ONLY,
            )
        )

        return tools
