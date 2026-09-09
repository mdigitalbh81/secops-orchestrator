"""Security toolchain inventory manager and health checker."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path

from app.toolchain.models import ToolCategory, ToolInfo, ToolStatus

logger = logging.getLogger(__name__)


def get_repo_root() -> Path | None:
    """Locate SecOps Orchestrator repository root directory."""
    env_root = os.environ.get("SECOPS_REPO_ROOT")
    if env_root:
        p = Path(env_root).resolve()
        if (p / "docker-compose.yml").is_file():
            return p

    try:
        # backend/app/toolchain/manager.py -> repo root is parents[3]
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
    """Extract semantic version (e.g. 1.2.3 or 1.2.3-beta) from arbitrary output."""
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
        """Check whether SecOps worker container is running."""
        if self._worker_running is not None:
            return self._worker_running

        if not shutil.which("docker"):
            self._worker_running = False
            return False

        try:
            cmd = self._get_compose_base() + ["ps", "-q", "worker"]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            self._worker_running = bool(res.returncode == 0 and res.stdout.strip())
        except Exception:
            self._worker_running = False

        return self._worker_running

    def run_safe_tool_command(
        self,
        cmd_argv: list[str],
        worker_argv: list[str] | None = None,
        timeout: int = 5,
    ) -> tuple[int, str, str]:
        """Execute version command on host if available, or inside worker if running."""
        host_bin = shutil.which(cmd_argv[0])
        if host_bin:
            try:
                res = subprocess.run(
                    cmd_argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                return res.returncode, res.stdout, res.stderr
            except subprocess.TimeoutExpired:
                return -1, "", "Command timed out"
            except Exception as exc:
                return -1, "", str(exc)

        if self.is_worker_running():
            exec_args = worker_argv or cmd_argv
            full_cmd = self._get_compose_base() + ["exec", "-T", "worker"] + exec_args
            try:
                res = subprocess.run(
                    full_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                return res.returncode, res.stdout, res.stderr
            except subprocess.TimeoutExpired:
                return -1, "", "Worker command timed out"
            except Exception as exc:
                return -1, "", str(exc)

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

    def detect_semgrep(self) -> tuple[str | None, str | None]:
        rc, stdout, stderr = self.run_safe_tool_command(["semgrep", "--version"])
        if rc == 0 and stdout:
            ver = parse_semantic_version(stdout)
            if ver:
                return ver, None
        return None, stderr.strip() or "Not found"

    def detect_pip_audit(self) -> tuple[str | None, str | None]:
        rc, stdout, stderr = self.run_safe_tool_command(["pip-audit", "--version"])
        if rc == 0 and stdout:
            ver = parse_semantic_version(stdout)
            if ver:
                return ver, None
        return None, stderr.strip() or "Not found"

    def detect_trivy(self) -> tuple[str | None, str | None]:
        rc, stdout, stderr = self.run_safe_tool_command(["trivy", "--version"])
        if rc == 0 and stdout:
            ver = parse_semantic_version(stdout)
            if ver:
                return ver, None
        return None, stderr.strip() or "Not found"

    def detect_npm(self) -> tuple[str | None, str | None]:
        rc, stdout, stderr = self.run_safe_tool_command(["npm", "--version"])
        if rc == 0 and stdout:
            ver = parse_semantic_version(stdout)
            if ver:
                return ver, None
        return None, stderr.strip() or "Not found"

    def detect_nuclei(self) -> tuple[str | None, str | None]:
        rc, stdout, stderr = self.run_safe_tool_command(["nuclei", "-version"])
        if rc == 0 and stdout:
            ver = parse_semantic_version(stdout)
            if ver:
                return ver, None
        return None, stderr.strip() or "Not found"

    def detect_codeql(self) -> tuple[str | None, str | None]:
        rc, stdout, stderr = self.run_safe_tool_command(["codeql", "version", "--format=json"])
        if rc == 0 and stdout:
            try:
                data = json.loads(stdout.strip())
                if isinstance(data, dict) and data.get("version"):
                    return str(data["version"]).strip(), None
            except Exception:
                ver = parse_semantic_version(stdout)
                if ver:
                    return ver, None
        return None, stderr.strip() or "Optional external CodeQL not detected"

    def detect_zap(self) -> tuple[str | None, str | None]:
        if shutil.which("docker"):
            try:
                res = subprocess.run(
                    ["docker", "inspect", "secops-zap", "--format", "{{.Config.Image}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    img = res.stdout.strip()
                    ver = img.split(":")[-1] if ":" in img else img
                    return ver, "container secops-zap"
            except Exception as exc:
                logger.debug("Failed inspecting secops-zap container: %s", exc)

        return None, "ZAP container not running"

    def detect_nuclei_templates(self) -> tuple[str | None, str | None]:
        rc, stdout, _ = self.run_safe_tool_command(
            ["cat", "/home/secops/.config/nuclei/.templates-config.json"],
            worker_argv=["cat", "/home/secops/.config/nuclei/.templates-config.json"],
        )
        if rc == 0 and stdout:
            try:
                cfg = json.loads(stdout.strip())
                ver = cfg.get("nuclei-templates-version")
                if ver:
                    return str(ver).lstrip("v"), None
            except Exception as exc:
                logger.debug("Failed parsing nuclei templates config: %s", exc)
        return None, "Templates config not accessible"

    def detect_trivy_db(self) -> tuple[str | None, str | None]:
        rc, stdout, _ = self.run_safe_tool_command(
            ["cat", "/home/secops/.cache/trivy/db/metadata.json"],
            worker_argv=["cat", "/home/secops/.cache/trivy/db/metadata.json"],
        )
        if rc == 0 and stdout:
            try:
                meta = json.loads(stdout.strip())
                schema = meta.get("Version", 2)
                updated = meta.get("UpdatedAt", "downloaded")
                return f"v{schema} ({str(updated)[:10]})", None
            except Exception as exc:
                logger.debug("Failed parsing trivy metadata: %s", exc)
        return None, "DB cache metadata not accessible"

    def check_upstream_version(self, tool_id: str) -> str | None:
        """Fetch latest upstream release version gracefully. Returns None on network error."""
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

    def get_inventory(self, check_upstream: bool = False) -> list[ToolInfo]:
        """Build full structured inventory for all monitored security tools."""
        configured = self.detect_configured_versions()
        tools: list[ToolInfo] = []

        # 1. Semgrep
        inst_ver, _ = self.detect_semgrep()
        avail_ver = self.check_upstream_version("semgrep") if check_upstream else None
        status = self._evaluate_status(inst_ver, avail_ver, check_upstream)
        tools.append(
            ToolInfo(
                name="Semgrep",
                category=ToolCategory.ENGINE,
                installed_version=inst_ver,
                configured_version=configured.get("semgrep", "unpinned"),
                available_version=avail_ver,
                source="pypi (worker)",
                update_policy="manual / build",
                availability="available" if inst_ver else "unavailable",
                status=status,
            )
        )

        # 2. CodeQL
        cql_ver, _ = self.detect_codeql()
        tools.append(
            ToolInfo(
                name="CodeQL",
                category=ToolCategory.ENGINE,
                installed_version=cql_ver,
                configured_version=configured.get("codeql", "external (optional)"),
                available_version=None,
                source="user-provided mount",
                update_policy="user-managed",
                availability="available" if cql_ver else "optional",
                status=ToolStatus.CURRENT if cql_ver else ToolStatus.OPTIONAL,
                notes="Proprietary GitHub terms; optional integration",
            )
        )

        # 3. Trivy
        trivy_ver, _ = self.detect_trivy()
        avail_trivy = self.check_upstream_version("trivy") if check_upstream else None
        tools.append(
            ToolInfo(
                name="Trivy",
                category=ToolCategory.ENGINE,
                installed_version=trivy_ver,
                configured_version=configured.get("trivy", "unpinned"),
                available_version=avail_trivy,
                source="aquasecurity binary",
                update_policy="manual / build",
                availability="available" if trivy_ver else "unavailable",
                status=self._evaluate_status(trivy_ver, avail_trivy, check_upstream),
            )
        )

        # 4. pip-audit
        pa_ver, _ = self.detect_pip_audit()
        avail_pa = self.check_upstream_version("pip-audit") if check_upstream else None
        tools.append(
            ToolInfo(
                name="pip-audit",
                category=ToolCategory.ENGINE,
                installed_version=pa_ver,
                configured_version=configured.get("pip-audit", "unpinned"),
                available_version=avail_pa,
                source="pypi (worker)",
                update_policy="manual / build",
                availability="available" if pa_ver else "unavailable",
                status=self._evaluate_status(pa_ver, avail_pa, check_upstream),
            )
        )

        # 5. npm
        npm_ver, _ = self.detect_npm()
        tools.append(
            ToolInfo(
                name="npm",
                category=ToolCategory.ENGINE,
                installed_version=npm_ver,
                configured_version=configured.get("npm", "system package"),
                available_version=None,
                source="debian apt (worker)",
                update_policy="base-image",
                availability="available" if npm_ver else "unavailable",
                status=ToolStatus.CURRENT if npm_ver else ToolStatus.NOT_INSTALLED,
            )
        )

        # 6. Nuclei
        nuclei_ver, _ = self.detect_nuclei()
        avail_nuclei = self.check_upstream_version("nuclei") if check_upstream else None
        tools.append(
            ToolInfo(
                name="Nuclei",
                category=ToolCategory.ENGINE,
                installed_version=nuclei_ver,
                configured_version=configured.get("nuclei", "3.3.2"),
                available_version=avail_nuclei,
                source="projectdiscovery binary",
                update_policy="pinned",
                availability="available" if nuclei_ver else "unavailable",
                status=self._evaluate_status(nuclei_ver, avail_nuclei, check_upstream),
            )
        )

        # 7. ZAP
        zap_ver, _ = self.detect_zap()
        avail_zap = self.check_upstream_version("zap") if check_upstream else None
        tools.append(
            ToolInfo(
                name="ZAP",
                category=ToolCategory.ENGINE,
                installed_version=zap_ver,
                configured_version=configured.get("zap", "2.17.0"),
                available_version=avail_zap,
                source="zaproxy/zap-stable container",
                update_policy="pinned container",
                availability="available" if zap_ver else "unavailable",
                status=self._evaluate_status(zap_ver, avail_zap, check_upstream),
            )
        )

        # 8. Nuclei Templates
        nt_ver, _ = self.detect_nuclei_templates()
        avail_nt = self.check_upstream_version("nuclei_templates") if check_upstream else None
        tools.append(
            ToolInfo(
                name="Nuclei Templates",
                category=ToolCategory.KNOWLEDGE,
                installed_version=nt_ver,
                configured_version=configured.get("nuclei_templates", "10.4.8"),
                available_version=avail_nt,
                source="projectdiscovery release",
                update_policy="pinned archive",
                availability="available" if nt_ver else "unavailable",
                status=self._evaluate_status(nt_ver, avail_nt, check_upstream),
            )
        )

        # 9. Trivy Vulnerability DB
        tdb_ver, _ = self.detect_trivy_db()
        tools.append(
            ToolInfo(
                name="Trivy DB",
                category=ToolCategory.KNOWLEDGE,
                installed_version=tdb_ver,
                configured_version=configured.get("trivy_db", "dynamic / cached"),
                available_version=None,
                source="aquasecurity ghcr.io",
                update_policy="build-cached / runtime",
                availability="available" if tdb_ver else "unavailable",
                status=ToolStatus.CURRENT if tdb_ver else ToolStatus.UNKNOWN,
            )
        )

        # 10. Google Mantis
        from app.agents.mantis import DEFAULT_REVISION

        tools.append(
            ToolInfo(
                name="Mantis",
                category=ToolCategory.AGENT,
                installed_version=None,
                configured_version=configured.get("mantis", "disabled (contract only)"),
                available_version=DEFAULT_REVISION[:8],
                source="google/mantis",
                update_policy="manual contract",
                availability="contract_only",
                status=ToolStatus.OPTIONAL,
                notes="Agentic framework integration boundary; active reproduction disabled",
            )
        )

        return tools

    def _evaluate_status(
        self,
        installed: str | None,
        available: str | None,
        check_upstream: bool,
    ) -> ToolStatus:
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
