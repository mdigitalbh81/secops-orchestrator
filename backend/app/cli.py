"""SecOps Orchestrator CLI.

Provides a unified, user-friendly command-line experience for scanning repositories,
inspecting reports, viewing findings, and running health checks.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VERSION = "0.4.1"
DEFAULT_API_URL = "http://localhost:8008"
ALLOWED_WORKSPACE_ROOT = "/tmp/secops-workspaces"


def get_api_base_url() -> str:
    return os.environ.get("SECOPS_API_URL", DEFAULT_API_URL).rstrip("/")


def get_state_file_path() -> Path:
    xdg_state = os.environ.get("XDG_STATE_HOME")
    base_dir = Path(xdg_state) if xdg_state else Path.home() / ".local" / "state"
    return base_dir / "secops-orchestrator" / "state.json"


def load_state() -> dict[str, Any] | None:
    state_path = get_state_file_path()
    if not state_path.is_file():
        return None
    try:
        with open(state_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_state(data: dict[str, Any]) -> None:
    state_path = get_state_file_path()
    state_dir = state_path.parent
    state_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(state_dir, 0o700)

    tmp_path = state_dir / f"state.json.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        with contextlib.suppress(OSError):
            os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, state_path)
    except Exception:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def get_secops_repo_root() -> Path | None:
    # Check environment variable first
    env_root = os.environ.get("SECOPS_REPO_ROOT")
    if env_root:
        p = Path(env_root).resolve()
        if (p / "docker-compose.yml").is_file():
            return p

    # Check relative to this module file: backend/app/cli.py -> repo_root is parents[2]
    try:
        mod_root = Path(__file__).resolve().parents[2]
        if (mod_root / "docker-compose.yml").is_file():
            return mod_root
    except (IndexError, ValueError):
        pass

    # Check argv[0] directory
    with contextlib.suppress(Exception):
        argv_dir = Path(sys.argv[0]).resolve().parent
        if (argv_dir / "docker-compose.yml").is_file():
            return argv_dir
        if (argv_dir.parent / "docker-compose.yml").is_file():
            return argv_dir.parent

    return None


def normalize_git_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url:
        return ""
    # Handle scp-like syntax: git@github.com:owner/repo.git
    if url.startswith("git@") and ":" in url:
        user_host, path = url.split(":", 1)
        host = user_host[4:] if user_host.startswith("git@") else user_host
        url = f"https://{host}/{path.lstrip('/')}"
    elif url.startswith("ssh://"):
        url = url[6:]
        if "@" in url:
            url = url.split("@", 1)[1]
        url = f"https://{url}"
    elif url.startswith("http://"):
        url = f"https://{url[7:]}"

    if not url.endswith(".git"):
        url = f"{url}.git"
    return url.lower()



def normalize_dast_hostname(url: str) -> str:
    """Extract and normalize hostname from a URL for stable DAST project identity.

    Rules: lowercase, strip trailing dot, ignore path/query/fragment,
    include port only when non-default (not 80 for http, not 443 for https).
    """
    parsed = urllib.parse.urlparse(url.strip())
    scheme = parsed.scheme.lower() or "https"
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError(f"Cannot extract hostname from URL: {url}")
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        return f"{hostname}:{port}"
    return hostname


def resolve_dast_project(
    api: ApiClient,
    target_url: str,
    explicit_project_id: str | None = None,
) -> tuple[str, str]:
    """Resolve or create a Project for a DAST-only scan.

    Identity is based on normalized hostname. Project name uses
    prefix "DAST: <hostname>" to avoid collisions with source-code projects.
    """
    # 1. Explicit --project-id
    if explicit_project_id:
        try:
            proj = api.get(f"/api/projects/{explicit_project_id}")
            return proj["id"], proj.get("name", explicit_project_id)
        except Exception as exc:
            raise RuntimeError(
                f"Project with ID '{explicit_project_id}' not found: {exc}"
            ) from exc

    hostname = normalize_dast_hostname(target_url)
    dast_project_name = f"DAST: {hostname}"

    # 2. Search by exact name
    candidates = api.get("/api/projects", query_params={"name": dast_project_name})
    if len(candidates) == 1:
        return candidates[0]["id"], candidates[0]["name"]
    elif len(candidates) > 1:
        id_list = ", ".join(f"{c['id']} ({c['name']})" for c in candidates)
        raise RuntimeError(
            f"Ambiguous DAST project match for '{hostname}'. "
            f"Multiple projects found: {id_list}. "
            f"Please specify --project-id explicitly."
        )

    # 3. Create new project
    new_proj = api.post("/api/projects", body={
        "name": dast_project_name,
        "description": f"DAST-only target: {hostname}",
    })
    return new_proj["id"], new_proj["name"]


@dataclass
class GitMetadata:
    repo_name: str
    branch: str
    commit_short: str
    commit_full: str
    remote_url: str | None
    is_dirty: bool


def inspect_git_repo(path: Path) -> GitMetadata:
    if not path.is_dir():
        raise ValueError(f"Directory not found: {path}")

    # Verify it is a valid git repository
    res = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    if res.returncode != 0 or res.stdout.strip() != "true":
        raise ValueError(f"Not a valid git repository: {path}")

    # Branch
    branch_res = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    branch = branch_res.stdout.strip() or "HEAD"

    # Short commit
    short_res = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    commit_short = short_res.stdout.strip()

    # Full commit SHA
    full_res = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    commit_full = full_res.stdout.strip()

    # Remote origin URL
    remote_res = subprocess.run(
        ["git", "config", "--get", "remote.origin.url"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    remote_url = remote_res.stdout.strip() or None

    # Working tree status
    status_res = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    is_dirty = bool(status_res.stdout.strip())

    repo_name = path.name
    if remote_url:
        clean_rem = remote_url.rstrip("/").removesuffix(".git")
        if "/" in clean_rem:
            extracted_name = clean_rem.split("/")[-1].split(":")[-1]
            if extracted_name:
                repo_name = extracted_name

    return GitMetadata(
        repo_name=repo_name,
        branch=branch,
        commit_short=commit_short,
        commit_full=commit_full,
        remote_url=remote_url,
        is_dirty=is_dirty,
    )


class ApiClient:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or get_api_base_url()).rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        query_params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> Any:
        url = f"{self.base_url}{path}"
        if query_params:
            clean_params = {k: v for k, v in query_params.items() if v is not None}
            if clean_params:
                qs = urllib.parse.urlencode(clean_params)
                url = f"{url}?{qs}"

        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError(f"Invalid API URL scheme: {url}")
        req = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
                resp_bytes = response.read()
                if not resp_bytes:
                    return None
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            detail = err_body
            with contextlib.suppress(Exception):
                err_json = json.loads(err_body)
                detail = err_json.get("detail", err_body)
            raise RuntimeError(f"API Error {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to connect to API at {self.base_url}: {e.reason}") from e

    def get(self, path: str, query_params: dict[str, Any] | None = None) -> Any:
        return self.request("GET", path, query_params=query_params)

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self.request("POST", path, body=body)


def resolve_project(
    api: ApiClient,
    project_path: Path,
    git_meta: GitMetadata,
    explicit_project_id: str | None = None,
) -> tuple[str, str]:
    """Resolve or create Project, returning (project_id, project_name)."""
    # 1. Explicit --project-id
    if explicit_project_id:
        try:
            proj = api.get(f"/api/projects/{explicit_project_id}")
            return proj["id"], proj.get("name", explicit_project_id)
        except Exception as exc:
            raise RuntimeError(f"Project with ID '{explicit_project_id}' not found: {exc}") from exc

    # 2 & 3. Normalized remote origin
    if git_meta.remote_url:
        norm_url = normalize_git_url(git_meta.remote_url)
        # Try exact search on backend
        candidates = api.get("/api/projects", query_params={"repository_url": norm_url})
        if not candidates:
            # Try raw remote url
            candidates = api.get("/api/projects", query_params={"repository_url": git_meta.remote_url})
        if not candidates:
            # Fall back to client-side normalized comparison over all projects
            all_projects = api.get("/api/projects")
            candidates = [
                p for p in all_projects
                if p.get("repository_url") and normalize_git_url(p["repository_url"]) == norm_url
            ]

        if len(candidates) == 1:
            return candidates[0]["id"], candidates[0]["name"]
        elif len(candidates) > 1:
            id_list = ", ".join(f"{c['id']} ({c['name']})" for c in candidates)
            raise RuntimeError(
                f"Ambiguous repository match for '{git_meta.remote_url}'. Multiple projects found: {id_list}. "
                f"Please specify --project-id explicitly."
            )

    # 5. Search by exact directory/repository name
    by_name = api.get("/api/projects", query_params={"name": git_meta.repo_name})
    if not by_name and project_path.name != git_meta.repo_name:
        by_name = api.get("/api/projects", query_params={"name": project_path.name})

    if len(by_name) == 1:
        return by_name[0]["id"], by_name[0]["name"]
    elif len(by_name) > 1:
        id_list = ", ".join(f"{c['id']} ({c['name']})" for c in by_name)
        raise RuntimeError(
            f"Ambiguous project name match for '{git_meta.repo_name}'. Multiple projects found: {id_list}. "
            f"Please specify --project-id explicitly."
        )

    # 8. Create new project
    norm_remote = normalize_git_url(git_meta.remote_url) if git_meta.remote_url else None
    new_proj = api.post(
        "/api/projects",
        body={
            "name": git_meta.repo_name,
            "repository_url": norm_remote,
            "description": f"Automated project for {git_meta.repo_name}",
        },
    )
    return new_proj["id"], new_proj["name"]


def get_project_internal_workspace(api: ApiClient, project_id: str) -> str:
    """Determine safe internal workspace path, reusing existing if present."""
    with contextlib.suppress(Exception):
        scans = api.get(f"/api/projects/{project_id}/scans", query_params={"limit": 1})
        if scans and len(scans) > 0:
            prev_path = scans[0].get("source_path", "")
            if prev_path.startswith(ALLOWED_WORKSPACE_ROOT) and ".." not in prev_path:
                return prev_path

    return f"{ALLOWED_WORKSPACE_ROOT}/{project_id}"


def deploy_snapshot(
    repo_root: Path | None,
    project_path: Path,
    internal_workspace: str,
) -> None:
    """Safely streams git archive HEAD into the worker container volume."""
    # Strong path validation: must be within ALLOWED_WORKSPACE_ROOT and no traversal
    clean_dest = os.path.normpath(internal_workspace)
    if not clean_dest.startswith(f"{ALLOWED_WORKSPACE_ROOT}/") or ".." in clean_dest:
        raise ValueError(f"Refusing to deploy snapshot: unsafe destination '{internal_workspace}'")

    compose_base = ["docker", "compose"]
    if repo_root and (repo_root / "docker-compose.yml").is_file():
        compose_base += ["-f", str(repo_root / "docker-compose.yml")]

    # 1. Clean workspace directory inside worker container
    rm_res = subprocess.run(
        compose_base + ["exec", "-T", "worker", "rm", "-rf", clean_dest],
        capture_output=True,
        text=True,
    )
    if rm_res.returncode != 0:
        raise RuntimeError(f"Failed to reset workspace in worker: {rm_res.stderr.strip()}")

    # 2. Create target directory inside worker container
    mkdir_res = subprocess.run(
        compose_base + ["exec", "-T", "worker", "mkdir", "-p", clean_dest],
        capture_output=True,
        text=True,
    )
    if mkdir_res.returncode != 0:
        raise RuntimeError(f"Failed to create workspace directory in worker: {mkdir_res.stderr.strip()}")

    # 3. Stream git archive HEAD directly to tar extraction inside worker
    p_archive = subprocess.Popen(
        ["git", "archive", "HEAD"],
        cwd=str(project_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    p_tar = subprocess.Popen(
        compose_base + ["exec", "-T", "worker", "tar", "-x", "-C", clean_dest],
        stdin=p_archive.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p_archive.stdout:
        p_archive.stdout.close()

    tar_out, tar_err = p_tar.communicate()
    arch_out, arch_err = p_archive.communicate()

    if p_archive.returncode != 0:
        raise RuntimeError(f"git archive failed: {arch_err.decode(errors='replace').strip()}")
    if p_tar.returncode != 0:
        raise RuntimeError(f"Snapshot extraction in worker failed: {tar_err.decode(errors='replace').strip()}")


def preflight_check(api: ApiClient, auto_start: bool = True) -> tuple[bool, str]:
    """Verify git, docker, docker daemon, api, and worker."""
    # 1. Git
    try:
        res = subprocess.run(["git", "--version"], capture_output=True, text=True)
        if res.returncode != 0:
            return False, "Git command returned non-zero. Please verify git installation."
    except FileNotFoundError:
        return False, "Git is not installed or not available in PATH."

    # 2. Docker
    try:
        res = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if res.returncode != 0:
            return False, "Docker command returned non-zero. Please verify docker installation."
    except FileNotFoundError:
        return False, "Docker is not installed or not available in PATH."

    # 3. Docker Daemon
    info_res = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if info_res.returncode != 0:
        return False, "Docker daemon is not running or not accessible by current user."

    # 4. API check
    api_ok = False
    try:
        health = api.get("/health")
        if health and health.get("status") == "ok":
            api_ok = True
    except Exception:
        api_ok = False

    repo_root = get_secops_repo_root()

    if not api_ok and auto_start and repo_root:
        compose_file = repo_root / "docker-compose.yml"
        if compose_file.is_file():
            sys.stderr.write("Starting SecOps services via Docker Compose...\n")
            subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "up", "-d"],
                capture_output=True,
                text=True,
            )
            # Wait up to 30s for API
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                time.sleep(1.5)
                with contextlib.suppress(Exception):
                    health = api.get("/health")
                    if health and health.get("status") == "ok":
                        api_ok = True
                        break

    if not api_ok:
        return False, f"SecOps API is unreachable at {api.base_url}. Start the stack with 'docker compose up -d'."

    # 5. Worker check
    compose_base = ["docker", "compose"]
    if repo_root and (repo_root / "docker-compose.yml").is_file():
        compose_base += ["-f", str(repo_root / "docker-compose.yml")]

    ps_worker = subprocess.run(compose_base + ["ps", "-q", "worker"], capture_output=True, text=True)
    worker_id = ps_worker.stdout.strip()
    if not worker_id and auto_start and repo_root:
        subprocess.run(compose_base + ["up", "-d", "worker"], capture_output=True, text=True)
        time.sleep(2.0)
        ps_worker = subprocess.run(compose_base + ["ps", "-q", "worker"], capture_output=True, text=True)
        worker_id = ps_worker.stdout.strip()

    if not worker_id:
        return False, "SecOps worker service is not running."

    return True, "Preflight checks passed."


def format_scanner_runs(scanner_runs: dict[str, str]) -> str:
    active: list[str] = []
    inactive: list[str] = []

    name_map = {
        "semgrep": "Semgrep",
        "codeql": "CodeQL",
        "npm-audit": "npm-audit",
        "pip-audit": "pip-audit",
        "trivy": "Trivy",
        "ai-appsec": "AppSec",
        "zap": "ZAP",
        "nuclei": "Nuclei",
    }

    for raw_name, status in scanner_runs.items():
        label = name_map.get(raw_name, raw_name)
        st = status.lower()
        if st in ("completed", "running", "partial", "applicable"):
            active.append(label)
        elif st == "unavailable":
            inactive.append(f"{label} unavailable")
        elif st == "not_applicable":
            inactive.append(f"{label} not applicable")
        elif st == "failed":
            inactive.append(f"{label} failed")

    active_str = ", ".join(active) if active else "None"
    if inactive:
        return f"{active_str} ({', '.join(inactive)})"
    return active_str


def print_human_report(
    project_name: str,
    branch: str | None,
    commit: str | None,
    summary: dict[str, Any],
) -> None:
    print(f"SecOps Orchestrator v{VERSION}")
    print(f"Project: {project_name}")
    if branch:
        print(f"Branch: {branch}")
    if commit:
        print(f"Commit: {commit}")
    print()

    scanner_runs = summary.get("scanner_runs", {})
    if scanner_runs:
        print(f"Scanning: {format_scanner_runs(scanner_runs)}")
        print()

    totals = summary.get("totals", {})
    print("Findings:")
    print(f"  Critical: {totals.get('critical', 0)}")
    print(f"  High:     {totals.get('high', 0)}")
    print(f"  Medium:   {totals.get('medium', 0)}")
    print(f"  Low:      {totals.get('low', 0)}")
    print(f"  Info:     {totals.get('info', 0)}")
    print(f"  Unknown:  {totals.get('unknown', 0)}")
    print()

    print("Dispositions:")
    print(f"  Open:             {summary.get('actionable_count', 0)}")
    print(f"  False Positive:   {summary.get('false_positive_count', 0)}")
    print(f"  Accepted Risk:    {summary.get('accepted_risk_count', 0)}")
    print(f"  Accepted Design:  {summary.get('accepted_by_design_count', 0)}")
    print(f"  Fixed:            {summary.get('fixed_count', 0)}")
    print()

    risk_gate = summary.get("risk_gate", "UNKNOWN")
    print(f"Risk Gate: {risk_gate}")
    print(f"Scan: {summary.get('scan_id')}")


def cmd_dast(args: argparse.Namespace, api: ApiClient) -> int:
    """Execute a DAST-only scan against a URL (no source code required)."""
    target_url = args.url

    # Basic URL syntax validation
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        sys.stderr.write(f"Error: Invalid URL scheme '{parsed.scheme}'. Use http:// or https://\n")
        return 1
    if not parsed.hostname:
        sys.stderr.write("Error: URL must contain a valid hostname.\n")
        return 1

    # Preflight check
    ok, preflight_msg = preflight_check(api, auto_start=True)
    if not ok:
        sys.stderr.write(f"Error: {preflight_msg}\n")
        return 1

    # Resolve / create Project for this DAST target
    try:
        project_id, project_name = resolve_dast_project(
            api, target_url, explicit_project_id=getattr(args, "project_id", None),
        )
    except RuntimeError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    if not args.json:
        print(f"SecOps Orchestrator v{VERSION}")
        print("Mode:    DAST only")
        print(f"Target:  {target_url}")
        print(f"Project: {project_name}")
        print()

    # Create scan with DAST_ONLY mode
    scan_payload: dict[str, Any] = {
        "project_id": project_id,
        "target_url": target_url,
        "scan_mode": "DAST_ONLY",
    }
    try:
        scan = api.post("/api/scans", body=scan_payload)
    except RuntimeError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    scan_id = scan["id"]

    if not args.json:
        print("Scanning...")

    # Poll scan status
    while True:
        time.sleep(2.0)
        try:
            scan_status_obj = api.get(f"/api/scans/{scan_id}")
        except RuntimeError as exc:
            sys.stderr.write(f"Error polling scan: {exc}\n")
            return 1
        if scan_status_obj.get("status") in ("COMPLETED", "FAILED"):
            break

    # Get summary
    try:
        summary = api.get(f"/api/scans/{scan_id}/summary")
    except RuntimeError as exc:
        sys.stderr.write(f"Error retrieving scan summary: {exc}\n")
        return 1

    # Save state file (no project_path for DAST-only)
    save_state({
        "project_id": project_id,
        "project_name": project_name,
        "scan_id": scan_id,
        "project_path": None,
        "branch": None,
        "commit": None,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    # Output
    if args.json:
        output = {
            "project": {
                "id": project_id,
                "name": project_name,
            },
            "target_url": target_url,
            "mode": "DAST_ONLY",
            "scan": scan_status_obj,
            "summary": summary,
        }
        print(json.dumps(output, indent=2))
    else:
        print_dast_report(
            project_name=project_name,
            target_url=target_url,
            summary=summary,
        )

    if scan_status_obj.get("status") == "FAILED":
        err = scan_status_obj.get("error_message") or "Scan execution failed."
        sys.stderr.write(f"Scan FAILED: {err}\n")
        return 1

    return 0


def print_dast_report(
    project_name: str,
    target_url: str,
    summary: dict[str, Any],
) -> None:
    """Print human-readable DAST-only scan report."""
    print(f"SecOps Orchestrator v{VERSION}")
    print("Mode:    DAST only")
    print(f"Target:  {target_url}")
    print(f"Project: {project_name}")
    print()

    scanner_runs = summary.get("scanner_runs", {})
    if scanner_runs:
        print(f"Scanning: {format_scanner_runs(scanner_runs)}")
        print()

    totals = summary.get("totals", {})
    print("Findings:")
    print(f"  Critical: {totals.get('critical', 0)}")
    print(f"  High:     {totals.get('high', 0)}")
    print(f"  Medium:   {totals.get('medium', 0)}")
    print(f"  Low:      {totals.get('low', 0)}")
    print(f"  Info:     {totals.get('info', 0)}")
    print()

    risk_gate = summary.get("risk_gate", "UNKNOWN")
    print(f"Risk Gate: {risk_gate}")
    print(f"Scan: {summary.get('scan_id')}")


def cmd_audit(args: argparse.Namespace, api: ApiClient) -> int:
    target_path = Path(args.path).expanduser().resolve()

    # Inspect git repo
    try:
        git_meta = inspect_git_repo(target_path)
    except ValueError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    # Working tree check
    if git_meta.is_dirty:
        msg = "Working tree contains uncommitted changes. Auditing committed HEAD only.\n"
        if args.json:
            sys.stderr.write(msg)
        else:
            print(msg.strip())

    # Preflight check
    ok, preflight_msg = preflight_check(api, auto_start=True)
    if not ok:
        sys.stderr.write(f"Error: {preflight_msg}\n")
        return 1

    # Resolve or create Project
    try:
        project_id, project_name = resolve_project(
            api,
            target_path,
            git_meta,
            explicit_project_id=args.project_id,
        )
    except RuntimeError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    # Internal workspace
    repo_root = get_secops_repo_root()
    internal_ws = get_project_internal_workspace(api, project_id)

    if not args.json:
        print("Preparing snapshot...")

    try:
        deploy_snapshot(repo_root, target_path, internal_ws)
    except Exception as exc:
        sys.stderr.write(f"Error preparing snapshot: {exc}\n")
        return 1

    if not args.json:
        print("Starting scan...")

    # Create scan via API
    scan_payload: dict[str, Any] = {
        "project_id": project_id,
        "source_path": internal_ws,
    }
    if args.url:
        scan_payload["target_url"] = args.url

    try:
        scan = api.post("/api/scans", body=scan_payload)
    except RuntimeError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    scan_id = scan["id"]

    # Poll scan status
    while True:
        time.sleep(2.0)
        try:
            scan_status_obj = api.get(f"/api/scans/{scan_id}")
        except RuntimeError as exc:
            sys.stderr.write(f"Error polling scan: {exc}\n")
            return 1

        st = scan_status_obj.get("status")
        if st in ("COMPLETED", "FAILED"):
            break

    # Get summary
    try:
        summary = api.get(f"/api/scans/{scan_id}/summary")
    except RuntimeError as exc:
        sys.stderr.write(f"Error retrieving scan summary: {exc}\n")
        return 1

    # Save state file
    save_state({
        "project_id": project_id,
        "project_name": project_name,
        "scan_id": scan_id,
        "project_path": str(target_path),
        "branch": git_meta.branch,
        "commit": git_meta.commit_short,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    # Output
    if args.json:
        output = {
            "project": {
                "id": project_id,
                "name": project_name,
                "branch": git_meta.branch,
                "commit": git_meta.commit_short,
                "path": str(target_path),
            },
            "scan": scan_status_obj,
            "summary": summary,
        }
        print(json.dumps(output, indent=2))
    else:
        print_human_report(
            project_name=project_name,
            branch=git_meta.branch,
            commit=git_meta.commit_short,
            summary=summary,
        )

    if scan_status_obj.get("status") == "FAILED":
        err = scan_status_obj.get("error_message") or "Scan execution failed."
        sys.stderr.write(f"Scan FAILED: {err}\n")
        return 1

    return 0


def resolve_scan_id(
    args: argparse.Namespace,
    api: ApiClient,
) -> tuple[str, str | None, str | None, str | None]:
    """Determine scan_id, project_name, branch, commit from args or state file."""
    # 1. Explicit --scan-id
    if getattr(args, "scan_id", None):
        return args.scan_id, None, None, None

    # 2. Path provided
    path_arg = getattr(args, "path", None)
    if path_arg:
        target_path = Path(path_arg).expanduser().resolve()
        try:
            git_meta = inspect_git_repo(target_path)
            project_id, project_name = resolve_project(
                api,
                target_path,
                git_meta,
                explicit_project_id=getattr(args, "project_id", None),
            )
        except Exception as exc:
            raise RuntimeError(f"Could not resolve project for path '{path_arg}': {exc}") from exc

        scans = api.get(f"/api/projects/{project_id}/scans", query_params={"limit": 1})
        if not scans:
            raise RuntimeError(f"No scans found for project '{project_name}' ({project_id})")
        return scans[0]["id"], project_name, git_meta.branch, git_meta.commit_short

    # 3. State file
    state = load_state()
    if state and state.get("scan_id"):
        return (
            state["scan_id"],
            state.get("project_name"),
            state.get("branch"),
            state.get("commit"),
        )

    raise RuntimeError("No scan specified. Run 'secops audit <path>' first or provide <path> / --scan-id.")


def cmd_report(args: argparse.Namespace, api: ApiClient) -> int:
    try:
        scan_id, proj_name, branch, commit = resolve_scan_id(args, api)
        summary = api.get(f"/api/scans/{scan_id}/summary")
        scan = api.get(f"/api/scans/{scan_id}")
    except RuntimeError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    if not proj_name:
        proj_id = scan.get("project_id")
        if proj_id:
            try:
                proj = api.get(f"/api/projects/{proj_id}")
                proj_name = proj.get("name", proj_id)
            except Exception:
                proj_name = proj_id
        else:
            proj_name = "Unknown"

    if args.json:
        output = {
            "scan": scan,
            "summary": summary,
        }
        print(json.dumps(output, indent=2))
    else:
        print_human_report(
            project_name=proj_name,
            branch=branch,
            commit=commit,
            summary=summary,
        )

    return 0


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}


def cmd_findings(args: argparse.Namespace, api: ApiClient) -> int:
    try:
        scan_id, _, _, _ = resolve_scan_id(args, api)
        findings: list[dict[str, Any]] = api.get(f"/api/scans/{scan_id}/findings")
    except RuntimeError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    # Status filter: default to OPEN unless --all or specific --status passed
    target_status = None
    if args.status:
        # Normalize status string
        norm_st = args.status.upper().replace("-", "_")
        target_status = norm_st
    elif not args.all:
        target_status = "OPEN"

    filtered: list[dict[str, Any]] = []
    for f in findings:
        # Status check
        if target_status and f.get("status") != target_status:
            continue

        # Severity check
        if args.severity:
            sev_filter = args.severity.upper()
            if f.get("severity", "").upper() != sev_filter:
                continue

        # Scanner check
        if args.scanner:
            scanner_filter = args.scanner.lower()
            if f.get("scanner_name", "").lower() != scanner_filter:
                continue

        filtered.append(f)

    # Deterministic sorting: severity -> scanner -> file/location -> title -> id
    def sort_key(item: dict[str, Any]) -> tuple:
        sev_rank = SEVERITY_ORDER.get(item.get("severity", "UNKNOWN"), 99)
        scanner = item.get("scanner_name", "").lower()
        loc = item.get("file_path") or item.get("package_name") or item.get("url") or ""
        line = item.get("line_start") or 0
        title = item.get("title", "")
        fid = item.get("id", "")
        return (sev_rank, scanner, loc, line, title, fid)

    filtered.sort(key=sort_key)

    if args.json:
        print(json.dumps(filtered, indent=2))
        return 0

    # Compact human output
    count = len(filtered)
    status_label = target_status or "TOTAL"
    sev_label = args.severity.upper() if args.severity else ""
    header_parts = [str(count)]
    if target_status:
        header_parts.append(status_label)
    if sev_label:
        header_parts.append(sev_label)
    header_parts.append("findings")
    print(" ".join(header_parts))
    print()

    for f in filtered:
        scanner = f.get("scanner_name", "").upper()
        sev = f.get("severity", "UNKNOWN").upper()
        status = f.get("status", "")
        status_tag = f" ({status})" if status and status != "OPEN" else ""

        # Location
        loc = ""
        if f.get("file_path"):
            loc = f.get("file_path")
            if f.get("line_start"):
                loc = f"{loc}:{f['line_start']}"
        elif f.get("package_name"):
            loc = f"pkg:{f['package_name']}"
            if f.get("installed_version"):
                loc = f"{loc}@{f['installed_version']}"
        elif f.get("url"):
            loc = f.get("url")
        else:
            loc = "project"

        title = f.get("title", "")
        print(f"{scanner} [{sev}]{status_tag} {loc} {title}")
        print(f"  ID: {f.get('id')}")
        print()

    return 0


def cmd_doctor(args: argparse.Namespace, api: ApiClient) -> int:
    repo_root = get_secops_repo_root()
    compose_base = ["docker", "compose"]
    if repo_root and (repo_root / "docker-compose.yml").is_file():
        compose_base += ["-f", str(repo_root / "docker-compose.yml")]

    all_ok = True

    # 1. Git
    try:
        res = subprocess.run(["git", "--version"], capture_output=True, text=True)
        if res.returncode == 0:
            git_ver = res.stdout.strip()
            print(f"[✓] Git: {git_ver}")
        else:
            print("[✗] Git: returned non-zero code")
            all_ok = False
    except FileNotFoundError:
        print("[✗] Git: not installed or not in PATH")
        all_ok = False

    # 2. Docker
    try:
        res = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if res.returncode == 0:
            doc_ver = res.stdout.strip()
            info_res = subprocess.run(["docker", "info"], capture_output=True, text=True)
            if info_res.returncode == 0:
                print(f"[✓] Docker: {doc_ver} (daemon running)")
            else:
                print(f"[✗] Docker: {doc_ver} (daemon unreachable)")
                all_ok = False
        else:
            print("[✗] Docker: returned non-zero code")
            all_ok = False
    except FileNotFoundError:
        print("[✗] Docker: not installed or not in PATH")
        all_ok = False

    # 3. Docker Compose
    try:
        res = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        if res.returncode == 0:
            dc_ver = res.stdout.strip()
            print(f"[✓] Docker Compose: {dc_ver}")
        else:
            print("[✗] Docker Compose: returned non-zero code")
            all_ok = False
    except FileNotFoundError:
        print("[✗] Docker Compose: not installed or not in PATH")
        all_ok = False

    # 4. API
    try:
        health = api.get("/health")
        if health and health.get("status") == "ok":
            print(f"[✓] API: {api.base_url} (healthy)")
        else:
            print(f"[✗] API: {api.base_url} responded with invalid health status: {health}")
            all_ok = False
    except Exception as exc:
        print(f"[✗] API: unreachable at {api.base_url} ({exc})")
        all_ok = False

    # Helper for checking container state
    def check_service(service_name: str, display_name: str) -> None:
        nonlocal all_ok
        try:
            ps_res = subprocess.run(compose_base + ["ps", "-q", service_name], capture_output=True, text=True)
            cid = ps_res.stdout.strip()
            if not cid:
                print(f"[✗] {display_name}: container not running")
                all_ok = False
                return
            # Check inspect status
            inspect_res = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}} (healthy: {{.State.Health.Status}})", cid],
                capture_output=True,
                text=True,
            )
            info = inspect_res.stdout.strip() if inspect_res.returncode == 0 else "running"
            # Clean up empty health string if no healthcheck
            info = info.replace(" (healthy: )", "").replace(" (healthy: <no value>)", "")
            print(f"[✓] {display_name}: {info}")
        except Exception as exc:
            print(f"[✗] {display_name}: check failed ({exc})")
            all_ok = False

    # 5. Worker
    check_service("worker", "Worker")

    # 6. PostgreSQL
    check_service("postgres", "PostgreSQL")

    # 7. Redis
    check_service("redis", "Redis")

    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secops",
        description="SecOps Orchestrator - Automated DevSecOps Platform CLI",
    )
    parser.add_argument("--version", action="version", version=f"SecOps Orchestrator v{VERSION}")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode and print tracebacks on failure")

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # audit
    audit_p = subparsers.add_parser("audit", help="Audit a repository committed HEAD")
    audit_p.add_argument("path", help="Path to local git repository")
    audit_p.add_argument("--url", dest="url", help="Target URL for DAST scanning")
    audit_p.add_argument("--project-id", dest="project_id", help="Explicit project ID")
    audit_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")


    # dast
    dast_p = subparsers.add_parser("dast", help="DAST-only scan against a URL (no source code)")
    dast_p.add_argument("url", help="Target URL for DAST scanning")
    dast_p.add_argument("--project-id", dest="project_id", help="Explicit project ID")
    dast_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # report
    report_p = subparsers.add_parser("report", help="Show summary report of scan")
    report_p.add_argument("path", nargs="?", help="Optional project directory path")
    report_p.add_argument("--scan-id", dest="scan_id", help="Scan UUID")
    report_p.add_argument("--project-id", dest="project_id", help="Explicit project ID")
    report_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # findings
    findings_p = subparsers.add_parser("findings", help="List scan findings")
    findings_p.add_argument("path", nargs="?", help="Optional project directory path")
    findings_p.add_argument("--scan-id", dest="scan_id", help="Scan UUID")
    findings_p.add_argument("--project-id", dest="project_id", help="Explicit project ID")
    findings_p.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info", "unknown"],
        help="Filter by severity",
    )
    findings_p.add_argument(
        "--status",
        choices=["open", "false-positive", "accepted-risk", "accepted-by-design", "fixed"],
        help="Filter by status",
    )
    findings_p.add_argument(
        "--scanner",
        help="Filter by scanner (codeql, semgrep, trivy, npm-audit, pip-audit, zap, nuclei, ai-appsec)",
    )
    findings_p.add_argument("--all", action="store_true", help="Include all statuses (not just OPEN)")
    findings_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # doctor
    subparsers.add_parser("doctor", help="Inspect local environment and infrastructure health")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    api = ApiClient()
    debug = args.debug or bool(os.environ.get("SECOPS_DEBUG"))

    try:
        if args.command == "audit":
            return cmd_audit(args, api)
        elif args.command == "dast":
            return cmd_dast(args, api)
        elif args.command == "report":
            return cmd_report(args, api)
        elif args.command == "findings":
            return cmd_findings(args, api)
        elif args.command == "doctor":
            return cmd_doctor(args, api)
        else:
            parser.print_help()
            return 0
    except Exception as exc:
        if debug:
            raise
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
