# Contributing to SecOps Orchestrator

Contributions are welcome. SecOps Orchestrator is a source-available project built for automated multi-scanner security analysis and DevSecOps orchestration.

We welcome bug reports, documentation updates, new scanner integrations, test improvements, and operational fixes. All contributions must preserve the security, predictability, and non-destructive defaults of the project.

## Before You Start

Please review these principles before opening an issue or pull request:

1. Check existing issues and pull requests to ensure your topic is not already being addressed.
2. For substantial architectural changes or new scanner proposals, open an issue first to discuss scope, integration model, and licensing.
3. Never submit secrets, API keys, credentials, private tokens, private keys, or sensitive production data in pull requests, issues, logs, or test fixtures.
4. Security scanners and DAST tools must only be executed against systems, repositories, and URLs you own or have explicit, documented authorization to test.

## Development Workflow

We follow a standard Git workflow: Fork -> Branch -> Change -> Test -> Pull Request.

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Create a focused branch from `main`:
   `git checkout -b feat/my-improvement`
4. Implement your changes following existing codebase conventions.
5. Run automated validation commands locally.
6. Push your branch to your fork.
7. Open a Pull Request targeting `main`.

Recommended branch naming conventions:

- `feat/<short-description>`
- `fix/<short-description>`
- `docs/<short-description>`
- `scanner/<scanner-name>`
- `test/<short-description>`

These names are recommended conventions to help organize work, not rigid policies.

## Testing and Validation

Pull Requests trigger automated validation gates via GitHub Actions. When branch protection is active, all checks aggregated by `Gate` must pass before merge (branch protection rulesets are configured separately). Contributors must run these same validation commands locally before opening or updating a pull request.

Run standard validation commands using the project's canonical configuration:

```bash
# Run canonical pytest test suite
python -m pytest -c backend/pyproject.toml

# Run Ruff linter
python -m ruff check .

# Check for whitespace errors
git diff --check

# Validate base Docker Compose configuration
docker compose config
```

Verify database migrations status:

```bash
cd backend
alembic heads
cd ..
```

Migration rule: there must be **exactly one Alembic head** (the current baseline on `main` is `005 (head)`).

Testing guidelines:

- Add new database migrations only when strictly necessary for schema evolution.
- Scanner changes must include unit and integration tests covering applicability, execution arguments, and output normalization.
- CLI changes must include corresponding test coverage.
- Normalization, deduplication, correlation, and risk engine changes must include regression tests.
- DAST execution is not required for general contributions; mocked outputs and unit tests are preferred.

## Adding a New Scanner

All scanner integrations must adhere to the project architecture:

- Subclass `ScannerAdapter` defined in `backend/app/scanners/base.py`.
- Implement `is_available` and `detect_applicability` cleanly and predictably without side-effects.
- Execute tools via the secure runner in `app.security.runner` (`run_command`). Never use `shell=True` or spawn raw shell interpreters.
- Prevent arbitrary input execution and sanitize all command arguments.
- Normalize output into `NormalizedFinding` instances using `compute_fingerprint` and `compute_normalized_fingerprint`.
- Ensure fingerprints remain deterministic across repeated executions.
- Include unit tests with mock runner outputs.
- Clearly document the upstream project URL, license, and maintenance status.
- Specify the integration model: bundled in image, installed during image build, optional external CLI detected via worker `PATH`, or remote service/API.
- Review upstream software licensing before proposing an integration.
- Never automatically accept licenses or terms of service on behalf of the user.
- For DAST scanners, preserve all safety guardrails, including hostname and IP allowlist validation (`SECOPS_DAST_ALLOWED_HOSTS`, `app.security.dast_validator`).

## Security and DAST Changes

SecOps Orchestrator is designed for safe execution across pipelines:

- Never silently replace baseline or passive scanning with active scanning.
- Any expansion of scan depth, payload aggressiveness, or fuzzing must be explicit, configurable, and thoroughly reviewed.
- Do not remove host allowlist checks or bypass target URL validations.
- Do not weaken symlink escape prevention, path traversal checks, or runner isolation.
- Never commit real credentials, sensitive tokens, or proprietary artifacts into test fixtures.
- Production targets must only be scanned with explicit authorization from the system owner.

## Licensing of Contributions

SecOps Orchestrator applies an inbound-equals-outbound licensing policy:

By submitting a contribution, you agree that your contribution is distributed under the same license that applies to the SecOps Orchestrator source code version containing the contribution.

The project source code is governed by the [PolyForm Perimeter License 1.0.1](LICENSE). SecOps Orchestrator is a source-available project.

- You must hold the necessary rights to submit the code, either as original author or with proper authorization.
- Do not submit copied code with incompatible license terms.
- New third-party dependencies must have compatible and documented licenses. Update [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) when adding new dependencies.
- No Contributor License Agreement (CLA) or Developer Certificate of Origin (DCO) is required. You retain your copyright subject to the project license.

## Pull Request Guidelines

When opening a Pull Request, include:

- A clear and descriptive title.
- A summary of the problem and the proposed solution.
- A list of tests and commands executed locally.
- An assessment of risks or compatibility impacts.
- Screenshots or log excerpts only when helpful, with sensitive information redacted.
- Focused scope: keep changes atomic and avoid unrelated refactoring.

Pull request checklist:

- [ ] Scope is focused on a single logical change
- [ ] Tests added or updated where needed
- [ ] Canonical test suite passes (`python -m pytest -c backend/pyproject.toml`)
- [ ] Linter passes (`python -m ruff check .`)
- [ ] Whitespace check passes (`git diff --check`)
- [ ] Exactly one Alembic head exists (`cd backend && alembic heads && cd ..`)
- [ ] Docker Compose configuration remains valid (`docker compose config`) when applicable
- [ ] No secrets, credentials, or sensitive data included
- [ ] Third-party licensing reviewed when applicable
- [ ] Documentation updated when behavior changes
