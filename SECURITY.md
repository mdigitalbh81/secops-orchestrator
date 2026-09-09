# Security Policy

SecOps Orchestrator is a security-focused, source-available project. Security reports are taken seriously, and responsible reporting is essential to protecting users and systems running the platform. Researchers and users are asked to avoid public disclosure of exploitable details prior to coordinated remediation, and to never include real secrets, credentials, private keys, tokens, or sensitive customer or production data in reports.

## Supported Versions

Security fixes are normally developed against the `main` branch and the latest published release, which serve as primary supported targets. Older releases are not guaranteed to receive backports. Reporters are asked to verify whether an issue exists on the current `main` branch or the latest release whenever possible.

## Reporting a Vulnerability

To protect users and systems, please do not disclose vulnerability details, reproduction steps, or exploit materials in public issues, pull requests, or discussions.

GitHub Private Vulnerability Reporting is not currently confirmed as enabled for this repository, and no dedicated security email address is published. Please use the following safe fallback:

1. Open a minimal public GitHub issue titled: `[Security Contact Request]`
2. In the issue description, do not include exploit details, reproduction steps, or secrets. State only that you have identified a potential security issue and request a private coordination channel with the maintainers.
3. A maintainer can then provide instructions for continuing the report through an appropriate private coordination channel.

If GitHub Private Vulnerability Reporting is enabled in the future, reports should be submitted privately through the repository Security tab.

## What to Include

To help assess and resolve reports efficiently, please provide:

- Affected SecOps Orchestrator version, release tag, or commit hash.
- Affected component (e.g., CLI, API, scanner adapter, orchestration worker, risk gate).
- Concise description of the security impact.
- Minimal, safe reproduction steps.
- Sanitized logs if helpful.
- Minimal proof of concept when strictly necessary.
- Expected security boundary versus actual observed behavior.
- Whether the issue reproduces on the latest release or current `main` branch if known.

Never submit real credentials, production secrets, or customer data. Always use sanitized or synthetic test values.

## Scope

In-scope components generally include:

- SecOps Orchestrator CLI.
- API and backend orchestration services.
- Scanner adapters and execution logic.
- Normalization, correlation, confidence scoring, and risk-gate logic when security-relevant.
- Docker and runtime container configurations shipped with SecOps Orchestrator.
- Workspace and snapshot isolation mechanisms.
- Path traversal and symlink escape protections.
- Command execution and subprocess argument handling.
- DAST target validation and host allowlist enforcement.
- Accidental secret exposure caused by SecOps Orchestrator itself.
- Dependency integration problems when SecOps Orchestrator usage materially introduces or exposes a vulnerability.

Out-of-scope guidance:

- Vulnerabilities that exist exclusively inside upstream third-party security scanners (these are normally reported directly to the upstream project).
- Vulnerabilities in scanned applications, target repositories, or external systems (these are findings of the scanners, not vulnerabilities in SecOps Orchestrator itself).
- Unauthorized security testing against third-party systems or non-consenting targets.

## Safe Testing Guidelines

When researching and verifying security issues:

- Test only against systems, repositories, and URLs you own or have explicit, documented permission to test.
- Avoid destructive testing actions.
- Avoid denial-of-service attacks and excessive resource exhaustion.
- Do not disable or bypass SecOps Orchestrator DAST allowlists merely to demonstrate an exploit report.
- Do not access, leak, or expose third-party data.
- Use minimal proofs of concept.
- Prefer local and isolated test environments.

SecOps Orchestrator does not grant authorization to test third-party systems or infrastructure.

## Coordinated Disclosure

Please avoid publishing technical exploit details while remediation is being coordinated. Maintainers may ask for clarification or reproduction assistance. Once remediation is developed and released, public disclosure will be coordinated where appropriate. Disclosure timelines depend on severity, technical complexity, and release impact.

## Third-Party Security Tools

SecOps Orchestrator integrates and orchestrates various third-party security tools (such as Semgrep, Trivy, pip-audit, Nuclei, OWASP ZAP, or optional GitHub CodeQL). Their own vulnerabilities and licensing remain governed by their respective upstream projects.

Flaws within SecOps Orchestrator's adapters, subprocess execution, or orchestration logic around these tools fall within the scope of this project; vulnerabilities residing solely inside an upstream tool normally belong upstream.
