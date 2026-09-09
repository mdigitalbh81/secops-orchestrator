# Summary
<!-- What does this change do? -->

# Problem / Motivation
<!-- Why is this change needed? -->

# Changes
<!-- List the focused changes included in this PR. -->

# Validation
<!-- List commands/tests actually executed. -->
- [ ] `pytest` passes (when code changes require it)
- [ ] `ruff check .` passes (when Python code changes apply)
- [ ] `git diff --check` passes
- [ ] `docker compose config` passes (when Docker / Compose changes apply)
- [ ] Alembic state checked (when database / migration changes apply)

# Security / Compliance
- [ ] No secrets, credentials, tokens, private keys, or sensitive data included
- [ ] Third-party licensing reviewed when dependencies or tools are added or changed
- [ ] DAST safety controls and target validation remain intact (when applicable)
- [ ] Command execution remains parameterized and safe (when applicable)
- [ ] Security-sensitive behavior changes are documented

# Compatibility / Risk
<!-- Does this change affect:
- API compatibility?
- Database schema?
- CLI behavior?
- Docker / runtime behavior?
- Scanner output / fingerprints?
- Risk-gate behavior?
-->

# Related Issues
<!-- Closes # (optional) -->
<!-- Related to # (optional) -->

# Final Checklist
- [ ] Scope is focused on one logical change
- [ ] Tests added/updated where necessary
- [ ] Documentation updated when behavior changed
- [ ] No unrelated refactoring included
- [ ] Breaking changes explicitly documented
- [ ] I reviewed the diff before submitting
