# Agent Safety Doctor — Production-Grade MVP Acceptance Criteria

This is the quality bar for the local-first validation product before public use.

## CLI contract

- `agent-safety-doctor scan [path]` works from an installed console script and via `python -m agent_safety_doctor.cli`.
- Supports Markdown, JSON, and HTML output.
- Supports explicit config path and auto-discovers `.agent-safety-doctor.toml`.
- Supports `--fail-under <score>` for CI/pilot gating.
- Exits non-zero for invalid paths, invalid config, or fail-under violations.
- Does not print secret values to stdout or reports.

## Scanner contract

- Skips standard heavy/generated directories.
- Supports configurable ignore globs.
- Avoids scanning binary/oversized files.
- Detects:
  - secret-looking file names;
  - secret-looking assignments in text without leaking values;
  - destructive shell/infra commands with line numbers;
  - MCP/tooling config and broad/write/delete/admin tool exposure;
  - missing approval policy;
  - missing backup/rollback policy;
  - missing/dirty Git state.
- De-duplicates findings enough for readable reports.
- Produces stable IDs for findings so reports are diffable.

## Report contract

- Markdown report includes metadata, score, executive summary, risk distribution, findings table, top fixes, approval-policy starter, and postmortem template.
- JSON report includes machine-readable schema version, scan metadata, score, counts, and findings.
- Markdown escapes unsafe table characters.
- Reports include caveat that this is first-pass operational safety, not a full pentest/compliance audit.

## Test contract

- Unit tests cover config parsing, scanner rules, JSON output, Markdown escaping, CLI exit behavior, and no-secret-value leakage.
- Canonical suite passes with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q` in this host environment.
- CLI smoke checks run against the unsafe demo workspace.

## Product readiness contract

- README documents install/dev usage, config, JSON, CI gating, and limitations.
- Demo workspace and sample report remain intentionally fake/demo-only.
- No outbound email, publishing, or Git push happens without approval.
