# Agent Safety Doctor

Production-grade local-first scanner and report generator for teams giving AI coding agents access to repos, terminals, credentials, MCP tools, and automation workflows.

## Why this exists

AI coding agents are moving from autocomplete to execution. They can read files, run commands, call tools, mutate repos, invoke MCP servers, and sometimes touch production credentials. Most teams do not have a simple way to answer:

- What can the agent touch?
- Are destructive commands or prod tokens reachable?
- Are MCP tools over-permissioned?
- Is there an approval policy?
- Could we produce a useful incident postmortem after a bad run?

`agent-safety-doctor` starts as a productized-service accelerator: it generates a first-pass safety report for an AI Coding Agent Safety Audit.

## Quick start

Install from PyPI:

```bash
python -m pip install agent-safety-doctor
agent-safety-doctor scan /path/to/repo --output agent-safety-report.md
```

Run directly from a source checkout:

```bash
python -m agent_safety_doctor.cli scan /path/to/repo --output agent-safety-report.md
```

For editable development:

```bash
python -m pip install -e .
agent-safety-doctor scan /path/to/repo --output agent-safety-report.md
```

JSON output:

```bash
agent-safety-doctor scan /path/to/repo --output agent-safety-report.json
```

HTML output for buyer-facing review:

```bash
agent-safety-doctor scan /path/to/repo --output agent-safety-report.html
```

CI/pilot gating:

```bash
agent-safety-doctor scan /path/to/repo --fail-under 85 --output agent-safety-report.md
```

If the safety score is below the threshold, the CLI exits non-zero.

## Current checks

- Secret-bearing file names near the workspace.
- Secret-looking assignments in text files, with values redacted.
- Risky/destructive command patterns in scripts/config/docs.
- MCP config and tool exposure indicators.
- Missing agent approval policy documentation.
- Missing backup/rollback documentation.
- Git missing or dirty state.

## Config

Create `.agent-safety-doctor.toml` in the scanned workspace:

```toml
[scanner]
ignore_dirs = [".git", "node_modules", ".venv", "dist", "build"]
ignore_globs = ["*.pyc", "*.png", "*safety-report.md"]
allow_secret_file_globs = ["*.example", ".env.example"]
max_file_bytes = 300000
scan_tests = false
```

Or pass an explicit config:

```bash
agent-safety-doctor scan /path/to/repo --config /path/to/.agent-safety-doctor.toml
```

## Output

Markdown report includes:

- scan metadata
- safety score
- risk distribution
- findings table with line/evidence where safe
- top recommended fixes
- incident postmortem template
- approval policy starter

JSON report includes:

- `schema_version`
- `metadata`
- `score`
- `counts`
- `findings`

HTML report includes:

- designed executive summary
- score card
- severity table
- top fixes
- postmortem starter

Secret values are redacted from reports.

## Demo

Generate a sample high-risk report from the included unsafe demo workspace:

```bash
python -m agent_safety_doctor.cli scan examples/unsafe-agent-workspace --output docs/sample-unsafe-workspace-report.md --display-root unsafe-agent-workspace
python -m agent_safety_doctor.cli scan examples/unsafe-agent-workspace --output docs/sample-unsafe-workspace-report.json --display-root unsafe-agent-workspace
python -m agent_safety_doctor.cli scan examples/unsafe-agent-workspace --output docs/sample-unsafe-workspace-report.html --display-root unsafe-agent-workspace
```

View the included buyer-facing example:

- [HTML sample report](docs/sample-unsafe-workspace-report.html)
- [Markdown sample report](docs/sample-unsafe-workspace-report.md)
- [JSON sample report](docs/sample-unsafe-workspace-report.json)

## Professional audit

The CLI is the first-pass evidence layer. Teams that need a scoped review of agent permissions, secrets exposure, destructive command paths, approval gates, and rollback readiness can review the [AI Coding Agent Safety Audit](docs/audit-offer.md).

## Limitations

This is a first-pass operational safety scanner, not a full penetration test, compliance audit, SAST engine, or guarantee of agent safety. It is designed to generate buyer-facing evidence quickly and identify obvious risky paths before deeper review.

## Development verification

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
python -m agent_safety_doctor.cli --version
python -m agent_safety_doctor.cli scan examples/unsafe-agent-workspace --output docs/sample-unsafe-workspace-report.md --summary
```

## Business wedge

Sell the audit first. Productize repeated checks second.
