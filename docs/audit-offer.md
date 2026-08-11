# AI Coding Agent Safety Audit

## Positioning

AI coding agents are now allowed to read files, run shell commands, call MCP tools, touch SaaS APIs, and mutate production-adjacent systems. Most teams adopted the agents faster than they built the safety layer.

This audit answers one question:

> If your Cursor, Claude Code, Codex, or MCP-powered agent goes wrong, what can it damage — and would you know exactly what happened?

## Ideal customer

- AI-native SaaS/startup using Cursor, Claude Code, Codex, Copilot, Claude Desktop, or MCP servers.
- Team has agents touching repos, terminals, credentials, customer workflows, or internal tools.
- Founder/CTO/security lead wants agent productivity without uncontrolled runtime risk.

## Trigger events

- Team is rolling out Claude Code/Cursor/Codex across engineers.
- Team is adding MCP servers to internal systems.
- Agent recently made a bad edit, ran a risky command, leaked context, looped, or hallucinated success.
- Customer/security review asks how AI agents are governed.
- Company wants SOC2-style evidence for AI-agent tool access.

## Deliverables

1. Agent/tooling inventory.
2. MCP/tool permission map.
3. Secrets exposure review.
4. Destructive command and production credential risk review.
5. Approval-gate recommendations.
6. Backup/rollback readiness review.
7. Local `agent-safety-doctor` report.
8. Incident postmortem template.
9. 7-day remediation checklist.
10. Optional implementation support.

## Pricing

- Beta audit: $499 for first 3 customers.
- Standard audit: $1,500.
- Team implementation package: $3,000-$5,000.

## Landing page headline

Your AI coding agents have tool access. Do you know what they can destroy?

## Subheadline

A fast safety audit for teams using Cursor, Claude Code, Codex, or MCP servers — map risky permissions, secrets exposure, destructive commands, missing approval gates, and incident-response gaps before an agent-caused failure becomes expensive.

## CTA

Book an AI Coding Agent Safety Audit.

## Outreach draft

Subject: Quick safety check for your AI coding agents

Hey {{name}},

Saw that {{company}} is building with AI/devtools. Quick question: have you mapped what your Cursor/Claude/Codex/MCP agents can actually touch — shell commands, repo files, secrets, SaaS APIs, or production-adjacent systems?

I’m building a local-first safety audit for AI coding-agent setups. It produces a concrete report: risky tool permissions, secrets exposure, destructive command paths, missing approval gates, rollback gaps, and an incident-postmortem template.

The point is not generic AI governance. It’s practical: if an agent goes wrong, what could it damage, and would you have a traceable postmortem?

I’m offering the first 3 beta audits for $499. Worth a quick look at your setup?

— Dhiraj

## Kill criteria

Pause or pivot if 30 precise founder/security/devtool conversations produce:

- no urgency around agent permissions or MCP security,
- no willingness to pay even at $499,
- repeated feedback that existing controls already solve the problem,
- no interest in local-first audit/report artifacts.

## Product path

1. `agent-safety-doctor` local CLI report.
2. MCP schema/tool diffing.
3. Runtime policy checks for shell/file/network/MCP actions.
4. Signed local audit log.
5. Replay/postmortem generator.
6. Team/enterprise package later, only after paid audits validate demand.
