# Agent Safety Policy

AI coding agents may read and edit this repository for development tasks, but must not execute or create irreversible operations without explicit human approval.

Approval required before:

- deleting files, databases, buckets, volumes, or backups
- force-pushing, hard-resetting, or cleaning Git state
- changing production infrastructure, billing, credentials, customer data, or live environments
- publishing, posting, purchasing, or sending external outreach
- running unknown scripts with network, filesystem, or destructive side effects

Default workflow:

1. Start from a clean Git state when practical.
2. Make the smallest scoped change.
3. Run tests or a focused smoke check.
4. Review diff before commit or publish.
5. Generate a postmortem after any failed autonomous run.

Rollback:

- Use Git diff/revert for code changes.
- Keep generated reports out of commits unless intentionally publishing a sanitized sample.
- Verify backups before any agent touches production-like data.
