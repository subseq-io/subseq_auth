# Agent Guidelines (subseq_auth)

This file stores durable, repo-specific guardrails for subseq_auth.

## Migration Safety
- Keep base migration files stable after release.
- Introduce schema evolution (for example scoped-role transitions) via incremental migrations only.
- Avoid modifying previously-applied migration bodies to prevent checksum/version mismatches.

## Role Delegation Contract
- Keep scoped role assignments managed through explicit auth role management APIs.
- Preserve delegation policy checks, admin override semantics, and self-grant protections in role mutation flows.
- Audit role mutations in auth log tables/paths.

## Error Envelope Contract
- Keep shared structured auth error primitives in the prelude as the canonical way downstream services emit authorization failure payloads.
- When changing structured error shapes, coordinate downstream service compatibility in the same round.
