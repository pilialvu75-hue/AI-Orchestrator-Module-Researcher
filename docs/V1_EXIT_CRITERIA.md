# Researcher V1 operational exit criteria

Version 1 is intentionally deterministic and does **not** require an LLM or other AI service.
AI-assisted research is deferred to V2.

V1 is ready to seed the Module Library when all of the following are true:

1. It reads `catalog/needs.json`, `contracts/index.json` and the LEGO standard from the Library.
2. It discovers and compares multiple independent candidates for active needs.
3. It pins immutable upstream provenance and rejects unstable/unresolved source refs.
4. It performs static security, dependency/SBOM and vulnerability admission without executing candidate code.
5. It persists candidates, scans, submissions and operational state across restart.
6. Dry-run remains the default and produces the exact payload that a live intake submission would use.
7. Live mode is fail-closed and requires both `DRY_RUN=false` and `ALLOW_LIBRARY_WRITE=true`.
8. Live delivery writes **only** to `intake/<asset-id>/<version>/` through a Library pull request.
9. Delivery is idempotent and restart-safe: a retry reuses the same branch, immutable payload and pull request instead of duplicating or overwriting a different payload.
10. A crash after remote delivery but before local acknowledgement is recoverable on the next cycle.
11. Researcher never writes `modules/` or `catalog/index.json` and never certifies a candidate.
12. CI covers restart/resume, idempotent remote delivery, dry-run/live fail-closed behavior, provenance, security admission and the Library exchange boundary.
13. The worker and dashboard expose enough state to see current capability, last cycle/error, coverage and submission status.
14. When seeding coverage is complete, the worker automatically falls back to low-frequency maintenance.

## Consumption boundary

`Ai-orchestrator-riserva` and the Cantiere should consume reusable assets from the **Module Library**, not from the Researcher process itself.

- `intake/` may be exposed read-only for inspection/debug UI, but is never an automatic reuse source.
- automatic reuse must read only certified Library assets (`modules/` + `catalog/index.json`);
- the Researcher can therefore be stopped, upgraded or replaced without becoming a runtime dependency of the app.
