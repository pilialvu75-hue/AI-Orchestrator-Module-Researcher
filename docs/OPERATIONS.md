# Operations

## Modes

- `once`: one cycle then exit; appropriate for external cron/schedulers.
- `worker`: persistent daemon-style worker.
- `dashboard`: read-only JSON health/status service.

Phase policy is independent from process mode:

- `SEEDING`: prioritize uncovered Library needs.
- `MAINTENANCE`: low-frequency checks for new/changed needs.
- `IMPROVEMENT`: optional later phase for deeper re-evaluation.

## Recovery

All durable work is in SQLite and JSON artifacts under `DATA_DIR`. Restarts do not discard
candidate fingerprints, rejection reasons, submissions or scan history. The Library needs
and contracts have a cache fallback for temporary Library/API outages.

## Quota exhaustion

GitHub API rate data is recorded in state. When quota reaches zero the discovery provider
stops issuing new search work; the worker backs off and preserves state. There is no paid
fallback.

## Dashboard

`/` serves a small read-only HTML dashboard. `/health` and `/status` return the non-secret
JSON snapshot including mode, RUNNING/IDLE/BACKOFF, current capability, Library snapshot,
candidate counts, submissions, rate-limit state, last error and Researcher version.

## Real intake enablement

Keep `DRY_RUN=true` until the Library handshake is accepted.

When authorized:

```bash
export DRY_RUN=false
export ALLOW_LIBRARY_WRITE=true
```

The real client creates a dedicated Library branch and PR with paths restricted by code to
`intake/<asset>/<version>/`. It never writes certified modules or the catalog.
