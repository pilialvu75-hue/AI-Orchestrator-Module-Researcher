# First real controlled scan — `network.http`

This directory is a **Researcher proof**, not Library certification.

Library source of truth: `pilialvu75-hue/AI-Orchestrator-Module-Library`.
The researched slot is `network.http -> network.http.v1` for Android, desktop and web.

## Result

Both candidates passed the Researcher pre-screen and are shortlisted:

1. **dart-lang/http — package:http 1.6.0** — preferred thin LEGO-oriented default.
2. **cfug/dio — Dio 5.11.1** — richer alternative when advanced networking features justify the extra integration surface.

The machine scorer ranks Dio slightly higher because its repository metadata explicitly mentions
timeout and cancellation. The evidence-enriched comparison instead prefers `package:http` for the
minimal `network.http.v1` slot: its `Client` / `BaseClient` API is explicitly composable and
swappable, `RetryClient` is built in, and abortable requests cover cancellation. Timeout requires
a small trusted abort-trigger wrapper.

Dio remains highly valuable: timeout/cancel and interceptors are first-class, and its ecosystem is
strong. Retry is normally supplied through a custom interceptor or separately reviewed companion.

## Provenance decisions

- Dio is pinned to commit `4684e29dabaa2655606f1620a4ed316ee3f8c963`; tag
  `dio_v5.11.1` was independently resolved and verified to point to the same SHA.
- package:http 1.6.0 is pinned to signed release-preparation commit
  `907782f5a792e7a5b0ed92f118c0ad91f3ecde51`. No matching GitHub release tag was found, so
  `source_tag` is deliberately `null` instead of inventing one.
- License files are pinned to the exact source commit.
- Candidate code was **not executed**.
- No definitive vulnerability audit or performance benchmark has been performed.

## Dry-run intake

The `dry-run/` manifests intentionally use Library status `discovered` and
`ai-orchestrator-lego` 1.0.0. They are stored only in this Researcher repository. Nothing in this
proof writes to Library `intake/`, `modules/` or `catalog/index.json`.

Library quarantine, normalization, tests, security/license review and certification remain
separate future gates.
