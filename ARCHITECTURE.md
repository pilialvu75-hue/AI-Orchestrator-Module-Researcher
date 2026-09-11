# Researcher Architecture

## Boundaries

`ResearchEngine` orchestrates a cycle but knows neither GitHub HTTP details nor Library
filesystem layout beyond public interfaces.

Main ports:

- `NeedSource`: loads Library needs + cache fallback.
- `ContractSource`: resolves Library contract IDs and Lego standard version.
- `DiscoveryProvider`: finds candidates; GitHub is the first implementation.
- `StateStore`: durable idempotency/restart state.
- `DossierStore`: immutable-ish JSON research evidence keyed by candidate fingerprint.
- `LibrarySubmissionClient`: dry-run or intake-PR implementation.
- analyzers/scorer/comparison: deterministic decision support.
- `RateLimitManager`: tracks quota/backoff without spending money.
- dashboard: reads state only.

## Phase state machine

```text
SEEDING -> MAINTENANCE
   ^            |
   |            | new Library need
   +------------+

IMPROVEMENT is a separately configured policy mode.
```

`SEEDING` completes when every active Library need has at least its requested number of
shortlisted/submitted candidate fingerprints in local state. Maintenance does not perform
aggressive rescans.

## Candidate lifecycle

```text
DISCOVERED
 -> SCREENED
 -> COMPARED
 -> BENCHMARKED (metadata/evidence only in V1; no untrusted code execution)
 -> SHORTLISTED
 -> PREPARED FOR LIBRARY INTAKE
```

Certification remains exclusively a Library responsibility.

## Provenance

A candidate fingerprint is derived from source provider + upstream repository + immutable
commit SHA + capability. Re-evaluation occurs only when the pinned commit changes or an
explicit policy invalidates prior analysis.

## Contract gaps

If the Library has no valid contract for a need, the engine writes a structured contract-gap
record and blocks submission. It never invents a connector contract.

## Submission safety

Real submission requires both `DRY_RUN=false` and `ALLOW_LIBRARY_WRITE=true`. The client
creates a dedicated branch and PR containing only files below:

`intake/<asset-id>/<version>/...`

No code path writes `modules/` or `catalog/index.json`.
