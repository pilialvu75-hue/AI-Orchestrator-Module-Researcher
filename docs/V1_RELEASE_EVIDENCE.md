# Researcher V1.0.0 release evidence

This document records the evidence used to declare the deterministic Researcher V1
operationally ready. It is an audit note, not a certification of any upstream candidate.

## Baseline

- Release candidate base: Researcher `main` at `5c39ecf1062174eec50250f55404e280a2b9bab9`.
- The post-merge CI for that baseline completed successfully.
- Candidate code remains untrusted and is never executed by Researcher V1.
- Library certification remains a separate Library-owned operation.

## Exit criteria evidence

1. **Library inputs** — `GitHubLibrarySource` reads the current `catalog/needs.json`,
   `contracts/index.json` and LEGO standard from the Library, with cache fallback for
   temporary API failures.
2. **Independent candidates** — controlled proofs and engine tests exercise multiple
   independent candidates and comparison output.
3. **Immutable provenance** — candidate fingerprints include the immutable source commit;
   stable-Dart release resolution and intake validation reject unresolved or mutable source
   evidence.
4. **Security admission** — full-tree static analysis, supply-chain inspection, SBOM and OSV
   vulnerability admission run before shortlist eligibility. Candidate/package-manager code is
   not executed.
5. **Durable state** — SQLite persists candidates, scans, submissions, events and engine state
   across restart.
6. **Dry-run parity** — dry-run and live delivery are built from the same immutable submission
   package shape.
7. **Fail-closed live switch** — live delivery requires both `DRY_RUN=false` and
   `ALLOW_LIBRARY_WRITE=true`.
8. **Intake-only delivery** — live delivery is restricted to
   `intake/<asset-id>/<version>/` and opens a Library pull request.
9. **Idempotent/restart-safe delivery** — PR #16 persists the exact package before remote side
   effects and reconciles the deterministic branch, files and PR on retry.
10. **Crash-window recovery** — PR #16 tests a crash after remote PR creation but before local
    acknowledgement; PR #17 additionally recovers shortlisted dossiers orphaned before durable
    submission intent without rediscovery.
11. **Authority boundary** — Researcher never writes `modules/` or `catalog/index.json` and
    never certifies a candidate.
12. **CI coverage** — CI covers syntax, Ruff, Mypy, security/guardrails, unit/integration tests,
    restart/resume, remote-delivery idempotency, provenance, fail-closed policy and the Library
    exchange boundary.
13. **Operational visibility** — dashboard/status expose current capability, last cycle/error,
    coverage, submissions and Diagnostics state; structured events persist locally.
14. **Maintenance transition** — E2E coverage proves completed seeding falls back to
    `MAINTENANCE`, where the scheduler uses the lower-frequency maintenance interval.

## Real Library transport smoke

A real remote-boundary smoke was performed on 2026-09-14 using the authorized GitHub
connector and the exact deterministic branch/package convention implemented by the Researcher.
This was deliberately **not** a Library certification test and **not** a deployed-worker run.
The restart/outbox behavior itself is covered by Researcher CI; this smoke verifies that the
resulting remote shape is accepted by the real Library repository.

- Library repository: `pilialvu75-hue/AI-Orchestrator-Module-Library`.
- Library base at smoke start: `91971a9c32dacc468682d357427e9b5aea14b739`.
- Candidate: `simolus3/drift` 2.35.0 at immutable commit
  `1e8bb788a8815d1e18e5c18d1705a2ca3cba6580`.
- Researcher fingerprint:
  `2a70f312704f56cf5cf8237a07f13102b4b383fe348937e0c3847bb6e7ad8a09`.
- Deterministic branch:
  `researcher/intake/storage.local_db.simolus3.drift-2a70f312704f`.
- Library PR: `https://github.com/pilialvu75-hue/AI-Orchestrator-Module-Library/pull/10`.
- Exactly three files were added, all under
  `intake/storage.local_db.simolus3.drift/0.1.0/`: manifest, Researcher dossier and materialized
  upstream LICENSE.
- The manifest remained `status=discovered`, `validation.tests_passed=false` and
  `security.reviewed=false`.
- Library validation workflow run `34816950955` completed successfully, including catalog/
  contract validation, history/lifecycle validation, Library tests, deterministic snapshot export
  and snapshot validation.
- A second lookup using the deterministic head identity resolved the same single open PR #10;
  no duplicate PR was created.
- Researcher did not merge PR #10 and did not advance its Library lifecycle.

## Release conclusion

All V1 operational exit criteria are satisfied by code/tests plus the real Library transport
smoke above. Future work such as richer candidate research, actual sandbox execution and AI/LLM-
assisted research belongs to later versions and is not required for the deterministic V1 boundary.
