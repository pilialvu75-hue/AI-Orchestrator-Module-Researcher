# Operations

## Modes

- `once`: one cycle then exit; appropriate for external cron/schedulers.
- `worker`: persistent daemon-style worker.
- `dashboard`: read-only JSON health/status service.
- `admit-pinned`: re-resolve one exact pre-researched GitHub commit, run the production
  admission gates, and deliver it only if it reaches `SHORTLISTED`.

Phase policy is independent from process mode:

- `SEEDING`: prioritize uncovered Library needs.
- `MAINTENANCE`: low-frequency checks for new/changed needs.
- `IMPROVEMENT`: optional later phase for deeper re-evaluation.

## Recovery

All durable work is in SQLite and JSON artifacts under `DATA_DIR`. Restarts do not discard
candidate fingerprints, rejection reasons, submissions or scan history. The Library needs
and contracts have a cache fallback for temporary Library/API outages.

Live intake uses deterministic submission ids and branches. Before a write, the immutable
submission intent is stored locally; retries reconcile the existing remote branch and pull
request instead of creating duplicates. A fresh one-shot runner can also safely retry the
same pinned candidate because remote branch/file/PR reconciliation is deterministic and
fails closed on payload divergence. Long-running workers should still use persistent
`DATA_DIR` storage so complete operational history survives restarts.

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

Real Library delivery requires three independent conditions and a dedicated credential:

```bash
export DRY_RUN=false
export ALLOW_LIBRARY_WRITE=true
export LIBRARY_GITHUB_TOKEN='<stored outside the repository>'
```

`LIBRARY_GITHUB_TOKEN` must be dedicated to the Module Library. For a fine-grained GitHub
token, select only `pilialvu75-hue/AI-Orchestrator-Module-Library` and grant the minimum
repository permissions needed by the intake client: **Contents: Read and write** and
**Pull requests: Read and write**. Do not reuse the Diagnostics token and do not store the
token in dossiers, configuration files, workflow inputs or logs.

`GITHUB_TOKEN` remains the source/research credential. Library reads prefer the dedicated
Library token when configured; live Library writes refuse to start without it.

The real client creates a dedicated Library branch and PR with paths restricted by code to
`intake/<asset>/<version>/`. It never writes certified modules or the catalog.

## Manual pinned intake workflow

`.github/workflows/intake-pinned.yml` is deliberately `workflow_dispatch` only. Pushes and
pull requests can never publish a candidate. Before using it, configure the Researcher
repository secret `RESEARCHER_LIBRARY_TOKEN` with the least-privilege Library credential
described above.

The workflow requires an explicit `confirm_write=true` input and accepts capability,
upstream `owner/name`, exact 40-character commit SHA, and optional release tag/version.
Workflow inputs are passed through environment variables and a Bash argument array rather
than interpolated into a shell command.

The workflow performs the same Full-Tree, supply-chain and SBOM/OSV admission used by the
normal engine. A result other than `SHORTLISTED` produces no Library submission. Candidate
source code is not executed by this workflow.


## Module evolution security boundary

The authoritative exchange path is:

`Researcher -> Module Library -> Cantiere -> Module Library`.

The Researcher must not dispatch evolution work directly to
`pilialvu75-hue/Ai-orchestrator-riserva`, and it must never require a
`RESEARCHER_CANTIERE_TOKEN`.

Researcher discoveries and shortlisted candidates enter the Module Library
through the existing intake-only path. The Library owns quarantine,
normalization, license/security review, deterministic certification and the
decision about what material is eligible for Cantiere consumption. The
Researcher never executes untrusted candidate code as part of this handoff.

`Module Evolution Worker` is therefore a **manual-only** queue/recovery and
evidence workflow. It is not scheduled and is not part of the autonomous
execution path. It may recover historical `QUEUED` claims created by the
retired direct-Cantiere path and expose pending proposals, but it must not
claim work for direct execution, send `repository_dispatch` to Cantiere, or
transfer source code.

Autonomous discovery and delivery remains owned by `Autonomous Library Seeding`,
which may submit only intake-scoped candidates to the Module Library after the
Researcher admission gates pass. The Library then owns quarantine,
normalization/certification and the certified package surface consumed by
Cantiere.

The historical repository secret `RESEARCHER_CANTIERE_TOKEN` is no longer
used by the workflow and may be removed after the migration is verified.
