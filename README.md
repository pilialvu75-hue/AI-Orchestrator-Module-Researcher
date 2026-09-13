# AI Orchestrator Module Researcher

Autonomous, host-agnostic service that discovers, screens, compares and proposes
reusable open-source software assets to the **AI Orchestrator Module Library**.

System topology:

```text
OPEN SOURCE
    |
    v
RESEARCHER
    |
    v
MODULE LIBRARY
    ^
    |
CANTIERE
```

The Researcher never modifies Cantiere applications and never promotes assets directly
to the Library certified catalog.

## Current phase

V1 starts in `SEEDING` mode. The authoritative work queue is
`AI-Orchestrator-Module-Library/catalog/needs.json`; this repository does **not**
own a parallel backlog.

After seeding is complete, the engine enters `MAINTENANCE`, where it checks for new
Library needs at low frequency. `IMPROVEMENT` is implemented as a policy mode but is
not enabled by default.

## Safety defaults

- `DRY_RUN=true`
- `ALLOW_LIBRARY_WRITE=false`
- no execution of discovered source code
- no secrets in repository, persisted dossier, dashboard or public diagnostics
- no paid API/service requirement
- GitHub API is the first discovery adapter, not a core dependency
- durable SQLite state, structured event log and cache survive restarts
- real Library submissions can only target `intake/` and are proposed on a dedicated PR
- Diagnostics upload is opt-in and uses a credential separate from the Researcher/Library token

## Quick start

Python 3.12+:

```bash
python -m pip install -e .
export GITHUB_TOKEN=...
researcher once
researcher worker
researcher dashboard
```

Without a token, tests and local mocked runs work normally. Access to the private Module
Library requires a GitHub credential supplied at runtime.

Useful commands:

```bash
researcher once --dry-run
researcher status
researcher events --limit 100
researcher diagnostics-sync
python -m unittest discover -s tests -v
```

## Structured logs and shared Diagnostics

The authoritative operational log is local and durable in `data/researcher.db`. Important
Researcher lifecycle events are stored as structured rows with timestamp, severity, component,
event name and a redacted payload. This local history does not depend on Diagnostics being
available.

Each event also gets a second, smaller public projection built from an explicit allowlist.
Secret-like keys, Bearer tokens and URL query/fragment data are redacted before persistence,
and public projection omits free-form messages, local paths, source text and repository names.

The optional public sink is the shared repository
`pilialvu75-hue/Ai-orchestrator-diagnostics`. Its authoritative producer contract is
`docs/PRODUCERS.md` and `schemas/diagnostic-event-v2.schema.json` in that repository.
The Researcher implements the `researcher` namespace without modifying the existing Android
app format.

### Researcher producer namespace

For each stable Researcher instance:

- release tag: `diagnostics-researcher-v1-<instance-id>`
- release name: `Researcher diagnostics <instance-id>`
- archive asset: `researcher-diag-<sha256>.jsonl`
- latest asset: `researcher-latest.jsonl`
- event schema: `ai-orchestrator.diagnostics.event.v2`
- maximum archive chunk: 1 MiB
- archive retention budget: 20 MiB per Researcher instance/release

Every JSONL event records producer, producer version/commit, platform, stable instance,
run identifier, RFC3339 timestamp with timezone, event, severity, correlation id and only
allowlisted technical fields. Uploads are content-addressed and idempotent. The queue is
acknowledged only after archive upload, latest asset and bounded release-body summary are
verified. Failures remain pending with exponential backoff.

Rotation is intentionally incapable of global cleanup: it considers only
`researcher-diag-*.jsonl` inside the Researcher's own release. It never deletes Android
`latest.txt`, `diag-*.txt`, `diag-crash-*.txt`, Library assets, or releases belonging to other
producers.

Because the Diagnostics repository is public, publishing is **disabled by default**. Enabling
it requires a separate `DIAGNOSTICS_GITHUB_TOKEN`; the bridge never reuses `GITHUB_TOKEN`.
A production fine-grained token should be limited to the Diagnostics repository with Contents
read/write and kept in the producer's secret store, never in source, logs or chat.

### Shared Diagnostics API endpoints used

Repository: `pilialvu75-hue/Ai-orchestrator-diagnostics`

```text
GET    /repos/pilialvu75-hue/Ai-orchestrator-diagnostics/releases/tags/<tag>
POST   /repos/pilialvu75-hue/Ai-orchestrator-diagnostics/releases
GET    /repos/pilialvu75-hue/Ai-orchestrator-diagnostics/releases/<release-id>/assets?per_page=100&page=<n>
POST   https://uploads.github.com/repos/pilialvu75-hue/Ai-orchestrator-diagnostics/releases/<release-id>/assets?name=<asset-name>
DELETE /repos/pilialvu75-hue/Ai-orchestrator-diagnostics/releases/assets/<asset-id>
PATCH  /repos/pilialvu75-hue/Ai-orchestrator-diagnostics/releases/<release-id>
```

Diagnostics is a secondary observation channel, not the source of truth. A Diagnostics outage
must never fail or block a research cycle.

## Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `RESEARCHER_MODE` | `SEEDING` | `SEEDING`, `MAINTENANCE`, `IMPROVEMENT` |
| `DRY_RUN` | `true` | Prevents final Library submission |
| `ALLOW_LIBRARY_WRITE` | `false` | Second fail-closed switch for intake writes |
| `GITHUB_TOKEN` | empty | GitHub API credential for normal Researcher work |
| `LIBRARY_REPOSITORY` | `pilialvu75-hue/AI-Orchestrator-Module-Library` | Library source |
| `LIBRARY_REF` | `main` | Library ref to read |
| `DATA_DIR` | `./data` | SQLite/cache/dossier root |
| `MAINTENANCE_INTERVAL_SECONDS` | `21600` | Low-frequency idle interval |
| `SEEDING_INTERVAL_SECONDS` | `900` | Delay between seeding cycles |
| `IMPROVEMENT_INTERVAL_SECONDS` | `86400` | Improvement cadence when explicitly enabled |
| `DASHBOARD_HOST` | `127.0.0.1` | HTTP health/dashboard bind |
| `DASHBOARD_PORT` | `8080` | HTTP port |
| `DIAGNOSTICS_ENABLED` | `false` | Enables the secondary public Diagnostics producer |
| `DIAGNOSTICS_GITHUB_TOKEN` | empty | Dedicated Diagnostics-only credential |
| `DIAGNOSTICS_REPOSITORY` | `pilialvu75-hue/Ai-orchestrator-diagnostics` | Shared sink |
| `DIAGNOSTICS_INSTANCE_ID` | persisted UUID | Optional stable instance override |
| `DIAGNOSTICS_PRODUCER_VERSION` | Researcher version | Optional immutable version/commit override |
| `RESEARCHER_COMMIT` | empty | Used as producer version when the explicit override is absent |

`GITHUB_API_BASE` and `GITHUB_UPLOADS_BASE` exist only for controlled endpoint configuration
and tests. Production uploads are restricted to `https://uploads.github.com`; plain HTTP is
accepted only for loopback test mocks.

## Deployment

The runtime has no mandatory third-party Python dependencies.

```bash
docker build -t ai-orchestrator-module-researcher .
docker run --rm \
  -e GITHUB_TOKEN \
  -e DRY_RUN=true \
  -e DASHBOARD_HOST=0.0.0.0 \
  -p 127.0.0.1:8080:8080 \
  -v researcher-data:/data \
  ai-orchestrator-module-researcher worker
```

The container runs as an unprivileged user, persists `/data`, and the persistent worker also
serves the health/status dashboard. The example binds it only to the host loopback interface.

### Zero-cost policy

No paid service is activated or assumed. The repository intentionally does not enable a
recurring GitHub Actions scan by default because private-repository Actions minutes are a
finite quota. CI runs on repository changes; scheduled production execution should use a
zero-cost environment explicitly chosen by the owner. If API quota is exhausted, the
engine backs off and preserves state instead of switching to a paid provider.

## GitHub App permissions for production

Preferred minimal permissions for a dedicated GitHub App:

- **Researcher repository**: Contents read/write only if it must persist generated artifacts there.
- **Module Library**:
  - Contents: read/write (writes constrained in application code to `intake/`)
  - Pull requests: read/write
  - Metadata: read
- **Discovery repositories**: public metadata/read; no write permission.
- **Diagnostics**: use a separate minimal credential scoped only to the Diagnostics repository;
  do not reuse the Library credential.

The current V1 can also use `GITHUB_TOKEN` for development, but a broad PAT is not the
recommended production credential.

## Data layout

```text
data/
  researcher.db        # state + structured events + Diagnostics outbox
  cache/
  discoveries/
  comparisons/
  shortlist/
  submissions/
  contract_gaps/
```

The Library remains authoritative for needs, contracts, certification and certified modules.
