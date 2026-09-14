# CONTRACT DETAIL GAP — `release.update_manager.v1`

The Library currently defines `release.update_manager.v1` only as a logical update/download management boundary.
The upstream evidence in this proof shows that a certifiable contract needs more detail before Researcher can claim
that one candidate fully implements it across Android and desktop.

## Missing semantic boundaries

At minimum the Library should decide whether the contract owns all of these phases or composes sub-contracts:

- **Discovery:** current/latest version, channel, metadata source, release notes.
- **Policy:** mandatory vs optional, skip/defer, minimum supported version, cadence.
- **Transfer:** destination, progress, pause/resume, retry, background/restart recovery, cancellation.
- **Integrity:** expected size/hash/signature and fail-closed behavior on mismatch.
- **Apply:** store handoff vs downloaded installer, platform permissions, restart, rollback/failure reporting.
- **Lifecycle:** state transitions that survive process death and allow idempotent resume.

## Proposed composition

Prefer keeping `release.update_manager.v1` as the Library-owned orchestration boundary while specifying explicit
sub-capabilities/contracts such as:

- `release.update.discovery.v1`
- `release.artifact_transfer.v1`
- `release.update.apply.v1`

A concrete product could then compose:

`discovery/policy -> durable transfer -> integrity gate -> platform apply/handoff`

For store-managed Android releases, apply may intentionally be a store handoff and artifact transfer may be skipped.
For direct desktop distribution, transfer and installer/apply phases are both needed.

## Researcher rule

Until Library resolves this detail gap, candidates in this proof remain `SCREENED` research components and
`certification_eligible=false`. The Researcher must not silently invent a universal installer API or claim that a
file downloader is a complete update manager.
