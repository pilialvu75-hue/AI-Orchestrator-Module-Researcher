# Controlled scan — `platform.permissions`

This directory records controlled research for the staged high-priority need `platform.permissions`.

## Boundary

- Need source: `catalog/needs.platform-extension.json` in Module Library.
- Need authority: staged, not authoritative catalog promotion.
- Required targets: Android, Windows, Linux, macOS, iOS and Web.
- Desired candidate depth: two candidates per required target.
- Draft contract: `platform.permissions.v1` / `1.0`.
- Known logical boundary: runtime permission/capability query, request and denial-state semantics.

The contract is still draft. This proof does **not** invent target equivalence, silent-grant policy, settings-navigation policy, denial normalization, sandbox behavior or platform-specific fallback semantics.

## Live security preflight

Workflow run `34949422173` evaluated immutable pinned source for both candidates with `DRY_RUN=true`, `ALLOW_LIBRARY_WRITE=false` and `DIAGNOSTICS_ENABLED=false`. No upstream code was executed.

Both candidates returned:

- source security `CLEAR`;
- supply chain `CLEAR`;
- no opaque artifacts, submodules or symlinks;
- vulnerability `REVIEW` because the generated Pub SBOM contains unresolved dependency versions;
- OSV not queried while dependency versions remain unresolved;
- overall preflight state `REVIEW`;
- no Library read/write and no certification assertion.

A green workflow therefore means the preflight completed successfully; it does **not** mean the candidates are admission-ready.

## Candidates

### `Baseflow/flutter-permission-handler:permission_handler` 13.0.2

Pinned commit: `fc60b52afbd076d90f25ee950952cbd434e88595`.

The package exposes a strong, mature permission API with status checks, requests, denial states, service status and app-settings handoff. The pinned package manifest registers Android, iOS, Web and Windows implementations. It does **not** register Linux or macOS at the top-level package boundary, so this candidate alone does not satisfy the full staged target set.

The preflight resolves its license as MIT and source security as `CLEAR`. Vulnerability admission remains blocked because hosted Pub dependency constraints are ranges rather than resolved immutable versions.

Role: strong reference/default candidate for the platforms it explicitly declares, but not a complete six-target solution by itself.

### `arcas0803/device_permission` 1.0.0

Pinned tag `v1.0.0`, commit `a6d4bd4aabc7148fbbf5db50becd48e89c917557`.

Its pinned manifest declares Android, iOS, Linux, macOS, Windows and Web, matching the staged target vocabulary. The API surface closely follows the familiar permission-handler model. Upstream's LICENSE file is MIT and explicitly notes that portions of the API surface, behaviour and naming are inspired by `flutter-permission-handler`.

The live Researcher resolver returned `license: null`, so Library admission must not silently replace that unresolved provenance field even though the upstream license file is visibly MIT. This discrepancy is retained as review evidence.

The Linux implementation also demonstrates why declared support is not equivalent to runtime certification: many desktop permissions are mapped directly to granted/restricted semantics and `openAppSettings` invokes `gnome-control-center privacy`. Those semantics require target-specific validation before they can become authoritative adapter behavior.

Role: promising full-declared-target candidate, but younger and not yet runtime-certified; candidate independence from Baseflow is also not absolute because upstream explicitly acknowledges API/behaviour inspiration.

## Per-target coverage

Under the current Researcher policy, two candidates are required for each target. This proof currently has:

- Android: 2
- Windows: 2
- iOS: 2
- Web: 2
- Linux: 1
- macOS: 1

Therefore the candidate-depth requirement is **not satisfied**. Linux and macOS remain explicit research blockers.

## Decision

Retain both candidates for staged research, but certify neither.

- Baseflow is the stronger established reference and preferred partial implementation where its declared platform packages apply.
- `device_permission` is the only one of these two that declares every required staged target.
- Neither candidate is vulnerability-clear because dependency versions remain unresolved.
- The desired two-candidate independence goal is not fully satisfied because `device_permission` explicitly derives portions of its API/behaviour model from Baseflow.
- The two-candidates-per-target requirement is not satisfied for Linux or macOS.
- Target declaration is not runtime evidence; Linux/macOS/Windows/Web behavior still requires platform-specific tests.

Before authoritative Library intake: resolve the Pub SBOM to immutable dependency versions, run OSV, validate runtime permission semantics per target, reconcile `device_permission` license provenance, and find at least one additional credible Linux/macOS candidate (preferably genuinely independent) or explicitly document a safer adapter-composition strategy.
