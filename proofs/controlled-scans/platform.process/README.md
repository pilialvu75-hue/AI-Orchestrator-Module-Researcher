# Controlled scan — `platform.process`

This directory records controlled research for the staged high-priority need `platform.process`.

## Boundary

- Need source: `catalog/needs.platform-extension.json` in Module Library.
- Need authority: staged, not authoritative catalog promotion.
- Required targets: Windows, Linux, macOS and Raspberry Pi.
- Draft contract: `platform.process.v1` / `1.0`.
- Known logical boundary: local process execution with argv, cwd, environment, stdout/stderr streaming, cancellation and exit status.

The contract is still draft. This proof does **not** invent executable allowlists, shell policy, environment-inheritance rules, process-tree cancellation semantics, resource/output limits or privilege policy.

## Security interpretation

Both credible candidates visibly contain `Process.start`. That is expected functionality for this capability, but it is also a high-impact primitive. The automated Security Gate therefore correctly returns `REVIEW` rather than silently allowlisting it.

**Expected dangerous capability != security CLEAR.**

A visible, intentional process primitive is different from hidden malicious execution, but it still requires explicit review and sandboxed behavior validation before Library admission. The vulnerability stage remains blocked while the earlier security gate is not clear. This is deliberate fail-closed behavior, not a scanner defect.

No upstream candidate code was executed during these preflights.

## Candidates

### `dart-lang/tools:pkgs/process` 5.0.6

Preferred architecture primitive. Upstream describes it as a pluggable, mockable process invocation abstraction. Its `ProcessManager` exposes an argv-like command list, working directory, environment, optional shell invocation, connected stdout/stderr through `start`, completion/exit status through `run`, and process termination primitives.

Live immutable preflight at tag `process-v5.0.6`, commit `c7f7a63f656f268f8a88dde5bbceeb9367b90aaa`:

- source scan complete;
- security `REVIEW` only for the visible `Process.start` primitive;
- supply chain `CLEAR`;
- no opaque artifacts, submodules or symlinks;
- vulnerability stage `NOT_ANALYZED` because security review must happen first;
- no upstream code executed.

The narrow `ProcessManager` seam and hermetic mockability make this the cleaner default candidate for an adapter boundary.

### `tekartik/process_run.dart:packages/process_run` 1.3.6

Independent richer alternative. It provides portable shell helpers, executable discovery and environment utilities for Linux/Windows/macOS. The extra shell surface may be useful for tooling, but it is broader than the Library draft boundary and therefore deserves stricter policy review.

Live immutable preflight at commit `45a0244d202d06d39793fe986f06f514516cc41d`:

- source scan complete;
- security `REVIEW` for the visible `Process.start` primitive;
- supply chain `CLEAR`;
- no opaque artifacts, submodules or symlinks;
- vulnerability stage `NOT_ANALYZED` because security review must happen first;
- no release tag is asserted for version 1.3.6; the version is taken from the pinned package manifest;
- no upstream code executed.

Upstream also documents that macOS Flutter process execution can interact with app sandbox entitlements. This reinforces the need for an explicit platform security policy rather than treating shell execution as a generic utility.

## Platform caution

Neither candidate is represented as explicitly Raspberry-Pi-certified upstream. Linux/Dart compatibility is useful feasibility evidence, but Raspberry Pi remains a target validation obligation.

## Decision

Retain both independent candidates. Prefer `package:process` as the narrow, mature, mockable architecture primitive; retain `process_run` as a richer alternative/reference.

Neither candidate is submission-ready or certified. Before authoritative intake, Module Library must define the process security policy and the candidate behavior must be validated in an isolated zero-trust sandbox.
