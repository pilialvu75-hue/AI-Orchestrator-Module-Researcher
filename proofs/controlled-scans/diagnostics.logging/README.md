# Controlled research proof — `diagnostics.logging`

Library need: **Structured logging and diagnostics**  
Contract boundary: `diagnostics.logging.v1` / `1.0` (`draft`)  
Required targets: **Android, desktop, web**

This proof is research evidence only. It does not execute upstream code and it does not bypass
Researcher V1 security admission. A manual research recommendation of `SHORTLIST` therefore
remains `SCREENED` and `certification_eligible=false` until the engine runs Full-Tree,
supply-chain, SBOM and vulnerability admission.

## Research shortlist

### 1. `dart-lang/core` — `package:logging` 1.3.0 — preferred minimal primitive

- Package component path: `pkgs/logging`.
- Verified tag: `logging-v1.3.0`.
- Immutable commit: `8151b9f57fa3fee10421a19ce24470e143c0dee5`.
- Tree: `5873e0f9715c30bc7701b3376d04b61cbaf75e48`.
- BSD-3-Clause package/repository license.
- Pure Dart API with named loggers, levels, `LogRecord`, error/stack information and record
  streams; it does not force a persistence or remote diagnostics backend.
- The current `dart-archive/logging` repository is archived because the package moved into the
  active official `dart-lang/core` monorepo; it is not evidence that the package is abandoned.
- Dedicated `logging.yaml` CI workflow and package test directory are present at the evaluated
  commit.

This is the preferred LEGO base because the Library can place its own redaction, persistence and
Diagnostics transport adapter around a small neutral event source.

### 2. `Frezyx/talker` 5.1.20 — richer alternative

- Immutable commit: `654391c1a81c6a0fa4a05d46562cc0d15241d964`.
- Tree: `02461fc347953734556f66ef3c4c5e8749134c7e`.
- `packages/talker/pubspec.yaml` records version `5.1.20`.
- MIT license.
- Adds error handling, customizable log classes, optional history and integrations in the wider
  Talker package family.
- CI/test workflows are present and the repository is actively maintained.
- No `v5.1.20` Git tag exists at the time of this proof; provenance is therefore commit-pinned and
  `source_tag` is deliberately `null`. The proof does not invent a tag from the release commit
  message.

Talker is the useful independent alternative when a consumer wants more diagnostics behavior
before the AI Orchestrator adapter layer.

## Screened alternative

`SourceHorizon/logger` 2.8.0 is active, MIT, multiplaform and has a verified version tag. It is
kept as a valid screened alternative rather than rejected. The two selected candidates create a
more useful architectural comparison for this need: official/minimal event primitive versus a
richer diagnostics/error-handling stack.

## Safety and scope

- No upstream candidate code was executed.
- No full-tree security result is claimed by this manual proof.
- No vulnerability-clean claim is made.
- Both dry-run manifests remain `status=discovered`, `tests_passed=false` and
  `security.reviewed=false`.
- No Library write is performed by this proof.
- The shared `Ai-orchestrator-diagnostics` repository is a transport/sink and is not treated as a
  substitute for the local logging capability itself.
