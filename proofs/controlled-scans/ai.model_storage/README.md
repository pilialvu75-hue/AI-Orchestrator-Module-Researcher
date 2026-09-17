# Controlled proof — `ai.model_storage`

Library staged need: **Large-model storage, integrity and migration abstraction**

- capability: `ai.model_storage`
- priority: high
- requested targets: Android, Windows, Linux, macOS, iOS and Raspberry Pi
- desired candidates: 2 per target
- staged authority: `catalog/needs.platform-extension.json`
- discovery status: depth closed
- admission/certification status: open

## Boundary

Large-model storage is not just a download button. The eventual contract must keep
five states separate: remote model identity/revision, staged transfer, integrity
validation, atomically promoted local storage, and migration/rollback/cleanup.

A completed transfer is not runtime-ready until the expected digest and/or the
application's signature/format policy passes. Credentials are retrieval inputs,
not durable model metadata.

## Candidate families

### `NathanKolbas/huggingface_hub_dart` v0.0.3

Pinned commit: `9cc45ef5681858af0777b6ba8c8295d30f6dcfae`.

This is the most model-specific research family. Its cache separates revision
refs, commit snapshots and content blobs; LFS objects use SHA-256 identity. The
upstream README reports Windows, macOS, Linux, Android and iOS as tested and
labels the project work-in-progress and Flutter-dependent.

The live preflight is **REVIEW**, not CLEAR, because the package intentionally
reads `HF_TOKEN` / `HF_TOKEN_PATH`. Its supply-chain gate is CLEAR. AI-Orchestrator
must route any such credentials through its own secret policy and must never copy
tokens into model manifests, logs or persisted transfer metadata.

Raspberry Pi is only Linux architecture-level discovery evidence here; no Pi
runtime claim is made.

### `whuppi/cellar` v1.0.0

Pinned commit: `430784710654f9ea329067e1978e82e7b6f91fec`.

Cellar provides the local storage substrate missing from a downloader: pure-Dart
streaming for large objects, atomic native writes through temp-file + rename,
persistent/cache/scratch partitions, cross-partition copy/move, whole-partition
migration, lifecycle cleanup and materialization to a native file path for FFI.

The live preflight is **CLEAR**, including a complete SBOM and OSV query with no
hits. That security result does not certify AI-Orchestrator integration or
Raspberry Pi behavior.

Cellar intentionally does not bundle a remote downloader. Same-key writers must
also be serialized by the application.

### `landxcape/resumable_downloader` 0.1.2

Pinned commit: `aec93d1c32846a0b361e1eb74ff98ed0db478fe1`.

This family supplies the transfer/integrity gate: multipart HTTP ranges, durable
checkpoints, resume, a staged file, expected SHA-256, and an application-owned
validator. A failed checksum/validator discards staging instead of exposing an
unverified final file. Persisted restoration data deliberately excludes headers,
cookies, bearer tokens and signed URLs.

Its source and supply-chain scans are CLEAR, but the overall preflight is
**REVIEW** because the repository does not lock-resolve the primary Pub dependency
versions for OSV analysis.

It is foreground-oriented and does not promise continuation after the mobile OS
terminates the app. Background transfer policy therefore remains a separate
integration concern.

## Target matrix

Android, Windows, macOS and iOS have all three research families available.
Linux also has all three. Raspberry Pi discovery uses the two explicit Linux-level
families:

- `whuppi/cellar`
- `NathanKolbas/huggingface_hub_dart`

This closes discovery depth only. Raspberry-Pi-specific filesystem behavior,
free-space pressure, atomicity, model loading and performance remain untested.

## Composite decision

No single winner is selected. The strongest architecture is compositional:

1. provider/model identity adapter (Hub revision/content addressing);
2. resumable staging + integrity validation;
3. atomic local object storage + migration/cleanup;
4. only then expose a verified model path to the inference runtime.

The exact providers can change later; the contract should preserve these states.

## Safety

- no upstream candidate code was executed;
- no Module Library read/write happened during preflights;
- one candidate is CLEAR, two remain REVIEW;
- discovery depth does not imply security admission or submission;
- migration, background policy and hardware behavior remain open;
- no certification is asserted.
