# Controlled research proof — voice.tts

Library need: `voice.tts` — text-to-speech integration bundle.

Logical contract: `voice.tts.v1` version `1.0`.

Requested targets from the current Library need are Android, desktop and Raspberry Pi. macOS/iOS observations are also recorded when upstream evidence exists, but they do not change the current required-target score. Embedded/Arduino remains a future family and is not mixed into this proof.

## Primary candidates

### 1. k2-fsa/sherpa-onnx v1.13.8 — preferred

Sherpa-ONNX is the preferred research candidate because the same native runtime explicitly supports local TTS, Android, Windows, macOS, Linux and Raspberry Pi, and exposes Dart/Flutter plus native bindings. The exact release commit is pinned.

Strengths:
- offline TTS is an explicit first-class upstream function;
- Android, desktop and Raspberry Pi are explicitly supported upstream;
- Flutter/Dart support reduces adapter friction for AI Orchestrator;
- Linux aarch64 artifacts are published;
- permissive Apache-2.0 license;
- same runtime can later share voice infrastructure with STT without forcing the Library contract to depend on one engine.

Risks:
- broad speech feature surface must be narrowed behind `voice.tts.v1`;
- voice/model bundles vary in size, language coverage and quality;
- latency, first-audio delay, memory, pronunciation and realtime factor still require target-device benchmarks.

### 2. espeak-ng/espeak-ng 1.52.0 — independent lightweight baseline

eSpeak NG is retained as the independent lightweight baseline. Upstream explicitly supports Linux, Windows, Android and Mac, uses a compact C implementation and ships an Android artifact. Its formant synthesis is far smaller than neural TTS but less natural.

Strengths:
- compact native C runtime;
- explicit Android and desktop support;
- more than 100 languages/accents;
- very small footprint compared with neural voices;
- stable C/shared-library integration surface.

Risks:
- speech is intentionally less natural than modern neural TTS;
- GPL-3.0-or-later requires Library/distribution policy review before adoption;
- Raspberry Pi is treated as a Linux/native compatibility candidate, not as a device already validated by this proof;
- stable release 1.52.0 is older than the sherpa-onnx release and needs maintenance review during admission.

## Screened quality reference: Kokoro ONNX

`thewh1teagle/kokoro-onnx` remains an interesting high-quality neural reference and publishes current ONNX model assets, including int8/fp16 variants. It is not promoted to the two-candidate target shortlist in this proof because current evidence collected here does not establish the same explicit Android + desktop + Raspberry Pi integration coverage as the two selected candidates. It should be revisited later as a quality-focused voice backend.

## Platform note

The current Library need names Android, desktop and Raspberry Pi. macOS is included within desktop evidence where applicable; iOS is recorded as extended evidence for sherpa-onnx but is not silently added to the contract. A future Library update can expand the required platform matrix after the platform policy is formally revised.

## Safety boundary

This is a controlled manual research proof only:
- no upstream code was executed;
- Full-Tree Security Admission was not represented as completed;
- no SBOM/OSV result is claimed for these manual dossiers;
- lifecycle remains `SCREENED`;
- dry-run manifests remain `discovered`;
- `certification_eligible=false` until automatic admission and Library review;
- no Library or Cantiere write is included.

## Research decision

Prefer sherpa-onnx for the first cross-platform neural/offline TTS adapter. Keep eSpeak NG as a genuinely independent ultra-light fallback/baseline, subject to GPL distribution review and Raspberry Pi validation. Keep Kokoro ONNX as a future quality-focused candidate rather than overclaiming target coverage today.
