# Controlled proof — `voice.stt`

Library need: **Speech-to-text integration bundle**

- capability: `voice.stt`
- logical contract: `voice.stt.v1` / `1.0`
- priority: high
- requested targets: Android + desktop + Raspberry Pi
- desired candidates: 2

The Library contract remains a logical STT boundary. This proof compares offline/on-device ASR engines without
inventing final method names, stream event schemas or model-selection semantics for the Library.

## 1. `k2-fsa/sherpa-onnx` v1.13.8 — preferred candidate

- exact tag: `v1.13.8`
- exact release commit: `11afbd009a7f8c08f4bcf2fc1b265d0df4670fbf`
- tree: `6de2d2d8a1cd6d9b64554f42a8012739d93de881`
- release commit signature: verified
- license: Apache-2.0
- upstream explicitly supports local speech-to-text, both streaming and non-streaming
- supported platforms include Android, Windows, macOS, Linux, ARM64/AArch64 and Raspberry Pi
- Flutter support includes Android/Windows/macOS/Linux on ARM64
- release assets include an Android AAR and Linux aarch64 native artifacts
- broad language/binding surface includes C/C++, Java/Kotlin, Dart and others
- supports multiple ASR model families rather than a single model architecture

Research recommendation: **SHORTLIST** and preferred general offline STT integration candidate.

## 2. `ggml-org/whisper.cpp` v1.9.4 — independent Whisper candidate

- exact tag: `v1.9.4`
- exact release commit: `927cfce34f31707e17f2bff35c349632fb9e2c3a`
- tree: `db312954f67ca741569ac3a889a9ff329e51d952`
- release commit signature: verified
- license: MIT
- dedicated high-performance C/C++ implementation of Whisper ASR
- upstream explicitly lists Android, Linux, Windows, macOS and Raspberry Pi
- CPU-only inference, quantization, VAD and several acceleration backends are available
- lightweight C API and ggml model format make native embedding straightforward

Research recommendation: **SHORTLIST** as the dedicated Whisper/ggml alternative.

## Trade-off

`sherpa-onnx` is preferred when AI Orchestrator wants one offline speech stack with streaming ASR, multiple model
families, Flutter/Dart support and an explicit Raspberry Pi path. `whisper.cpp` is attractive when the desired model
family is specifically Whisper and a compact native C/C++ implementation is preferable.

The Library should keep `voice.stt.v1` engine-neutral. A future detailed contract can normalize lifecycle, audio
feeding, partial/final results, language/model metadata, cancellation and health reporting without exposing engine
classes directly.

## Safety and lifecycle

- no candidate code was executed;
- this manual proof did not run Full-Tree/SBOM/OSV admission through the Researcher engine;
- dossiers remain `SCREENED` and `certification_eligible=false`;
- dry-run manifests remain `discovered`, `tests_passed=false`, `security.reviewed=false`;
- upstream platform support is evidence, not a Library certification on our exact devices;
- no Library or Cantiere write is included.
