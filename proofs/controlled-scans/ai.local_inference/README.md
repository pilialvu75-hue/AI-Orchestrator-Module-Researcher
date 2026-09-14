# Controlled proof — `ai.local_inference`

Library need: **Local LLM runtime integration bundle**

- capability: `ai.local_inference`
- logical contract: `ai.local_inference.v1` / `1.0`
- priority: high
- requested targets: Android + desktop + Raspberry Pi
- desired candidates: 2

The Library contract is currently a logical runtime boundary only. This proof therefore compares runtime
capabilities and integration evidence without inventing a mandatory chat/session/token API for the Library.

## 1. `ggml-org/llama.cpp` v0.4.0 — preferred general-purpose candidate

- exact tag: `v0.4.0`
- exact release commit: `5266f24da75dc449bd56cbed7addb9c8e4a6a73e`
- tree: `0424752fbbc3bb01469ec830a30f2bc035497cd4`
- release commit signature: verified
- license: MIT
- native C/C++ runtime focused on local LLM/VLM inference
- GGUF ecosystem with low-bit quantization and CPU/GPU hybrid inference
- Android documentation includes a Kotlin binding, GGUF model loading, token streaming through Kotlin Flow,
  Termux execution and explicit NDK cross-compilation for `arm64-v8a`
- desktop backends include CPU, CUDA, HIP, Metal, Vulkan, SYCL and others
- release/source tree includes broad CI/test/build infrastructure

For Raspberry Pi, the proof does **not** claim a Raspberry-Pi-specific certification. `llama.cpp` has ARM64/Linux
build support and is therefore a strong architecture-level candidate for 64-bit Raspberry Pi Linux, but exact Pi
model/OS/thermal/performance validation remains a Library/Cantiere host test.

Research recommendation: **SHORTLIST** and preferred default runtime candidate.

## 2. `microsoft/onnxruntime-genai` v0.15.2 — independent ONNX alternative

- exact tag: `v0.15.2`
- exact release commit: `ed5f4e87147731e5b07810f9f5c90103b3603cdf`
- tree: `4c5472aadb10ad78c5bec541cab3ed25459213c8`
- release commit signature: unsigned
- license: MIT
- generative loop over ONNX Runtime including tokenization/generation support, search/sampling and KV-cache
  management
- upstream support matrix explicitly includes Linux, Windows, macOS, Android and ARM64
- Android build documentation includes Java bindings, Android NDK setup and `arm64-v8a`
- v0.15.2 release publishes a `linux-arm64` archive, providing concrete ARM64 Linux packaging evidence
- model ecosystem is ONNX rather than GGUF and integration/deployment is materially different from llama.cpp

For Raspberry Pi, the `linux-arm64` release is strong architecture evidence but is **not** represented as an
upstream Raspberry-Pi-specific validation. Exact board/OS/model compatibility still requires host testing.

Research recommendation: **SHORTLIST** as an independent runtime alternative, especially where ONNX models and
ONNX Runtime execution providers are desirable.

## Comparison boundary

The two candidates are deliberately independent:

- llama.cpp optimizes the GGUF/ggml local-inference path and offers very broad native backend flexibility;
- ONNX Runtime GenAI uses the ONNX Runtime ecosystem and its execution providers.

The Library should keep `ai.local_inference.v1` provider-neutral and let adapters normalize model loading,
generation/streaming, cancellation, runtime health and capability reporting after the detailed contract is defined.
No method names are invented by this proof.

## Safety and lifecycle

- no upstream candidate code was executed;
- this manual controlled proof did not run the engine Full-Tree gate, complete SBOM, or OSV admission;
- dossiers therefore remain `SCREENED` and `certification_eligible=false`;
- dry-run manifests remain `discovered`, `tests_passed=false`, `security.reviewed=false`;
- no claim is made that either candidate is certified on Raspberry Pi hardware;
- no Library or Cantiere write is included.
