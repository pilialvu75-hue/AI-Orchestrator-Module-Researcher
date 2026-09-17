# Controlled proof — `ai.acceleration_backend`

Library staged need: **Target-specific local inference acceleration backend**

- capability: `ai.acceleration_backend`
- priority: high
- requested targets: Android, Windows, Linux, macOS, iOS, Web and Raspberry Pi
- desired candidates: 2 per target
- staged authority: `catalog/needs.platform-extension.json`
- discovery status: depth closed
- admission/certification status: open

## Boundary

This Ring is narrower than `ai.local_inference`.

`ai.local_inference` compares complete inference runtimes. This proof asks which
hardware/backend families can accelerate a compatible local model on the current
target, how availability is detected, and how a CPU-safe fallback is represented.

OS support alone is not proof that an accelerator is usable. A backend can be
compiled in but unavailable on the device, unavailable to the current model, or
slower/unsupported for a specific configuration. Runtime selection therefore
remains probe-driven and fail-closed.

## Candidate families

### `ggml-org/llama.cpp` v0.4.1

Pinned commit: `b29c606e28a01b1bc8c1351026a0fa6e616bf6c4`.

Research evidence covers native CPU plus Metal, CUDA, HIP, Vulkan, SYCL, OpenCL,
Hexagon and other ggml backends. The pinned Android documentation describes
automatic host-feature detection and Arm SME2/x86 AMX acceleration. Apple
XCFramework packaging is also documented.

The full-repository preflight is **BLOCKED**. A second scan restricted to
`ggml/src` is complete but remains **REVIEW** because regeneration tooling can
execute subprocesses and the scope has no supported dependency manifest.

No security admission is asserted.

### `microsoft/onnxruntime` v1.30.0

Pinned commit: `f2c39fe2f838cf35ce7da92824f5a5e3ee6e88a7`.

ONNX Runtime provides a second, materially different model/runtime ecosystem.
The pinned provider registry includes CPU, CUDA, TensorRT, OpenVINO, QNN, NNAPI,
CoreML, DirectML, WebNN, WebGPU and XNNPACK among other execution providers.
The v1.30.0 release also publishes Linux AArch64 artifacts.

The full-repository preflight is **REVIEW**. The component scan restricted to
`onnxruntime/core/providers` is also **REVIEW** and incomplete because the
scanner reached its 800-file budget. Supply-chain and vulnerability admission
therefore remain open.

### `ngxson/wllama` 3.5.1

Pinned commit: `766d28e03eeac044fe055327d06b83d3f9b84544`.

For Web, wllama supplies a browser integration independent from ONNX Runtime:
WebAssembly SIMD with optional WebGPU offload over the llama.cpp ecosystem.
Its preflight is **REVIEW** because the repository contains an unscanned
llama.cpp submodule, precompiled WASM and process-execution tooling.

Browser/device support and deployment requirements remain runtime concerns.

## Target matrix

Native and Raspberry Pi research use the pair:

- `ggml-org/llama.cpp`
- `microsoft/onnxruntime`

Web research uses:

- `microsoft/onnxruntime`
- `ngxson/wllama`

This closes the requested discovery depth of two candidates per staged target.
It does **not** close security admission, contract conformance, model
compatibility, target hardware validation, Raspberry Pi validation, Web browser
validation or runtime certification.

## Safety

- no upstream candidate code was executed;
- no Module Library read/write happened during the preflights;
- no candidate is submitted or promoted;
- the original full-repository verdicts are preserved alongside scoped scans;
- `BLOCKED` and `REVIEW` are never converted into `CLEAR`;
- no certification is asserted.
