# `ai.local_inference` comparison

Both primary candidates are credible native local-inference runtimes, but they represent different model ecosystems.
The Library should preserve that distinction instead of coupling `ai.local_inference.v1` to either GGUF or ONNX.

| Candidate | Model ecosystem | Android | Desktop | Raspberry Pi evidence | Main strength | Research result |
|---|---|---:|---:|---|---|---|
| `ggml-org/llama.cpp` v0.4.0 | GGUF / ggml | yes | yes | Linux ARM64 architecture path; Pi-specific validation pending | quantized native inference + broad backends | preferred shortlist |
| `microsoft/onnxruntime-genai` v0.15.2 | ONNX Runtime GenAI | yes | yes | published Linux ARM64 artifact; Pi-specific validation pending | ONNX ecosystem + execution providers | alternative shortlist |

## Preferred candidate

`llama.cpp` is preferred for the current AI Orchestrator direction because it maps naturally to locally downloaded
GGUF models, low-bit quantization, Android native integration and CPU/GPU hybrid execution. The evaluated release is
pinned to the signed commit `5266f24da75dc449bd56cbed7addb9c8e4a6a73e`.

This preference is not a claim that the Library should expose llama.cpp-specific API types. The adapter boundary must
remain provider-neutral.

## Independent alternative

ONNX Runtime GenAI is a real independent alternative rather than a wrapper around llama.cpp. Its support matrix
covers Linux, Windows, macOS, Android and ARM64, and the v0.15.2 release publishes a Linux ARM64 native archive.
That makes it particularly useful as a second architecture path when ONNX models or ONNX execution providers are
wanted.

## Raspberry Pi interpretation

Neither dossier claims a Raspberry-Pi-specific upstream certification. The evidence is architectural:

- native Linux ARM64 support for llama.cpp;
- an actual Linux ARM64 v0.15.2 release artifact for ONNX Runtime GenAI.

A Library certification for `raspberry_pi` must still run on the exact target class and record model, RAM, context,
backend, thermal and performance constraints.

## Security/admission

The candidates are research-shortlisted only. This manual proof did not execute candidate code or the Researcher
Full-Tree/SBOM/OSV admission path. Their engine lifecycle remains `SCREENED`; the dry-run manifests remain
`discovered` and cannot be presented as certified Library modules.
