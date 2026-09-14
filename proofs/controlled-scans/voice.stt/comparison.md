# `voice.stt` comparison

Both candidates have real upstream evidence for Android, desktop and Raspberry Pi. The difference is primarily the
runtime/model strategy rather than target availability.

| Candidate | Profile | Streaming | Android | Desktop | Raspberry Pi | Research result |
|---|---|---:|---:|---:|---:|---|
| `k2-fsa/sherpa-onnx` v1.13.8 | multi-model offline speech stack | yes | yes | yes | explicitly listed | preferred shortlist |
| `ggml-org/whisper.cpp` v1.9.4 | dedicated Whisper C/C++ runtime | model/runtime dependent | yes | yes | explicitly listed | alternative shortlist |

## Preferred candidate

`sherpa-onnx` is preferred for the general AI Orchestrator STT LEGO because it provides both streaming and
non-streaming ASR, multiple model families, Flutter/Dart bindings and explicit Raspberry Pi support. The evaluated
release is pinned to the verified commit `11afbd009a7f8c08f4bcf2fc1b265d0df4670fbf`.

Its broad speech stack is also a reason to keep the Library adapter narrow: `voice.stt.v1` should expose only STT
capabilities even though sherpa-onnx also implements TTS, VAD, diarization and other functions.

## Independent alternative

`whisper.cpp` is not a sherpa wrapper. It is a lightweight dedicated C/C++ Whisper implementation with quantization,
VAD, CPU-only operation and multiple acceleration backends. Upstream explicitly lists Android and Raspberry Pi, so it
is a strong second engine when Whisper compatibility is the priority.

## Certification still required

Upstream support does not replace Library validation. Exact model download, audio format, language behavior, partial
result semantics, latency, memory and cancellation must be exercised on the selected Android, desktop and Raspberry
Pi hosts before certification.

The manual proof did not run Full-Tree/SBOM/OSV admission, so both dossiers remain `SCREENED` and their dry-run
manifests remain `discovered`.
