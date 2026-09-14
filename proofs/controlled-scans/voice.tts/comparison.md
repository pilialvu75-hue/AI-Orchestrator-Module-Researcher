# voice.tts comparison

## Decision

Prefer **sherpa-onnx v1.13.8** for the first cross-platform offline TTS adapter. Keep **eSpeak NG 1.52.0** as an independent ultra-light fallback with explicit constraints. Keep **Kokoro ONNX** as a quality-focused reference for later research rather than overclaiming current target coverage.

| Dimension | sherpa-onnx v1.13.8 | eSpeak NG 1.52.0 |
| --- | --- | --- |
| Android | Explicit | Explicit |
| Desktop | Windows/macOS/Linux | Windows/Mac/Linux |
| Raspberry Pi | Explicit upstream support | Linux/native candidate; exact Pi validation pending |
| iOS extended evidence | Explicit | Not claimed |
| macOS extended evidence | Explicit | Explicit |
| Offline | Yes | Yes |
| Synthesis type | Neural/model-based | Formant synthesis |
| Flutter/Dart | Yes | Adapter required |
| Footprint | Model-dependent | Very small |
| Naturalness | Model-dependent, neural | Lower than neural TTS |
| License | Apache-2.0 | GPL-3.0-or-later |
| Release provenance | v1.13.8, pinned verified commit | 1.52.0, pinned verified commit |
| Research lifecycle | SCREENED | SCREENED |
| Certification eligible | No | No |

## Why sherpa-onnx is preferred

It has the strongest current fit to the Library's Android + desktop + Raspberry Pi requirement and already exposes Flutter/Dart plus native bindings. It also leaves room for multiple TTS model families while the future Library adapter can expose only the stable `voice.tts.v1` behavior.

## Why keep eSpeak NG

eSpeak NG is useful as an independent, deterministic, tiny fallback and as a baseline for low-resource hardware. It is not equivalent in voice naturalness and its GPL license requires a deliberate Library/distribution decision before promotion.

## Why Kokoro ONNX is not one of the two target candidates yet

Kokoro ONNX is promising for voice quality and current ONNX model packaging, but the evidence collected for this initial proof does not establish the same explicit Android + desktop + Raspberry Pi integration matrix. It stays on the research radar without being misrepresented.

## Admission boundary

Neither candidate has passed automatic Full-Tree/SBOM/OSV admission in this manual proof. No upstream code was executed, no Library intake was written, and no certification is claimed.
