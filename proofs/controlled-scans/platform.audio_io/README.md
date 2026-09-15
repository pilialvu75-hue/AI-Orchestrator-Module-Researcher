# platform.audio_io controlled scan

This proof covers the staged high-priority need `platform.audio_io` from `catalog/needs.platform-extension.json`.

The Library contract `platform.audio_io.v1` is still draft. The only contract boundary treated as known here is audio capture/playback, device routing, and explicit format negotiation. This proof does **not** invent method names, lifecycle semantics, latency guarantees, route-change policy, buffer ownership, or error semantics.

## First research ring

Two independent Flutter families were pinned and inspected:

- `WAMF/audio_io` `0.6.1` at `47690f931422a2f58a0c4901133aba307e9649bf`
- `flutter-webrtc/flutter-webrtc` `1.6.2+hotfix.3` at `964066f26f3303dd7d518cb86b8d76c8ee82b031`

Both have evidence for Android, Windows, Linux, macOS, iOS and Web. Neither is counted for Raspberry Pi. Generic Linux support, Flutter embedded support, or an eLinux label is not treated as Raspberry Pi proof.

`audio_io` is currently the narrower architectural fit for a voice-first STT/TTS transport because it is explicitly centered on realtime microphone/speaker PCM streaming and sample-rate handling. `flutter-webrtc` is retained as a mature independent alternative with concrete device enumeration and input/output selection APIs. No winner is certified.

## Live source-security result

The temporary branch workflow ran `researcher preflight-pinned` against both immutable upstream snapshots. Candidate code was never executed.

`WAMF/audio_io`:

- static source: `CLEAR`
- 126 relevant files / 4,447,765 bytes scanned
- no static security findings
- no opaque artifacts or submodules
- two internal macOS symlinks resolved safely and their targets were scanned
- supply chain: `CLEAR`
- vulnerability gate: `REVIEW`, because `ffi ^2.1.0` and `web ^0.5.1` are ranges rather than resolved immutable runtime versions
- OSV was therefore **not** claimed as checked

`flutter-webrtc/flutter-webrtc`:

- static source: `CLEAR`
- 314 relevant files / 2,054,078 bytes scanned
- no static security findings
- no opaque artifacts or submodules
- internal iOS/macOS symlinks resolved safely and their targets were scanned
- supply chain: `CLEAR`
- vulnerability gate: `REVIEW`, because six Pub runtime dependencies remain range-based
- OSV was therefore **not** claimed as checked

The overall state of both candidates remains `REVIEW`. Static `CLEAR` is not certification.

## Security-scanner hardening produced by this ring

The audio candidates exposed two generic scanner limitations that were corrected without weakening fail-closed behavior:

1. Safe repository-internal symlinks can now be resolved transitively inside the admitted immutable tree, while missing, escaping or cyclic symlinks remain review findings.
2. Large text source files can be scanned in overlapping bounded chunks up to a hard cap. Files beyond the hard cap remain fail-closed. A regression test proves that a malicious shell-download signature crossing a chunk boundary is still detected.

The npm install-hook detector was also narrowed to quoted package-script keys so ordinary native identifiers such as `prepare = callback` are not misclassified as package install hooks.

## Target-depth state

Required research depth is two candidates per required target:

- Android: 2/2
- Windows: 2/2
- Linux: 2/2
- macOS: 2/2
- iOS: 2/2
- Web: 2/2
- Raspberry Pi: **0/2**

Research depth is therefore intentionally **not closed**.

The next target-specific family is `mackron/miniaudio`, whose upstream documentation explicitly lists Raspberry Pi support. That evidence is only a lead for the next ring; it does not retroactively prove that the Flutter `audio_io` package supports Raspberry Pi.

## Boundaries

- no Library intake was written
- no Library certification is asserted
- no candidate source code was executed
- no target runtime behavior was validated yet
- no OSV-clean claim is made while runtime dependency versions remain unresolved
- no Raspberry Pi support is inferred from Linux or embedded support
