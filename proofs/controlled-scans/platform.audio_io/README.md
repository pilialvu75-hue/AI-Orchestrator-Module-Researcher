# platform.audio_io controlled scan

This proof covers the staged high-priority need `platform.audio_io` from `catalog/needs.platform-extension.json`.

The Library contract `platform.audio_io.v1` is still draft. The only contract boundary treated as known here is audio capture/playback, device routing, and explicit format negotiation. This proof does **not** invent method names, lifecycle semantics, latency guarantees, route-change policy, buffer ownership, or error semantics.

## Flutter research ring

Two independent Flutter families were pinned and inspected:

- `WAMF/audio_io` `0.6.1` at `47690f931422a2f58a0c4901133aba307e9649bf`
- `flutter-webrtc/flutter-webrtc` `1.6.2+hotfix.3` at `964066f26f3303dd7d518cb86b8d76c8ee82b031`

Both have evidence for Android, Windows, Linux, macOS, iOS and Web. Neither is counted for Raspberry Pi. Generic Linux support, Flutter embedded support, or an eLinux label is not treated as Raspberry Pi proof.

`audio_io` is currently the narrower architectural fit for a voice-first STT/TTS transport because it is explicitly centered on realtime microphone/speaker PCM streaming and sample-rate handling. `flutter-webrtc` is retained as a mature independent alternative with concrete device enumeration and input/output selection APIs. No winner is certified.

### Flutter live source-security result

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

## Raspberry Pi target-depth ring

Two additional **native** and independent audio-I/O families were pinned specifically for Raspberry Pi research depth:

- `mackron/miniaudio` `0.11.25` at `9634bedb5b5a2ca38c1ee7108a9358a4e233f14d`
- `PortAudio/portaudio` `v19.7.0` at `147dd722548358763a8b649b3e4b41dfffbcfbb6`

These are not Flutter plugins and are not represented as drop-in modules. They are candidate native providers that would require a Raspberry-Pi platform adapter, most naturally through Dart FFI or another platform implementation behind `platform.audio_io.v1`.

### miniaudio Raspberry Pi evidence

The exact pinned miniaudio release README:

- describes the project as an audio **playback and capture** library;
- exposes low-level raw audio, conversion and resampling capabilities;
- explicitly lists **Raspberry Pi** in Supported Platforms;
- lists ALSA, PulseAudio and JACK among Linux-family backends;
- has device enumeration APIs for separate playback and capture device lists.

The exact pinned license file offers a choice between public domain and MIT No Attribution.

The live immutable security preflight remains `REVIEW`:

- 108 files / 9,347,685 bytes were scanned;
- no critical finding was produced;
- `.gitmodules` is a verified zero-byte file, but the current Researcher blob reader treats empty base64 content as unreadable, so that reader limitation remains fail-closed;
- `tests/android/MiniaudioTester/gradle/wrapper/gradle-wrapper.jar` is correctly treated as an opaque/precompiled artifact requiring separate review;
- no supported package dependency manifest was found, so native supply-chain analysis is `NOT_ANALYZED`;
- OSV is therefore not claimed as checked.

### PortAudio Raspberry Pi evidence

PortAudio is an independent C audio-I/O family. Its pinned release README describes callback and blocking input/output, format conversion, device enumeration, recording/playback tests and an input-to-output wire test. The project also maintains an official `Platforms_RaspberryPi` wiki page that explicitly states that PortAudio can be compiled directly on Raspberry Pi, uses ALSA there, and documents running device/output examples on the Pi.

The pinned license text is permissive and MIT-style, while GitHub metadata reports `NOASSERTION`; the proof preserves that distinction instead of inventing an SPDX identifier.

The live immutable security preflight remains `REVIEW`:

- 202 files / 5,294,108 bytes were scanned;
- no critical finding and no opaque artifact were produced;
- `test/patest_suggested_vs_streaminfo_latency.py` uses `os.system()` to invoke a local compiled latency test executable, so the process-execution gate correctly remains REVIEW;
- no supported package dependency manifest was found, so native supply-chain analysis is `NOT_ANALYZED`;
- OSV is therefore not claimed as checked.

## Discovery depth versus admission

Required research depth is two candidates per required target:

- Android: 2/2
- Windows: 2/2
- Linux: 2/2
- macOS: 2/2
- iOS: 2/2
- Web: 2/2
- Raspberry Pi: **2/2**

**Target discovery depth is now closed.** This means the Researcher has found at least two independent candidate families with explicit evidence for every required target.

It does **not** mean security admission, contract conformance or runtime certification is closed. In particular:

- the two Flutter candidates still have unresolved runtime versions at the OSV boundary;
- the two native Raspberry Pi candidates remain security REVIEW;
- the Researcher does not yet have complete native C/CMake supply-chain analysis;
- no Raspberry Pi adapter has been built or run;
- no microphone/speaker device-routing, full-duplex latency, hot-plug or sample-format behavior has been measured on actual Raspberry Pi hardware.

## Security-scanner hardening produced by the first ring

The original audio candidates exposed generic scanner limitations that were corrected without weakening fail-closed behavior:

1. Safe repository-internal symlinks can be resolved transitively inside the admitted immutable tree, while missing, escaping or cyclic symlinks remain review findings.
2. Large text source files can be scanned in overlapping bounded chunks up to a hard cap. Files beyond the hard cap remain fail-closed. A regression test proves that a malicious shell-download signature crossing a chunk boundary is still detected.
3. The npm install-hook detector was narrowed to quoted package-script keys so ordinary native identifiers such as `prepare = callback` are not misclassified as package install hooks.

The Raspberry Pi ring exposed a further precision gap: zero-byte Git blobs should be readable as empty text instead of being classified as unreadable. That issue is recorded for correction; the miniaudio result remains REVIEW until it is actually fixed and re-run.

## Boundaries and next action

- no Library intake was written
- no Library certification is asserted
- no candidate source code was executed
- no Raspberry Pi runtime behavior was validated
- discovery depth closure is not security-admission closure
- no OSV-clean claim is made where supply-chain evidence is incomplete
- no Raspberry Pi support is inferred from generic Linux/embedded support

Next, keep discovery depth closed and work on **admission quality**: fix the zero-byte blob reader false positive, add native C/CMake supply-chain evidence, review the test-only opaque/process findings without whitelisting them blindly, then design and hardware-test the Raspberry Pi adapter before any Library intake.
