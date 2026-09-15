# platform.lifecycle controlled research proof

This proof closes **research/discovery depth only** for the staged `platform.lifecycle` need. It does not certify a module, approve Library intake, or claim runtime behavior on any target.

## Boundary

The draft boundary intentionally keeps five event classes distinct: Flutter app lifecycle, native mobile foreground/background, desktop window-close/focus, browser unload, and headless process shutdown. Adapters may normalize them into one higher-level contract later, but discovery does not declare them semantically equivalent.

## Candidate strategy

- **Android / iOS:** `app_lifecycle_protector` provides the Flutter framework lifecycle path; `flutter_fgbg` independently uses Android `ProcessLifecycleOwner` and iOS application foreground/background notifications.
- **Windows / Linux / macOS:** framework lifecycle is complemented by native desktop window lifecycle/close candidates (`window_manager`, `flutter_window_close`).
- **Web:** framework lifecycle is complemented by `flutter_window_close`'s real `beforeunload` implementation.
- **Raspberry Pi / headless Linux:** `isoos/shutdown` uses POSIX/Dart process signals; `dart_graceful` uses a distinct detached child/parent watchdog.

## Security state

Live pinned dry-run preflights completed for four candidates. `flutter_fgbg` and `shutdown` are `CLEAR`; `app_lifecycle_protector` is `REVIEW` because an exact Pub dependency version could not be resolved for OSV; `dart_graceful` is `REVIEW` because static scanning correctly flags `Process.start`. No untrusted code was executed.

Pinned scans for `lifecycle`, `window_manager`, and `flutter_window_close` were retried on separate GitHub-hosted runners but were deferred by GitHub API rate limits. They remain **not security admitted**. As established by the earlier `platform.audio_io` proof, security deferral does not invalidate pinned discovery evidence; it does keep admission open.

## Important constraints

`dart_graceful 1.2.0` declares Dart `>=2.16.0 <3.0.0`, so it is useful as an independent research family but is not a current-runtime candidate for AI Orchestrator without modernization or replacement. Raspberry Pi compatibility is a research bridge from Linux/process semantics, not hardware validation.

## Decision

Per-target discovery depth is at least 2 for Android, iOS, Windows, Linux, macOS, Web, and Raspberry Pi. Discovery depth is therefore closed; security admission, contract conformance, and runtime validation remain open and fail-closed.
