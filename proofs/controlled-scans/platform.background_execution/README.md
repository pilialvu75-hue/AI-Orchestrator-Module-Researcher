# Controlled scan — `platform.background_execution`

This directory records controlled research for the staged high-priority need `platform.background_execution`.

## Boundary

- Need source: `catalog/needs.platform-extension.json` in Module Library.
- Required targets: Android, Windows, Linux, macOS, iOS and Raspberry Pi.
- Desired discovery depth: two candidates per required target.
- Draft contract: `platform.background_execution.v1` / `1.0`.
- Known boundary: schedule bounded background work and manage long-lived worker/service lifecycle through platform-specific adapters.

The contract deliberately does **not** pretend background execution is equivalent across operating systems. Android/iOS schedulers are subject to OS quotas, battery policy and best-effort timing; desktop and Raspberry Pi can use native service managers with materially different lifecycle guarantees.

## Counted research families

### Mobile scheduling

`fluttercommunity/flutter_workmanager` 0.10.10 and `brewkits/native_workmanager` 1.8.1 are the two independent Android/iOS scheduler families. `auto_start_flutter` 1.4.0 is a third cross-platform background/startup bridge.

No persistent iOS daemon is asserted. Apple timing, quota, cancellation and continuation behavior remain target-specific contract work.

### Desktop service/background execution

`auto_start_flutter` and `OmnyGrid/dart_service_manager` provide independent Windows/Linux/macOS families. `dart_service_manager` exposes install/start/stop/restart/status over Windows SCM, launchd and systemd; `auto_start_flutter` uses platform-specific startup/background/scheduling mechanisms.

### Raspberry Pi

The counted Pi families are `OmnyGrid/dart_service_manager` and `kardianos/service`.

Both pinned upstream sources support Linux/systemd service management. Official Raspberry Pi documentation demonstrates real Raspberry Pi OS services managed through systemd/systemctl. This mechanism match is recorded only as **research target evidence**. It is not hardware/runtime certification, and Raspberry Pi remains subject to explicit lifecycle tests before Library intake.

## Security preflight

All preflights were immutable/pinned, `DRY_RUN=true`, `ALLOW_LIBRARY_WRITE=false`, and did not execute untrusted upstream code.

Key outcomes:

- `auto_start_flutter`: `CLEAR`; source and supply chain clear, OSV queried on 24 components, zero hits.
- `flutter_workmanager`: `REVIEW`; source/supply chain clear, but federated Pub dependency versions unresolved, so OSV was not queried.
- `native_workmanager`: `REVIEW`; committed DevTools/build binary artifacts and fonts require separate review; vulnerability analysis therefore did not run.
- `dart_service_manager`: `REVIEW`; source/supply chain clear, Pub versions unresolved.
- `kardianos/service`: `REVIEW`; source/supply chain clear and OSV queried, but `golang.org/x/sys v0.34.0` reports `GO-2026-5024`.
- `Supervisor`: `REVIEW`; retained as an uncounted Unix alternative.
- `RunWisp`: `BLOCKED`; scan file budget exceeded and shell-download-execute patterns were found in pinned test source.
- `service-manager-rs`: `BLOCKED`; pinned CI contains a `curl ... | sh` installer pattern.

A green GitHub Actions run means the preflight command completed and evidence was saved. It does **not** mean the candidate passed admission.

## Decision

Discovery depth is closed at at least 2/2 for every required target, but nothing is submitted to or certified by the Library.

Before intake: resolve Pub dependency versions, remediate or upgrade the kardianos vulnerability, define per-platform cancellation/retry/boot/power/foreground semantics, and run real lifecycle tests on every target including Raspberry Pi hardware.
