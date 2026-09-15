# Controlled scan — `platform.permissions`

This directory records controlled research for the staged high-priority need `platform.permissions`.

## Boundary

- Need source: `catalog/needs.platform-extension.json` in Module Library.
- Need authority: staged, not authoritative catalog promotion.
- Required targets: Android, Windows, Linux, macOS, iOS and Web.
- Desired candidate depth: two research candidates per required target.
- Draft contract: `platform.permissions.v1` / `1.0`.
- Known logical boundary: runtime permission/capability query, request and denial-state semantics.

Target-aware discovery evidence is not target certification. The Library remains authoritative for runtime certification.

## First review ring

Workflow run `34949422173` evaluated immutable pinned source for:

- `Baseflow/flutter-permission-handler:permission_handler` 13.0.2;
- `arcas0803/device_permission` 1.0.0.

Both had source and supply-chain `CLEAR`, but vulnerability `REVIEW` because exact Pub dependency versions were unresolved and OSV was therefore not queried. Baseflow did not declare Linux/macOS at the top-level package boundary, leaving those targets at 1/2 research candidates.

## Depth ring

Workflow run `34950820746` evaluated immutable pinned source for:

- `jagadeeshchoudhary/permission_plus` 1.0.0;
- its pinned `permission_plus_linux` 1.0.0 backend;
- its pinned `permission_plus_apple` 1.0.0 backend for iOS/macOS;
- `manojprajapati1999/permission_manager` 2.0.9 as an additional candidate check.

No upstream code was executed. `DRY_RUN=true`, `ALLOW_LIBRARY_WRITE=false`, and no certification was asserted.

`permission_plus`, `permission_plus_linux`, and `permission_plus_apple` all returned source `CLEAR` and supply-chain `CLEAR`. They remain vulnerability `REVIEW`: hosted Pub dependency constraints are unresolved, so OSV has not actually been queried.

`permission_manager` is **not counted**. Its source gate is `REVIEW` because `example/android/gradle/wrapper/gradle-wrapper.jar` is an opaque/precompiled artifact. Independently, the pinned Linux plugin only implements `getPlatformVersion`, while its Dart side invokes permission channel methods such as `check`, `request`, batch operations and settings handoff.

## Candidate families

### Baseflow `permission_handler`

Strong established reference for Android, iOS, Web and Windows. It is not a complete six-target solution at the pinned top-level package boundary.

### `device_permission`

Declares all six required targets, but remains under runtime/provenance review. Its upstream license also acknowledges that portions of its API surface, behaviour and naming are inspired by `flutter-permission-handler`, so independence from Baseflow must not be overstated.

### `permission_plus`

Declares all six required targets and uses federated packages. The actual Linux and Apple backend repositories were pinned and separately preflighted rather than inferred from the parent manifest.

Linux is a genuine backend, but its current policy returns `GRANTED` for every permission type on standard Linux binaries and explicitly notes that Flatpak/Snap would require `xdg-desktop-portal`. This makes it useful as a distinct research strategy, not as certified sandbox-aware semantics.

The Apple backend uses shared Darwin source for iOS/macOS and contains native Swift handlers across multiple permission families, including AV capture, Bluetooth, contacts, EventKit, location and notifications.

## Per-target discovery coverage

The Researcher discovery-depth requirement is now satisfied:

- Android: 3 candidates
- Windows: 3 candidates
- iOS: 3 candidates
- Web: 3 candidates
- Linux: 2 candidates
- macOS: 2 candidates

This only closes the **research/discovery depth** required by the target-aware Researcher policy. It does not mark any target or module as certified.

## Remaining blockers

No candidate is ready for authoritative Library promotion yet. The remaining gates are:

- resolve Pub dependency constraints to immutable exact versions and actually run OSV;
- perform target-specific runtime validation;
- define Linux standard-binary versus Flatpak/Snap permission semantics;
- reconcile `device_permission` license provenance in the Researcher resolver;
- finalize contract policy for denial normalization, settings handoff and unsupported/silent-grant behavior.

## Decision

The Linux/macOS candidate-depth blocker is closed. `permission_plus` is retained as the third research family; `permission_manager` is rejected from candidate-depth counting. Certification remains fail-closed and no Library submission is asserted by this proof.
