# Controlled proof — `release.update_manager`

Library need: **Update/download manager**

- capability: `release.update_manager`
- logical contract: `release.update_manager.v1` / `1.0`
- priority: high
- requested targets: Android + desktop
- desired candidates: 2

## Contract detail gap

The current Library contract is only a logical boundary. Real upstream packages show that the title
"Update/download manager" combines at least three materially different responsibilities:

1. **discovery / policy** — detect a newer release, compare versions, force/skip policy, release notes;
2. **artifact transfer** — durable download, retry, pause/resume, progress, background/restart recovery;
3. **apply / install** — platform-specific store handoff or installer execution, restart and potentially rollback.

No candidate examined here safely satisfies all three responsibilities across both Android and desktop.
Researcher therefore does **not** invent missing contract semantics and does not present either primary
candidate as a complete `release.update_manager.v1` implementation.

Recommended Library follow-up is either:

- keep `release.update_manager.v1` as an orchestrator contract and define explicit sub-contracts for
  discovery/policy, transfer and apply/install; or
- split the capability into separately certifiable LEGO assets and compose them in Cantiere.

## Research components

### 1. `781flyingdutchman/background_downloader` 9.6.1

Preferred **transfer component**.

- immutable commit: `e3b88c4bdbc11fedca2a5c89bc3bba8d1bd539d1`
- tree: `6f795119953a5a7ef99a07d01169ae6f87c3fec6`
- source tag: not asserted; GitHub latest-release endpoint did not provide a release object during proof
- pubspec version: 9.6.1
- license: BSD-3-Clause (with bundled localstore MIT notice)
- requested target coverage: Android + Linux/macOS/Windows
- evidence: persistent database tracking, reconciliation after suspension/closure, pause/resume/cancel,
  offline holding/resume, retries and background transfers
- limitation: it is a file-transfer engine; no cross-platform app installation/update policy is claimed

Research recommendation: **SHORTLIST_AS_TRANSFER_COMPONENT**.

### 2. `mantreshkhurana/app_updater` 2.1.0

Preferred **discovery/policy/store-handoff component**.

- verified release tag target: `2.1.0` -> `e7c140749339fb1838bb83ca9c8e2a5c6a73bd1e`
- tree: `f5c9cc1fe63168c6c507c7d100f639449d036791`
- license: MIT
- requested target coverage: Android + macOS/Windows/Linux
- evidence: version checks, release notes, update frequency, force-update policy, GitHub Releases and store
  integration, platform-adaptive update dialogs
- limitation: documentation describes checking/policy/store handoff; it is not a durable artifact transfer
  engine and is not treated as an installer

Research recommendation: **SHORTLIST_AS_DISCOVERY_POLICY_COMPONENT**.

### Screened reference: `aguilaair/updat` 1.4.0

`updat` is a useful desktop self-update reference. Release tag `1.4.0` resolves to commit
`552d064303a39d28ec5ba82b6edad94d7209f5a0`. Its own README describes it as a Flutter-based desktop
update package that obtains the latest version/binary URL and opens the downloaded installer. Because the
Library need requires Android **and** desktop, it is kept as a screened reference rather than one of the two
primary cross-target components.

## Safety and lifecycle

This is controlled Researcher evidence only.

- no upstream candidate code was executed;
- Full-Tree / supply-chain / SBOM / OSV admission was not performed by the engine for these manual proof records;
- dossiers therefore remain `SCREENED` and `certification_eligible=false`;
- dry-run manifests remain `discovered`, `tests_passed=false`, `security.reviewed=false`;
- no Library or Cantiere write is part of this proof;
- Researcher does not resolve the contract detail gap on behalf of Library.
