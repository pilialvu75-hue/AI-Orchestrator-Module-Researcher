# Controlled scan — `platform.filesystem`

This directory records controlled research for the staged cross-platform need `platform.filesystem`.

## Boundary

- Need source: `catalog/needs.platform-extension.json` in Module Library.
- Need status: staged `needed`, not authoritative catalog promotion.
- Priority: high.
- Desired independent candidates: 2.
- Required targets: Android, Windows, Linux, macOS, iOS and Raspberry Pi.
- Draft contract: `platform.filesystem.v1` / `1.0`.
- Known logical boundary only: sandbox-aware filesystem abstraction with scoped read/write, atomic replace and path-capability semantics.

The contract is still draft. This proof does **not** invent method signatures, exact path-capability rules, certification criteria, or a final adapter API.

## Candidates

### `dart-lang/tools:pkgs/file` 7.0.1

Preferred architecture primitive. `package:file` is a generic first-class filesystem abstraction for Dart, supports custom and in-memory filesystems and keeps local `dart:io` access behind `LocalFileSystem`. Its `ChrootFileSystem` can present a filesystem rooted in a designated directory tree, which is useful for scoped-path adaptation.

Important limit: upstream explicitly states that `ChrootFileSystem` is a convenient abstraction, **not an operating-system security boundary**. The reviewed upstream evidence also does not establish the Library draft contract's atomic-replace requirement. That remains adapter/contract work.

Live immutable preflight at tag `file-v7.0.1`, commit `3f7a46606496f826c2f60586ab71c2b7a9bfbf15`:

- full selected component source scan: `CLEAR`;
- supply chain: `CLEAR`;
- no opaque artifacts, submodules, symlinks or static findings;
- vulnerability admission: `REVIEW` because runtime ranges `meta:^1.9.1` and `path:^1.8.3` have no immutable release lock resolution;
- no upstream code executed.

### `whuppi/cellar_flutter` 1.0.0

Independent emerging alternative. It resolves app-private storage roots through `path_provider`, uses platform-neutral validated keys, supports namespace/tenant scoping, and documents atomic writes. It explicitly supports iOS, Android, macOS, Windows, Linux and web.

It is not a drop-in general `FileSystem` abstraction; it is an object-storage facade. It is also a very young project with low adoption, so its maturity risk is materially higher than `package:file` despite the stronger match to some draft contract semantics.

Live immutable preflight at tag `v1.0.0`, commit `ecf8d628c3942d73aee8c14e47b6560515e68827`:

- full source scan: `CLEAR`;
- primary package supply chain: `CLEAR`;
- OSV admission: `CLEAR`, 48 locked components queried, no hits;
- auxiliary example manifests were scanned as source but excluded from the primary package dependency scope;
- no upstream code executed.

The admission SBOM is deliberately conservative: when a Pub lockfile cannot prove that a transitive package is dev-only, Researcher keeps it in vulnerability scanning rather than pruning it by assumption.

## Platform caution

Neither candidate is represented here as explicitly Raspberry-Pi-certified upstream. Linux compatibility is useful evidence for the Pi target, but exact Raspberry Pi validation remains a Library/Cantiere test obligation.

## Decision

Retain both independent candidates. Prefer `package:file` as the mature architecture primitive, while retaining `cellar_flutter` as a strong emerging alternative for atomic/scoped app storage semantics.

No candidate is certified or submitted to Library from this staged proof. Before authoritative intake, resolve the draft contract detail gap and obtain deterministic vulnerability evidence for `package:file` (or explicitly accept a Library review path that accounts for its unresolved package ranges).
