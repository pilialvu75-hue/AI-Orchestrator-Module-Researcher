# Controlled proof: `storage.local_db`

This proof evaluates the Library need `storage.local_db` against the draft logical
contract `storage.local_db.v1` (version `1.0`) for **Android + desktop**.

The contract index currently defines only a logical local-persistence boundary. This
proof therefore does **not** invent CRUD method names, schema shapes, migration APIs,
transaction semantics or storage formats as contract requirements.

## Shortlist

1. **simolus3/drift 2.35.0** — preferred general-purpose candidate.
   - Exact signed release commit: `1e8bb788a8815d1e18e5c18d1705a2ca3cba6580`.
   - MIT, SQLite-based, Android/Linux/macOS/Windows, transactions, migrations,
     reactive/type-safe persistence, mature tests and CI.
2. **isar-community/isar-community 3.3.2** — independent NoSQL alternative.
   - Exact release commit: `4c2cd02d4e5c17b7edca89d141d1729ddc1698ff`.
   - Apache-2.0, Android/Linux/macOS/Windows, native object persistence, active
     community maintenance and broad test/release workflows.
   - The release commit is unsigned and native artifacts were not independently
     reproduced by the Researcher.

## Screened but not shortlisted

**objectbox/objectbox-dart 5.3.2** is technically strong, active and cross-platform.
Its Dart repository is Apache-2.0, but the upstream project explicitly states that the
native runtime uses the separate ObjectBox Binary License. The database core is free to
use and Sync is optional/commercial, but this mixed licensing is a weaker default for a
reusable open-source Module Library. It remains a future alternative and is deliberately
not mislabeled as an all-Apache stack.

## Safety and limits

- `DRY_RUN=true`; no Library intake write was performed.
- Candidate source code and native release binaries were **not executed**.
- Upstream CI/test presence was inspected; this proof does not assert every upstream run is green.
- No performance benchmark or definitive vulnerability audit was performed.
- Manifests remain `status=discovered`, `tests_passed=false`,
  `security.reviewed=false`.
- Library certification is still required.
