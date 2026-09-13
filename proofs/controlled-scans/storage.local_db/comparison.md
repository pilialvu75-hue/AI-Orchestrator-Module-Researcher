# `storage.local_db` comparison

| Dimension | Drift 2.35.0 | Isar Community 3.3.2 | Assessment |
| --- | --- | --- | --- |
| License | MIT | Apache-2.0 + Apache-2.0 libmdbx NOTICE | Both strong open-source fits |
| Required targets | Android + Linux/macOS/Windows | Android + Linux/macOS/Windows | Both cover Android + desktop |
| Model | Relational SQLite | NoSQL object database | Different, genuinely independent implementations |
| Persistence lifecycle | Transactions + schema migrations explicitly documented | Native local object persistence | Drift has stronger directly evidenced generic lifecycle features |
| Maturity | Project since 2019; 3273 stars; active signed release | Community fork since 2024; 193 stars; active | Drift stronger maturity; Isar active but newer governance |
| Tests / CI | Unit/integration tests + GitHub Actions | Test/testlab/cron/release workflows | Strong static signals for both |
| Integration | Dart >=3.10, SQLite/native packaging, common codegen | Native binaries + generator | Both medium; Isar needs extra reproducibility scrutiny |

## Recommendation

Use **Drift 2.35.0** as the default candidate for Library evaluation. Keep
**Isar Community 3.3.2** as the open-source NoSQL alternative.

ObjectBox 5.3.2 was screened but not shortlisted because its open-source Dart
binding sits on a native runtime distributed under a separate binary license.

No detailed `storage.local_db.v1` API is assumed by this proof.
