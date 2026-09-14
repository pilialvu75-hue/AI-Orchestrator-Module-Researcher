# Comparison — `diagnostics.logging`

The Library contract is a logical capability boundary only. These scores are research decision
support, not certification and not a substitute for the Researcher V1 security gates.

| Candidate | Profile | Research score | Security admission | Research decision |
| --- | --- | ---: | --- | --- |
| `dart-lang/core` → `pkgs/logging` 1.3.0 | minimal official Dart event primitive | 0.93 | not executed in manual proof | preferred shortlist |
| `Frezyx/talker` → `packages/talker` 5.1.20 | richer history/error-handling diagnostics | 0.87 | not executed in manual proof | alternate shortlist |
| `SourceHorizon/logger` 2.8.0 | extensible logger/output stack | screened only | not executed | valid fallback |

## Preferred — `package:logging`

`package:logging` exposes named loggers, severity levels and `LogRecord` streams while leaving
storage, redaction and remote transport to the consumer. That separation fits AI Orchestrator well:
the Library can adapt records into its own diagnostic-event representation and keep the existing
shared Diagnostics publisher independent from the chosen logger.

The historic `dart-archive/logging` repository being archived is not a maintenance failure: the
package moved into the active official `dart-lang/core` monorepo. The evaluated stable tag
`logging-v1.3.0` resolves to the immutable, verified commit
`8151b9f57fa3fee10421a19ce24470e143c0dee5`.

## Alternative — Talker

Talker provides more behavior out of the box: custom logs, exception/error handling, configurable
history and a broader integrations family. This is useful when richer local diagnostics are wanted,
but it also creates more policy overlap with AI Orchestrator-owned redaction, persistence and
transport.

The evaluated `packages/talker/pubspec.yaml` reports 5.1.20 at commit
`654391c1a81c6a0fa4a05d46562cc0d15241d964`. No Git tag `v5.1.20` exists, so the proof deliberately
uses a null source tag instead of inferring one from the commit message.

## Safety conclusion

Both selected candidates are only **research-shortlisted** here. Their engine lifecycle remains
`SCREENED` until Full-Tree, supply-chain, SBOM and OSV admission is performed. Both dry-run
manifests therefore remain `discovered`, with Library tests/security review explicitly false.
