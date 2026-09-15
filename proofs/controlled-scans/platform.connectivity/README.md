# platform.connectivity controlled research proof

This proof closes **research/discovery depth only** for the staged `platform.connectivity` need. It does not approve Library intake, assert contract conformance, or claim runtime certification.

## Boundary

The draft contract deliberately separates three dimensions:

1. local network transport availability/type;
2. actual Internet reachability and online/offline transitions;
3. metering/cost/expensive-network policy.

A connected Wi-Fi or cellular transport is not proof of Internet access, and neither signal alone describes metering.

## Candidate strategy

- `connectivity_plus 7.3.1` is pinned to the exact release commit and covers Android, iOS, Linux, macOS, Web and Windows. Its Linux implementation uses NetworkManager through `package:nm`.
- `internet_connection_checker_plus 3.1.2` is pinned independently and is pure Dart. It checks external reachability and exposes a real-time `InternetStatus` stream.
- For Raspberry Pi, Raspberry Pi OS Bookworm uses NetworkManager by default, which provides a research bridge for the first family; the second family uses pure Dart/HTTP and is mechanically independent. This is not hardware validation.

## Security state

Both pinned dry-run preflights were attempted with Library writes disabled and no untrusted execution. GitHub API returned HTTP 504 before a security verdict for both candidates. They therefore remain `DEFERRED_API_TIMEOUT` and are **not security admitted**. The timeout is infrastructure evidence, not a candidate security failure.

## Metering gap

Discovery depth is satisfied, but the staged need explicitly includes metering. A normalized policy for expensive/constrained/metered/cost signals still needs platform-specific evidence and tests. Contract conformance therefore remains open.

## Decision

There are two independent research families for every required target, including Raspberry Pi through qualified Linux evidence. Discovery depth is closed. Security admission, metering semantics, contract conformance and runtime validation remain open and fail-closed.
