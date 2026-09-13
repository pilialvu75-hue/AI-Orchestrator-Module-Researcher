# Controlled real scan — `auth.session`

This proof records a **DRY_RUN-only** Researcher evaluation for the Library need
`auth.session` / `auth.session.v1`. Nothing in this directory is certified and
nothing was written to the Library intake or catalog.

## Library boundary

At scan time the Library exposes `auth.session.v1` version `1.0` as a **draft
logical authentication/session boundary**. There is no separate technical
contract file defining concrete APIs. This proof therefore does not invent
unstated method names or persistence semantics; contract-fit scores are
deliberately conservative.

## Shortlisted candidates

### Bdaya-Dev/oidc 4.0.0

Pinned source commit:
`eedd79f14f7b72fa0d725b9446d8c896c4c02b8b`

Why it remains on the shortlist:
- `OidcUserManager` exposes an explicit user/session lifecycle;
- authorization-code + PKCE, login/logout, discovery and automatic refresh-token
  rotation are documented;
- federated packages explicitly cover Android, iOS, Linux, macOS, Web and
  Windows;
- persistence store and HTTP client are customizable;
- tests, E2E coverage, GitHub Actions and Dependabot are present in the pinned
  tree;
- MIT license.

Main constraint: `oidc 4.0.0` requires Flutter `>=3.41.0` and Dart `^3.11.0`,
and its federated dependency surface is materially larger.

### appsup-dart/openid_client 0.4.10+1

Pinned source commit:
`44348cc4006762363a873526e33bf769d751ad71`

Why it remains on the shortlist:
- provider-neutral Dart OpenID Connect implementation;
- provider discovery, authorization-code flow, ID-token validation, refresh
  support and RP-initiated logout;
- Flutter, command-line and browser examples; published package coverage spans
  mobile, desktop and Web;
- lower framework coupling (`Dart >=3.0 <4.0`);
- BSD-3-Clause license.

Main constraint: it is a thinner authentication primitive. A trusted
`auth.session.v1` adapter still needs to make session restoration and secure
persistence semantics explicit. The pinned tree contains tests and a Travis CI
configuration, but this proof does **not** claim current upstream CI health.

## Outcome

Both candidates are `SHORTLISTED`; there is no universal winner.

- **Preferred full-session candidate:** Bdaya-Dev/oidc 4.0.0.
- **Preferred thin/lower-coupling alternative:** appsup-dart/openid_client
  0.4.10+1.

The Library must still validate platform/toolchain compatibility, storage
ownership, security, tests and the concrete `auth.session.v1` adapter before
promotion.

## Safety / evidence limits

- Candidate code was **not executed**.
- No vulnerability scan or security certification was performed.
- No benchmark was executed.
- Neither repository exposes a usable GitHub `releases/latest` object for these
  package versions, so `source_tag` is intentionally `null`; version evidence is
  pinned to each package manifest at the immutable commit.
- All generated exchange manifests remain `status: discovered`,
  `validation.tests_passed: false` and `security.reviewed: false`.
