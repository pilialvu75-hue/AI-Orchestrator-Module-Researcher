# `auth.session` candidate comparison

| Dimension | Bdaya-Dev/oidc 4.0.0 | appsup-dart/openid_client 0.4.10+1 |
|---|---|---|
| License | MIT | BSD-3-Clause |
| Requested targets | Android/Desktop/Web via federated all-platform plugin | Android/Desktop/Web via Dart IO/browser package design |
| Session lifecycle | Strong: `OidcUserManager`, user changes, login/logout, refresh | Thinner: Client/Credential/Flow primitives |
| Refresh | Automatic refresh-token rotation | Refresh supported; current release fixes refresh-future deduplication |
| Persistence | Custom store is first-class | Adapter/Library policy must define session persistence |
| Framework coupling | Flutter >=3.41, Dart ^3.11 | Dart >=3.0 <4.0 |
| Dependency surface | Larger federated stack | Smaller Dart library surface |
| Quality signals | Unit/E2E tests, GitHub Actions, Dependabot | Tests + pinned Travis config; current CI status not asserted |
| Integration trade-off | Less session-semantic work, higher host/toolchain constraints | Lower framework coupling, more adapter semantics |

## Recommendation

Use **Bdaya-Dev/oidc 4.0.0** as the preferred candidate when `auth.session.v1`
is expected to be a full session-management boundary. Keep
**appsup-dart/openid_client 0.4.10+1** as the thinner alternative when low
framework coupling and a provider-neutral OIDC core matter more.

This is a Researcher shortlist, not a Library certification. The Library
contract is currently only a draft logical boundary; no missing API semantics
were invented.
