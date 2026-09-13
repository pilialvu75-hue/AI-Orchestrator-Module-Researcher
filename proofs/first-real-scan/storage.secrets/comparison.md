# storage.secrets — controlled real scan

Library need: `storage.secrets` / `storage.secrets.v1`  
Targets: Android + desktop  
Mode: `DRY_RUN`

## Candidates

### Default: flutter_secure_storage 11.1.1

`juliansteenbakker/flutter_secure_storage` is the mature candidate. The evaluated release is
pinned to commit `7ee0d6733b3e5179f6874eff34f6d9756c44c16e` and verified tag
`flutter_secure_storage-v11.1.1`. It exposes a small key/value API while delegating secret
protection to platform-specific mechanisms. Its maintenance, documentation, CI and release
provenance are materially stronger than the alternative.

### Emerging alternative: webauthn_secure_storage 0.2.3

`JohnGalt1717/webauthn_secure_storage` is an independent hardware/biometric-oriented
implementation pinned to signed commit `807eb716e506bcc48e7b5a739d2b2c93131cf6d0`. It provides
strong native concepts across Android and desktop platforms, but the project is young and has
limited adoption. It therefore remains a useful alternative, not an equal-confidence default.

## Security status

Neither candidate is certified or considered safe merely because it is shortlisted. No
candidate code was executed. The full-source Security Admission Gate, dependency/SBOM review
and sandbox validation have not yet run, so both candidates are explicitly
`certification_eligible=false`.

The Researcher may collect and analyse evidence; only the Library may certify a module.
Critical static findings must block admission rather than merely reduce a score.

## Outcome

Two independent candidates satisfy the discovery target. `flutter_secure_storage 11.1.1` is
the preferred mature default for a thin `storage.secrets.v1` adapter. The WebAuthn candidate is
retained as an emerging alternative requiring stricter validation. No Library intake was
written.
