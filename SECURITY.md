# Security policy

All discovered source code is treated as untrusted.

## Candidate admission pipeline

A discovered candidate is never trusted merely because it is popular, licensed, well tested,
or hosted on GitHub. The intended lifecycle is:

`FOUND -> QUARANTINED -> STATIC_ANALYSIS -> SUPPLY_CHAIN_ANALYSIS -> SANDBOX_TEST -> LIBRARY_REVIEW -> CERTIFIED`

Researcher may discover and analyse candidates, but only the Library is allowed to certify them.
No candidate may skip a stage.

### Static admission gate

`researcher.security_gate` performs a fail-closed static pre-screen over source text supplied by
a source adapter. It never executes candidate content. Missing scan evidence is
`NOT_SCANNED`, which is not certification-eligible. High-risk patterns require human/Library
review, while critical patterns such as download-and-execute chains or apparent credential
exfiltration are blocked.

The static gate is only the first source-code layer. Before certification, the pipeline must
also inspect dependency provenance, lockfiles, Git dependencies, install/build hooks,
submodules, bundled/precompiled binaries, unexpected network behaviour, credential/keystore
access, obfuscation and generated code. Findings are evidence for review, not proof of safety.

### Execution isolation

Researcher V1 does not clone and execute arbitrary candidate code. Any future benchmark or
compatibility execution must run in a separate sandbox runner with:

- ephemeral filesystem and guaranteed destruction after the run;
- no GitHub token, API key, signing key, keystore, SSH key or project secret;
- no mount of the Researcher, Library, Cantiere or application repositories;
- network denied by default and allowlisted only for a test that explicitly requires it;
- strict CPU, RAM, process-count, disk and wall-clock limits;
- repository and artifact size caps;
- no privileged container mode, host socket, Docker socket or host device access;
- immutable candidate commit provenance and recorded hashes;
- complete logs/results exported as evidence before cleanup.

The sandbox result does not certify a candidate by itself. Library review remains the final
authority.

## Project secrets and Library writes

Secrets are runtime-only environment variables and must never be written to dossiers,
status endpoints or logs. Real Library writes are fail-closed behind both `DRY_RUN=false`
and `ALLOW_LIBRARY_WRITE=true`.

Report security defects privately to the repository owner rather than publishing credentials
or exploit details in an issue.
