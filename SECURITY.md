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
`NOT_SCANNED`, which is not admission-eligible. High-risk patterns require human/Library
review, while critical patterns such as download-and-execute chains or apparent credential
exfiltration are blocked.

`researcher.security_admission` adds the GitHub full-tree admission stage for candidates that
have already passed the cheaper metadata/scoring pre-screen. It resolves the exact immutable
candidate commit, verifies its tree provenance, enumerates the recursive tree, and reads only
security-relevant source/configuration blobs through the GitHub API. Candidate code is never
executed during this stage.

Automatic admission requires a `CLEAR` and complete report. The following conditions fail
closed to `REVIEW` or `BLOCK` rather than being silently ignored:

- commit or tree provenance mismatch;
- truncated recursive tree responses;
- unscanned Git submodules or symbolic links;
- bundled/precompiled binaries and archives such as `.so`, `.dll`, `.jar`, `.aar`, `.wasm`,
  `.exe` and `.zip`;
- relevant source blobs that are too large, unreadable, non-UTF-8 or exceed scan budgets;
- suspicious source patterns detected by the static gate.

The scanner has bounded file/byte budgets to prevent an upstream repository from exhausting
Researcher resources. Exceeding those budgets never produces a clean result; it requires
review. Non-code assets may be skipped after the entire tree has been enumerated, but opaque
or executable artifacts are not treated as harmless assets.

The static/full-tree gates are still only source-code layers. Before Library certification,
the pipeline must also inspect dependency provenance, lockfiles, Git dependencies,
install/build hooks, vulnerability/SBOM evidence, generated code and any behaviour observed
in an isolated sandbox. Findings are evidence for review, not proof of safety.

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
