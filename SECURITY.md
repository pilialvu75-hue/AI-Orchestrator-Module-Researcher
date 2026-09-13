# Security policy

All discovered source code is treated as untrusted.

## Candidate admission pipeline

A discovered candidate is never trusted merely because it is popular, licensed, well tested,
or hosted on GitHub. The intended lifecycle is:

`FOUND -> QUARANTINED -> STATIC_ANALYSIS -> SUPPLY_CHAIN_ANALYSIS -> SBOM_VULNERABILITY_ANALYSIS -> SANDBOX_TEST -> LIBRARY_REVIEW -> CERTIFIED`

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

### Supply-chain admission gate

`researcher.supply_chain` analyses dependency manifests already collected by the full-tree
scan. It does not invoke npm, pub, pip, cargo, Go tooling or any package-manager lifecycle
script. This avoids turning dependency inspection itself into code execution.

The initial zero-cost analyser supports `package.json`, `pubspec.yaml`, `Cargo.toml`,
`pyproject.toml`, `requirements.txt` and `go.mod`, while recording recognised lockfiles. It
extracts direct dependency provenance and requires review for trust-boundary changes such as:

- npm lifecycle hooks including `preinstall`, `install`, `postinstall` and `prepare`;
- Git dependencies, even when commit-pinned, until their dependency source is separately
  admitted;
- Git dependencies that are not pinned to an exact 40-character commit;
- local/path/workspace and editable dependencies;
- direct HTTP/archive dependency references;
- Cargo path/Git dependencies, Pub path/Git dependencies and Go `replace` directives;
- dependency manifests that cannot be parsed or ecosystems not yet supported by the gate.

A clean source tree is therefore not enough for automatic admission: the supply-chain report
must also be `CLEAR`. Supply-chain evidence is stored in the dossier, including manifests,
lockfiles and enumerated direct dependencies.

### SBOM and vulnerability admission gate

`researcher.vulnerability` and `researcher.vulnerability_admission` add a fail-closed,
zero-cost vulnerability correlation stage without running package managers or candidate code.
The Researcher reads recognised lockfiles at the exact immutable candidate commit and builds a
deterministic SBOM-like inventory with a SHA-256 fingerprint. Exact registry versions may also
be taken from already-admitted dependency manifests where the constraint itself is exact.

The first vulnerability database is OSV. Only dependency versions that can be resolved to an
exact package version are queried. Automatic admission requires all of the following:

- the earlier full-tree and supply-chain gates are `CLEAR`;
- the SBOM has no unresolved dependency versions;
- the vulnerability database query completes successfully and returns a structurally valid
  response for every queried component;
- no known vulnerability is returned for the exact queried package/version set.

An unresolved version, unreadable/oversized lockfile, vulnerability-database outage, malformed
response, component-budget overflow or known vulnerability produces `SECURITY_REVIEW`, never a
clean admission. A database outage is therefore not equivalent to "zero vulnerabilities".
Known vulnerability findings are review evidence rather than an automatic exploitability
claim; Library review remains responsible for severity, reachability, remediation and final
certification decisions.

The dossier records the SBOM fingerprint, component count, whether vulnerability correlation
actually completed, the database verdict and the number of known vulnerability hits. Candidate
or package-manager code is still never executed at this stage.

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
