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

Researcher still does not execute arbitrary candidate code. `researcher.sandbox` now provides
a **planning-only** Docker sandbox foundation. It produces a hardened argv/configuration but
contains no executor and never invokes Docker or a subprocess. Every generated plan explicitly
sets `execution_enabled=false`.

The planner requires a trusted runner image pinned by SHA-256 digest and refuses protected host
paths such as the Researcher, Library, Cantiere repositories, `.git` storage and Docker socket.
Its generated policy includes:

- network namespace disabled with `--network none`;
- read-only container root filesystem;
- read-only candidate source bind mount;
- all Linux capabilities dropped;
- `no-new-privileges=true`;
- no privileged mode and no host-device mappings;
- no host secret/environment injection;
- non-root UID/GID;
- bounded CPU, RAM, PID and wall-clock policy;
- `--pull never` so execution cannot silently replace the trusted runner image;
- ephemeral tmpfs work area and a smaller no-exec tmpfs for temporary files;
- no project repository, Docker socket or broad host-directory mount.

A future executor must additionally guarantee wall-clock termination and cleanup outside the
container, stage candidate content into a dedicated ephemeral quarantine directory, capture
results without exposing host storage, verify the trusted runner image digest, and preserve the
same fail-closed policy. That executor must be separately reviewed and explicitly enabled; CI
must not execute third-party candidate code merely to test the planner.

The sandbox result will not certify a candidate by itself. Library review remains the final
authority.

## Project secrets and Library writes

Secrets are runtime-only environment variables and must never be written to dossiers,
status endpoints or logs. Real Library writes are fail-closed behind both `DRY_RUN=false`
and `ALLOW_LIBRARY_WRITE=true`.

Report security defects privately to the repository owner rather than publishing credentials
or exploit details in an issue.
