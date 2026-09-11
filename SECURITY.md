# Security policy

All discovered source code is treated as untrusted.

Researcher V1 performs metadata analysis only. It does not clone and execute arbitrary
candidate code. A future benchmark runner must be a separate sandboxed component with
ephemeral filesystem, no secrets, network denied by default, strict CPU/RAM/time limits,
repository size caps and guaranteed cleanup.

Secrets are runtime-only environment variables and must never be written to dossiers,
status endpoints or logs. Real Library writes are fail-closed behind both `DRY_RUN=false`
and `ALLOW_LIBRARY_WRITE=true`.

Report security defects privately to the repository owner rather than publishing credentials
or exploit details in an issue.
