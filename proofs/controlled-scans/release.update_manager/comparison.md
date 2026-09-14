# `release.update_manager` comparison

There is no honest single winner for the current logical boundary because the Library title combines update
discovery/policy, durable artifact transfer and platform application/install semantics.

| Candidate | Strongest role | Android | Desktop | Durable transfer | Policy/discovery | Apply/install | Research result |
|---|---|---:|---:|---:|---:|---:|---|
| `background_downloader` 9.6.1 | artifact transfer | yes | yes | strong | no | no documented cross-platform installer | shortlist as component |
| `app_updater` 2.1.0 | discovery/policy/store handoff | yes | yes | no | strong | store-oriented handoff | shortlist as component |
| `updat` 1.4.0 | direct desktop updater | not claimed here | yes | integrated desktop flow | basic | opens downloaded installer | screened reference |

## Preferred composition

For a future Library-owned `release.update_manager.v1` implementation, the strongest current direction is a
composition rather than pretending one package solves everything:

1. Library/Cantiere-owned update orchestration and policy boundary.
2. `app_updater`-style discovery/policy/store handoff where store-managed distribution is appropriate.
3. `background_downloader`-style persistent transfer for direct artifacts, large model/voice/update payloads and
   restart-safe downloads.
4. A separately defined platform apply/install adapter for direct desktop installers and Android-specific install
   policy where the product distribution model permits it.

`updat` remains valuable evidence for the desktop apply stage but is not promoted to a cross-target candidate.

## Security/admission note

The two primary candidates are research-shortlisted only. Their engine lifecycle remains `SCREENED` because this
manual controlled proof did not execute Full-Tree admission, generate a complete SBOM or query OSV. No candidate
code was executed and no Library intake submission is produced from this proof.
