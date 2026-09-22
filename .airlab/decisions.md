# Private architecture decisions

Updated: 2026-09-22  
Reconstructed from the historical Researcher conversations, predecessor repository and current main.

## Repository identity

- `Ai_orchestrator-prova1` was the first Researcher workspace and completed Milestone 1.
- `AI-Orchestrator-Module-Researcher` is the definitive Researcher repository.
- The predecessor must not be developed in parallel; it is a historical/recovery snapshot.

## Normal operation

- `Autonomous Library Seeding` is the normal scheduled path and runs every six hours.
- The Module Library needs list is the authority for what is missing.
- A newly registered Library capability gap becomes Researcher work on the **first** gap.
- Researcher search runs in parallel with Cantiere's attempt to build what the current user request needs; Researcher must not block the current project.

## Security boundary

- Researcher does not execute external candidate code as part of discovery.
- Researcher never sends candidate source/executables directly to Cantiere.
- Candidate material goes to Module Library intake, where quarantine/certification owns the trust transition.
- The historical direct Researcher -> Cantiere repository-dispatch path is retired.
- The legacy Module Evolution Worker is manual-only for queue recovery/audit.

## Direct communication with Cantiere

- A future direct Researcher <-> Cantiere **control plane** is allowed and useful.
- It may carry structured sanitized events such as capability gaps, targeted research requests, found/no-match status, certification status, runtime feedback, security alerts and replacement candidates.
- It may not be used as a disguised source-code/executable transport.

## Learning loop

- Library-approved metadata about Cantiere-created capabilities may guide future Researcher searches.
- Real application integration results and physical-device validation may become search signals.
- Researcher may propose improvements/replacements but cannot overwrite certified Library state.

## Cost policy

- Zero-cost/free-first remains the default.
- Paid providers/services are never silently activated.

## Roadmap policy

- Persistent roadmap/state is stored only in private repositories for now.
- Future chats/agents must read `.airlab/handoff.md` before changing this repository.


## First-party legacy repositories

- Owner-controlled legacy private repositories may be mined as first-party sources.
- The allowlist is owned by Module Library at `.airlab/first-party-sources.yaml`.
- Access must be read-only and explicit.
- Discovery does not execute legacy source code.
- Every extracted candidate retains repository/commit provenance and still enters Module Library intake/certification.
- This path is for reuse recovery, not for reviving old products in parallel.
