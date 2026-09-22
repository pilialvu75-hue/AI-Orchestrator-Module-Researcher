# Handoff

This directory is the private continuity contract for the definitive Module Researcher.

Read in this order:

1. `.airlab/roadmap.yaml`
2. `.airlab/state.json`
3. `.airlab/decisions.md`
4. Current workflows/tests relevant to the selected roadmap item.

Current direction:

- Autonomous seeding runs every six hours against Module Library needs.
- The first missing capability should become Researcher work; repeated Cantiere regeneration is not acceptable.
- Researcher and Cantiere may eventually exchange structured sanitized **control messages**, but source/executable candidates must still pass through Library.
- Cantiere may build a missing capability in parallel. Once its reusable solution is captured/certified by Library, Researcher can use approved metadata and real feedback to search for better alternatives.
- Real physical-device/application feedback is a future Researcher signal, not release authority.

Repository lineage:

`Ai_orchestrator-prova1` -> **AI-Orchestrator-Module-Researcher** (definitive).

Do not restore the retired direct code dispatch to Cantiere.

When roadmap state changes, update `roadmap.yaml`, `state.json` and new decisions in `decisions.md` in the same PR.
