# Private architecture decisions

Updated: 2026-09-22

- Autonomous Library Seeding remains the normal scheduled Researcher path and currently runs every six hours.
- The historical Module Evolution Worker is manual-only and must not dispatch code directly to Cantiere.
- Direct Researcher-Cantiere communication may be reintroduced only as a sanitized control plane, not a code execution path.
- Missing capability discovery begins on the first Library gap, not after repeated implementations.
- Cantiere-created reusable solutions are stored through Library, while Researcher may later use their approved metadata and real integration results to improve future searches.
- Roadmap/state files are stored only in private repositories for now.
