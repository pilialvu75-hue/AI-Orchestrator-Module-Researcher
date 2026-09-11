from __future__ import annotations

from pathlib import Path

FORBIDDEN_LIBRARY_PATHS = ("modules/", "catalog/index.json")
FORBIDDEN_SECRET_PATTERNS = ("ghp_", "github_pat_", "sk-proj-", "BEGIN PRIVATE KEY")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    violations: list[str] = []
    for path in (root / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_SECRET_PATTERNS:
            if pattern in text:
                violations.append(f"{path}: secret-like pattern {pattern}")
    submission = (root / "src/researcher/submission.py").read_text(encoding="utf-8")
    for forbidden in FORBIDDEN_LIBRARY_PATHS:
        if f'"{forbidden}' in submission or f"'{forbidden}" in submission:
            violations.append(f"submission client references forbidden Library path {forbidden}")
    if violations:
        raise SystemExit("\n".join(violations))


if __name__ == "__main__":
    main()
