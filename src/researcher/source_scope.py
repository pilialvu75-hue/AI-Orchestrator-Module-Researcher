from __future__ import annotations


def validate_source_subpath(value: str | None) -> str | None:
    """Return a canonical repository-relative package scope or fail closed."""

    if value is None:
        return None
    scope = value.strip()
    if not scope:
        return None
    if len(scope) > 512:
        raise ValueError("source subpath is too long")
    if scope.startswith("/") or scope.endswith("/"):
        raise ValueError("source subpath must be a canonical repository-relative path")
    if "\\" in scope or "\x00" in scope:
        raise ValueError("source subpath contains an invalid separator or NUL")
    parts = scope.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("source subpath contains an unsafe path segment")
    return "/".join(parts)


def path_is_in_scope(path: str, source_subpath: str | None) -> bool:
    if source_subpath is None:
        return True
    return path == source_subpath or path.startswith(f"{source_subpath}/")
