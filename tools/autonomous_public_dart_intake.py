"""Discover and acquire one immutable, permissively licensed public Dart package.

Owned by Researcher; writes only a NOT-CERTIFIED source sandbox under a
checked-out Library. No upstream code executes with cross-repository credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

REMOTE = "https://github.com/dart-lang/core.git"
REPOSITORY = "https://github.com/dart-lang/core"
# Only generic, previously specified Aivexus integration contracts are supported.
# Actual source tag, version, commit and package choice are resolved on each run.
PROFILES = {
    "path": "platform.filesystem",
    "characters": "platform.filesystem",
    "fixnum": "platform.process",
}
TAG = re.compile(r"(path|characters|fixnum)-v([0-9]+[.][0-9]+[.][0-9]+)$")
SHA = re.compile(r"[a-f0-9]{40}$")
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 400, 524288, 12582912


def git(*args: str, cwd: Path | None = None, timeout: int = 120) -> bytes:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                          capture_output=True, timeout=timeout).stdout


def known(library: Path) -> set[str]:
    found = set()
    for p in (library / "sandbox/researcher_public_dart").glob("*/metadata.json"):
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if obj.get("source_repository") == REPOSITORY:
            found.add(obj.get("package"))
    for p in (library / "intake").glob("*/*/manifest.json"):
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        origin = obj.get("provenance") or {}
        if origin.get("source_repository") == REPOSITORY:
            subtree = origin.get("source_subtree") or ""
            if subtree.startswith("pkgs/"):
                found.add(subtree[5:])
    return found


def discover(tags: bytes, existing: set[str], needs: set[str]) -> list[tuple[str, str, str]]:
    by_package = {}
    for line in tags.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].startswith("refs/tags/"):
            continue
        tag = fields[1][10:]
        m = TAG.fullmatch(tag)
        if not m or m[1] in existing or PROFILES[m[1]] not in needs:
            continue
        by_package.setdefault(m[1], []).append(
            (tuple(int(x) for x in m[2].split(".")), tag, m[2]))
    result = []
    for pkg in PROFILES:
        for _, tag, version in sorted(by_package.get(pkg, []), reverse=True):
            result.append((pkg, tag, version))
    return result


def adapter(pkg: str) -> tuple[str, str]:
    if pkg == "path":
        return (
            "import 'package:path/path.dart' as p;\n"
            "class AivexusPathOps {\n"
            " String join(String a, String b) => p.posix.join(a, b);\n"
            " String normalize(String s) => p.posix.normalize(s);\n}\n",
            " final x = AivexusPathOps();\n"
            " if (x.join('a','b') != 'a/b' || x.normalize('a/../b') != 'b')\n"
            "   throw StateError('real path functionality failed');\n",
        )
    if pkg == "characters":
        return (
            "import 'package:characters/characters.dart';\n"
            "class AivexusTextOps {\n"
            " int graphemes(String s) => Characters(s).length;\n}\n",
            " if (AivexusTextOps().graphemes('hello') != 5)\n"
            "   throw StateError('real grapheme functionality failed');\n",
        )
    if pkg == "fixnum":
        return (
            "import 'package:fixnum/fixnum.dart';\n"
            "class AivexusIntOps {\n"
            " int sum(int a, int b) => (Int64(a)+Int64(b)).toInt();\n}\n",
            " if (AivexusIntOps().sum(3, 8) != 11)\n"
            "   throw StateError('real fixed integer functionality failed');\n",
        )
    raise ValueError("no audited integration template")


def payload_digest(root: Path) -> str:
    h = hashlib.sha256()
    for f in sorted((x for x in root.rglob("*") if x.is_file()),
                    key=lambda p: p.as_posix()):
        if f.is_symlink():
            raise ValueError("symlink inside source payload")
        rel = f.relative_to(root).as_posix().encode()
        h.update(len(rel).to_bytes(8, "big"))
        h.update(rel)
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


def acquire(library: Path, pkg: str, tag: str, version: str, repo: Path) -> dict:
    commit = git("rev-parse", "HEAD", cwd=repo).decode().strip()
    if SHA.fullmatch(commit) is None:
        raise ValueError("tag did not resolve to immutable commit")
    prefix = "pkgs/" + pkg + "/"
    rows = git("ls-tree", "-r", "-z", "HEAD", "pkgs/" + pkg, cwd=repo)
    files: dict[str, tuple[str, bytes]] = {}
    total = 0
    for row in rows.split(bytes([0])):
        if not row:
            continue
        fields, path = row.split(bytes([9]), 1)
        mode, typ, blob_sha = fields.decode("ascii").split()
        name = path.decode("utf-8")
        if not name.startswith(prefix):
            raise ValueError("out-of-scope public file")
        rel = name[len(prefix):]
        parts = PurePosixPath(rel).parts
        if (not rel or rel.startswith("/") or chr(92) in rel
                or any(x in ("", ".", "..") for x in parts)
                or mode != "100644" or typ != "blob"
                or SHA.fullmatch(blob_sha) is None):
            raise ValueError("untrusted symlink, executable, gitlink or unsafe file path")
        blob = git("cat-file", "blob", blob_sha, cwd=repo)
        total += len(blob)
        if len(files) >= MAX_FILES or len(blob) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("upstream package too large")
        files[rel] = (blob_sha, blob)
    pubspec = files.get("pubspec.yaml", ("", b""))[1].decode("utf-8")
    if not re.search("(?m)^name:[ ]*" + re.escape(pkg) + "[ ]*$", pubspec):
        raise ValueError("upstream package name mismatch")
    if not re.search("(?m)^version:[ ]*" + re.escape(version) + "[ ]*$", pubspec):
        raise ValueError("tag is not verified stable package version")
    if re.search("(?m)^dependencies:[ ]*$", pubspec):
        raise ValueError("unreviewed third party runtime dependency")
    if "lib/" + pkg + ".dart" not in files:
        raise ValueError("public Dart library absent")
    license_bytes = files.get("LICENSE", ("", b""))[1]
    if b"Redistribution and use in source and binary forms" not in license_bytes:
        raise ValueError("BSD-3-Clause license bytes not demonstrated")
    target = library / "sandbox/researcher_public_dart" / pkg
    if target.exists():
        raise ValueError("package already staged")
    wrapper = "aivexus_external_" + pkg
    public_code, assertions = adapter(pkg)
    source = target / "payload/src"
    payloads = {("vendor/" + pkg + "/" + rel): body
                for rel, (_, body) in files.items()}
    payloads["lib/aivexus_external.dart"] = public_code.encode()
    payloads["pubspec.yaml"] = (
        "name: " + wrapper + "\nversion: 0.1.0\npublish_to: none\n"
        "environment:\n  sdk: ^3.4.0\ndependencies:\n  " + pkg +
        ":\n    path: vendor/" + pkg + "\n").encode()
    payloads["tool/self_test.dart"] = (
        "import 'package:" + wrapper + "/aivexus_external.dart';\n"
        "void main() {\n" + assertions +
        " print('PASS: independently acquired public Dart source');\n}\n"
    ).encode()
    for rel, body in payloads.items():
        p = source / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    meta = {
        "schema": "aivexus.researcher.autonomous-public-dart-intake.v1",
        "state": "NORMALIZED_NOT_TESTED", "package": pkg, "package_version": version,
        "capability_id": PROFILES[pkg], "source_repository": REPOSITORY,
        "source_subtree": "pkgs/" + pkg, "source_tag": tag,
        "source_commit": commit, "source_license": "BSD-3-Clause",
        "source_git_blobs": {p: blob for p, (blob, _) in files.items()},
        "payload_sha256": payload_digest(source), "upstream_files": len(files),
        "source_materialized": True, "independent_security_reviewed": False,
        "certification_authorized": False, "production_installation_authorized": False,
    }
    (target / "metadata.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def run(library: Path) -> dict:
    if not (library / "catalog/needs.json").is_file():
        raise ValueError("Library needs catalog missing")
    needs = json.loads((library / "catalog/needs.json").read_text(encoding="utf-8"))
    wanted = {x.get("capability_id") for x in needs.get("items", [])
              if x.get("status") == "needed"}
    pending = [p for p in PROFILES if PROFILES[p] in wanted and p not in known(library)]
    if not pending:
        return {"created": False, "reason": "no_missing_supported_package"}
    tags = git("ls-remote", "--tags", "--refs", REMOTE, timeout=50)
    candidates = discover(tags, known(library), wanted)[:12]
    failures = []
    for pkg, tag, version in candidates:
        try:
            with tempfile.TemporaryDirectory(prefix="public-dart-source-") as tmp:
                source = Path(tmp) / "upstream"
                git("clone", "--quiet", "--depth", "1", "--branch", tag,
                    "--no-checkout", REMOTE, str(source), timeout=180)
                result = acquire(library, pkg, tag, version, source)
            return {"created": True, "package": pkg,
                    "source_commit": result["source_commit"],
                    "payload_sha256": result["payload_sha256"],
                    "security_reviewed": False, "certification_authorized": False}
        except (ValueError, subprocess.SubprocessError, OSError, UnicodeError) as exc:
            failures.append({"package": pkg, "tag": tag, "error_type": type(exc).__name__})
    return {"created": False, "reason": "all_candidates_rejected",
            "attempted": len(candidates), "failures": failures[:5]}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--library-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = run(args.library_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
