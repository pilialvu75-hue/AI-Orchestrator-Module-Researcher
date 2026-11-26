"""Minimal read-only upstream acquisition; never execute downloaded source."""
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

START = time.monotonic()
ROOT = Path(sys.argv[1]) / "incoming" / "dart-lang-core"
TOKEN = os.environ.get("GITHUB_TOKEN", "")
def api(path):
    req = urllib.request.Request("https://api.github.com/repos/dart-lang/core/" + path,
        headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)

def blob(item):
    data = base64.b64decode(api("git/blobs/" + item["sha"])["content"])
    assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == item["sha"]
    return data

# First observation uses a known upstream organization, not arbitrary binaries.
commit = api("commits/main")["sha"]
tree = api("git/trees/" + commit + "?recursive=1")
if tree["truncated"]:
    raise RuntimeError("Incomplete upstream tree")
items = {x["path"]: x for x in tree["tree"]}
packages = sorted({p.split("/")[1] for p in items if re.fullmatch(r"pkgs/[a-z_]+/pubspec.yaml", p)})
added = 0
for name in packages:
    if (ROOT / name).exists():
        continue
    prefix = "pkgs/" + name + "/"
    selected = [x for p,x in items.items() if p.startswith(prefix) and
        (p.endswith(".dart") and p.startswith(prefix+"lib/") or
         p[len(prefix):] in ("LICENSE", "LICENSE.md", "pubspec.yaml", "NOTICE", "README.md"))]
    if not selected or not any(x["path"].endswith("/pubspec.yaml") for x in selected):
        continue
    if not any(x["path"].startswith(prefix+"lib/") for x in selected):
        continue
    if any(x["type"] != "blob" or x["mode"] != "100644" or x.get("size",0)>512000 for x in selected) or sum(x.get("size",0) for x in selected)>2000000 or len(selected)>100:
        print(name, "SKIP source bounds or file type", flush=True)
        continue
    payload = {}
    try:
        for x in selected:
            rel = x["path"][len(prefix):]
            if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in (".","..") and not part.startswith(".") for part in rel.split("/")):
                raise ValueError("unsafe path")
            data = blob(x)
            source = data.decode("utf-8")
            if "\0" in source or re.search(r"Process\s*\.\s*(run|start)|DynamicLibrary\s*\.\s*open|dart:ffi|dart:mirrors", source):
                raise ValueError("baseline suspicious source")
            payload[rel] = data
        license_data = payload.get("LICENSE", payload.get("LICENSE.md", b""))
        if b"Redistribution and use" not in license_data or b"Neither the name" not in license_data:
            raise ValueError("license not recognized")
    except (ValueError, UnicodeError) as exc:
        print(name, "SKIP", str(exc), flush=True)
        continue
    target = ROOT / name
    for rel,data in payload.items():
        path = target / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    receipt = {"source": "https://github.com/dart-lang/core", "commit": commit,
        "package": name, "status": "SOURCE_REFERENCE_ONLY", "security": "baseline static screening only; not malware clearance",
        "license": "BSD-style; see original LICENSE", "files": {p:hashlib.sha256(d).hexdigest() for p,d in payload.items()}}
    (target/"receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    added += 1
    print(name, "ACQUIRED", len(payload), "files", sum(map(len,payload.values())), "bytes", flush=True)
    if added >= 3:
        break
print(json.dumps({"discovered":len(packages),"acquired":added,"elapsed_seconds":round(time.monotonic()-START,2)}))
