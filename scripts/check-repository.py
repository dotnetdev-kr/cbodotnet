#!/usr/bin/env python3
"""Check source syntax, pinned patch bytes and local documentation links."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    python_files = sorted((root / "scripts").glob("*.py"))
    python_files += sorted((root / "tests").glob("*.py"))
    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    shell_files = sorted((root / "scripts").glob("*.sh"))
    for path in shell_files:
        subprocess.run(["bash", "-n", str(path)], check=True)
    json_files = sorted((root / "profiles").glob("*.json"))
    json_files += sorted((root / "patches").rglob("*.json"))
    for path in json_files:
        json.loads(path.read_text(encoding="utf-8-sig"))

    checked = set()

    def pinned(base, relative, expected):
        path = base / relative
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
            raise ValueError("Unsafe or absent pinned input: " + str(path))
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected.lower():
            raise ValueError("Pinned input changed: " + str(path.relative_to(root)))
        checked.add(path)

    # Historical baseline manifests can reference superseded patch payloads.
    # Verify their retained bytes, and the payloads selected by active manifests.
    for path in (root / "patches").glob("*/manifest.json"):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        previous = data.get("previousManifest")
        if previous:
            pinned(path.parent, previous["name"], previous["sha256"])
        for patch in data.get("patches", []):
            if "patchSha256" in patch:
                pinned(path.parent, patch["name"], patch["patchSha256"])
    for path in (root / "profiles").glob("*.json"):
        profile = json.loads(path.read_text(encoding="utf-8-sig"))
        for patch in profile.get("build", {}).get("patches", []):
            if isinstance(patch, dict) and patch.get("path", "").startswith("patches/") and "sha256" in patch:
                pinned(root, patch["path"], patch["sha256"])

    links = 0
    documents = [root / "README.md", *sorted((root / "docs").glob("*.md"))]
    for path in documents:
        content = path.read_text(encoding="utf-8-sig")
        if re.search(r"[\uac00-\ud7a3]", content):
            raise ValueError("Repository documentation must use English: " + str(path))
        if sum(line.startswith("```") for line in content.splitlines()) % 2:
            raise ValueError("Unclosed Markdown code fence: " + str(path))
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", content):
            target = target.strip("<>").split("#", 1)[0]
            if not target or "://" in target or target.startswith(("mailto:", "/")):
                continue
            if not (path.parent / target).exists():
                raise ValueError("Broken documentation link: " + str(path) + ": " + target)
            links += 1
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    for path in workflows:
        for action in re.findall(r"uses:\s*([^\s#]+)", path.read_text()):
            if not action.startswith("./") and not re.fullmatch(r"[\w.-]+/[\w./-]+@[a-f0-9]{40}", action):
                raise ValueError("Actions must be pinned to full commit SHAs: " + action)
    print(json.dumps({"status": "passed", "pythonFiles": len(python_files),
                      "bashFiles": len(shell_files), "jsonFiles": len(json_files),
                      "pinnedInputs": len(checked), "localLinks": links,
                      "workflows": len(workflows)}))


if __name__ == "__main__":
    main()
