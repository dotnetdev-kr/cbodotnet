#!/usr/bin/env python3
"""Validate public SDK releases and render a small, dependency-free download site."""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request


ARCHITECTURES = {"aarch64": "linux-arm64", "x64": "linux-x64"}
KINDS = ("sdk", "source", "evidence")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_CHECKSUM_BYTES = 64 * 1024
ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def repository_name(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value),
            "Invalid repository name")
    return value


def positive_id(value, field):
    require(not isinstance(value, bool) and re.fullmatch(r"[1-9][0-9]*", str(value)),
            "Invalid " + field)
    return str(value)


def asset_descriptor(value, expected_name):
    require(isinstance(value, dict), "Missing asset descriptor: " + expected_name)
    require(value.get("name") == expected_name, "Unexpected asset name: " + expected_name)
    require(type(value.get("size")) is int and value["size"] > 0, "Invalid asset size: " + expected_name)
    require(isinstance(value.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", value["sha256"]),
            "Invalid SHA-256: " + expected_name)
    return value


def asset_descriptors(manifest):
    for arch in ARCHITECTURES:
        for kind in KINDS:
            yield manifest["architectures"][arch][kind]
    yield manifest["checksums"]


def validate_manifest(manifest, repository, release=None):
    """Validate names, target identities and provenance without trusting artifact code."""
    repository_name(repository)
    require(isinstance(manifest, dict) and type(manifest.get("schemaVersion")) is int
            and manifest["schemaVersion"] == 1, "Unsupported release manifest")
    version = manifest.get("sdkVersion")
    require(isinstance(version, str) and re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version),
            "Invalid stable SDK version")
    require(manifest.get("tag") == "sdk-" + version, "Release tag does not match SDK version")
    require(manifest.get("repository") == repository, "Release repository does not match")
    architectures = manifest.get("architectures")
    require(isinstance(architectures, dict) and set(architectures) == set(ARCHITECTURES),
            "A public SDK release requires both aarch64 and x64")
    for arch, rid in ARCHITECTURES.items():
        entry = architectures[arch]
        require(isinstance(entry, dict), "Invalid architecture entry")
        asset_descriptor(entry.get("sdk"), "cbodotnet-sdk-" + version + "-linux-" + arch + ".tar.gz")
        asset_descriptor(entry.get("source"), "cbodotnet-source-" + version + "-linux-" + arch + ".tar.gz")
        asset_descriptor(entry.get("evidence"), "evidence-" + arch + ".tar.gz")
        provenance = entry.get("provenance")
        require(isinstance(provenance, dict) and provenance.get("targetRid") == rid, "Unexpected target RID")
        require(isinstance(provenance.get("projectCommit"), str)
                and re.fullmatch(r"[a-f0-9]{40}", provenance["projectCommit"]), "Invalid producer commit")
        run_id = positive_id(provenance.get("runId"), "workflow run ID")
        positive_id(provenance.get("runAttempt"), "workflow run attempt")
        positive_id(provenance.get("artifactId"), "workflow artifact ID")
        require(provenance.get("workflowUrl") == "https://github.com/" + repository + "/actions/runs/" + run_id,
                "Workflow URL does not match release provenance")
    asset_descriptor(manifest.get("checksums"), "SHA256SUMS")
    if release is not None:
        require(isinstance(release, dict) and release.get("tag_name") == manifest["tag"], "API release tag mismatch")
        require(release.get("draft") is False and release.get("prerelease") is False, "Release is not public and stable")
        require(release.get("html_url") == "https://github.com/" + repository + "/releases/tag/" + manifest["tag"],
                "Unexpected release URL")
    return manifest


def validate_api_asset(asset, name, repository, tag, descriptor=None, content=None):
    require(isinstance(asset, dict) and asset.get("name") == name and asset.get("state") == "uploaded",
            "Release asset is missing or incomplete: " + name)
    require(type(asset.get("size")) is int and asset["size"] > 0, "Invalid API asset size: " + name)
    expected_url = "https://github.com/" + repository + "/releases/download/" + tag + "/" + name
    require(asset.get("browser_download_url") == expected_url, "Unexpected asset download URL: " + name)
    if descriptor is not None:
        require(asset["size"] == descriptor["size"], "API asset size mismatch: " + name)
    if content is not None:
        require(len(content) == asset["size"], "Downloaded asset size mismatch: " + name)
    digest = asset.get("digest")
    if digest is not None:
        require(isinstance(digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", digest),
                "Unsupported API asset digest: " + name)
        if descriptor is not None:
            require(digest == "sha256:" + descriptor["sha256"], "API asset digest mismatch: " + name)
        if content is not None:
            require(digest == "sha256:" + sha256(content), "Downloaded API asset digest mismatch: " + name)
    if descriptor is not None and content is not None:
        require(sha256(content) == descriptor["sha256"], "Downloaded manifest digest mismatch: " + name)


def release_assets(release):
    assets = release.get("assets")
    require(isinstance(assets, list), "Release assets are missing")
    names = [asset.get("name") for asset in assets if isinstance(asset, dict)]
    require(len(names) == len(assets) and len(set(names)) == len(names), "Duplicate or malformed release assets")
    return {asset["name"]: asset for asset in assets}


def validate_checksums(manifest, checksum_bytes):
    """Require one checksum for every SDK, source and evidence archive."""
    require(len(checksum_bytes) <= MAX_CHECKSUM_BYTES, "Release checksums exceed their size limit")
    expected = {manifest["architectures"][arch][kind]["name"]: manifest["architectures"][arch][kind]["sha256"]
                for arch in ARCHITECTURES for kind in KINDS}
    observed = {}
    for line in checksum_bytes.decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64}) [ *]([A-Za-z0-9._-]+)", line)
        require(match is not None and match[2] not in observed, "Malformed or duplicate checksum entry")
        observed[match[2]] = match[1]
    require(observed == expected, "SHA256SUMS does not match the complete release")


def validate_release(release, manifest_bytes, checksum_bytes, repository):
    """Authenticate a release manifest and its complete two-architecture asset list."""
    require(len(manifest_bytes) <= MAX_JSON_BYTES and len(checksum_bytes) <= MAX_CHECKSUM_BYTES,
            "Release metadata exceeds its size limit")
    manifest = json.loads(manifest_bytes)
    validate_manifest(manifest, repository, release)
    assets = release_assets(release)
    tag = manifest["tag"]
    validate_api_asset(assets.get("release-manifest.json"), "release-manifest.json", repository, tag,
                       content=manifest_bytes)
    for descriptor in asset_descriptors(manifest):
        validate_api_asset(assets.get(descriptor["name"]), descriptor["name"], repository, tag, descriptor)
    validate_api_asset(assets["SHA256SUMS"], "SHA256SUMS", repository, tag, manifest["checksums"], checksum_bytes)
    validate_checksums(manifest, checksum_bytes)
    return {"sdkVersion": manifest["sdkVersion"], "tag": tag,
            "releaseUrl": release["html_url"], "publishedAt": release.get("published_at"),
            "manifestUrl": assets["release-manifest.json"]["browser_download_url"],
            "checksumsUrl": assets["SHA256SUMS"]["browser_download_url"],
            "architectures": {arch: {**manifest["architectures"][arch],
                **{kind: {**manifest["architectures"][arch][kind],
                          "url": assets[manifest["architectures"][arch][kind]["name"]]["browser_download_url"]}
                   for kind in KINDS}} for arch in ARCHITECTURES}}


def get_bytes(url, maximum, token=None, api=False):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in {"api.github.com", "github.com"}
            and parsed.username is None and parsed.password is None, "Untrusted GitHub metadata URL")
    headers = {"User-Agent": "cbodotnet-release-catalog", "Accept": "application/vnd.github+json" if api else "application/octet-stream"}
    if api:
        require(parsed.hostname == "api.github.com", "Credentials may only be sent to the GitHub API")
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if token:
            headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        data = response.read(maximum + 1)
    require(len(data) <= maximum, "Downloaded metadata exceeds its size limit")
    return data


def fetch_releases(repository, token=None):
    repository_name(repository)
    releases = []
    for page in range(1, 101):
        url = "https://api.github.com/repos/" + repository + "/releases?per_page=100&page=" + str(page)
        entries = json.loads(get_bytes(url, MAX_JSON_BYTES, token, api=True))
        require(isinstance(entries, list), "Invalid GitHub release API response")
        releases.extend(entries)
        if len(entries) < 100:
            return releases
    raise ValueError("Release pagination exceeded the explicit 10,000-release bound")


def build_catalog(releases, fetch_asset, repository, generated_at=None):
    records = []
    seen = set()
    for release in releases:
        if release.get("draft") or release.get("prerelease") or not str(release.get("tag_name", "")).startswith("sdk-"):
            continue
        assets = release_assets(release)
        require("release-manifest.json" in assets and "SHA256SUMS" in assets,
                "A public SDK release is missing its publication manifest or checksums")
        record = validate_release(release,
            fetch_asset(assets["release-manifest.json"], MAX_JSON_BYTES),
            fetch_asset(assets["SHA256SUMS"], MAX_CHECKSUM_BYTES), repository)
        require(record["sdkVersion"] not in seen, "Duplicate public SDK version")
        seen.add(record["sdkVersion"])
        records.append(record)
    records.sort(key=lambda row: tuple(int(part) for part in row["sdkVersion"].split(".")), reverse=True)
    return {"schemaVersion": 1, "repository": repository, "generatedAt": generated_at or
            datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), "releases": records}


def render_html(catalog, template):
    escape = html.escape
    rows = []
    for release in catalog["releases"]:
        cells = ['<th scope="row"><a href="' + escape(release["releaseUrl"], quote=True) + '">' +
                 escape(release["sdkVersion"]) + '</a></th>']
        for arch in ("x64", "aarch64"):
            entry = release["architectures"][arch]
            links = []
            for kind, label in (("sdk", "tar.gz"), ("source", "source"), ("evidence", "evidence")):
                asset = entry[kind]
                links.append('<a href="' + escape(asset["url"], quote=True) + '">' + label + '</a>')
            cells.append('<td>' + ' &middot; '.join(links) + '<br><small>' +
                         format(entry["sdk"]["size"] / (1024 * 1024), ".1f") + ' MiB SDK</small></td>')
        cells.append('<td><a href="' + escape(release["checksumsUrl"], quote=True) + '">SHA-256</a><br>' +
                     '<a href="' + escape(release["manifestUrl"], quote=True) + '">manifest</a></td>')
        rows.append('<tr>' + ''.join(cells) + '</tr>')
    if not rows:
        rows.append('<tr><td colspan="4">No complete public builds are available yet.</td></tr>')
    replacements = {"{{DOWNLOAD_ROWS}}": "\n".join(rows), "{{GENERATED_AT}}": escape(catalog["generatedAt"]),
                    "{{REPOSITORY_URL}}": "https://github.com/" + escape(catalog["repository"], quote=True)}
    for key, value in replacements.items():
        require(template.count(key) >= 1, "Missing site template placeholder: " + key)
        template = template.replace(key, value)
    require("{{" not in template, "Unresolved site template placeholder")
    return template


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "dotnetdev-kr/cbodotnet"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--template", type=Path, default=ROOT / "site" / "index.html.in")
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    releases = fetch_releases(args.repository, token)
    catalog = build_catalog(releases, lambda asset, limit: get_bytes(asset["browser_download_url"], limit), args.repository)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "index.html").write_text(render_html(catalog, args.template.read_text(encoding="utf-8")), encoding="utf-8")
    (args.output_dir / "releases.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / ".nojekyll").write_text("", encoding="utf-8")
    print(json.dumps({"status": "passed", "releases": len(catalog["releases"]), "output": str(args.output_dir)}))


if __name__ == "__main__":
    main()
