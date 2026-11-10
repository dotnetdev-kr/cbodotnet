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
import shutil
import sys
import time
import urllib.error
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


def fresh_release_url(url, attempt):
    """Request a new public redirect on retry without changing the stored asset URL."""
    parsed = urllib.parse.urlsplit(url)
    if (attempt > 0 and parsed.scheme == "https" and parsed.netloc == "github.com"
            and re.fullmatch(r"/[^/]+/[^/]+/releases/download/[^/]+/[^/]+", parsed.path)):
        query = parsed.query + ("&" if parsed.query else "") + "cbodotnet_retry=" + str(attempt) + "-" + str(time.time_ns())
        return urllib.parse.urlunsplit(parsed._replace(query=query))
    return url


def anonymous_release_metadata(url, maximum):
    """Resolve a canonical small public asset through the anonymous GitHub API."""
    parsed = urllib.parse.urlsplit(url)
    match = re.fullmatch(r"/([A-Za-z0-9][A-Za-z0-9_.-]*)/([A-Za-z0-9][A-Za-z0-9_.-]*)/releases/download/"
                         r"([A-Za-z0-9][A-Za-z0-9_.+-]*)/([A-Za-z0-9][A-Za-z0-9_.+-]*)", parsed.path)
    if not (parsed.scheme == "https" and parsed.netloc == "github.com" and not parsed.query and not parsed.fragment
            and match and type(maximum) is int and 0 < maximum <= 16 * 1024**2):
        return None
    owner, repository, tag, name = match.groups()
    base = "https://api.github.com/repos/" + owner + "/" + repository
    headers = {"User-Agent": "cbodotnet-release-catalog", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    print("GitHub metadata GET anonymous API fallback: " + parsed.scheme + "://" + parsed.hostname + parsed.path,
          file=sys.stderr)
    request = urllib.request.Request(base + "/releases/tags/" + urllib.parse.quote(tag, safe=""), headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        metadata = response.read(MAX_JSON_BYTES + 1)
    require(len(metadata) <= MAX_JSON_BYTES, "Anonymous release API metadata exceeds its size limit")
    release = json.loads(metadata)
    require(isinstance(release, dict) and release.get("tag_name") == tag and release.get("draft") is False,
            "Anonymous release API identity differs from the public release")
    assets = release.get("assets")
    require(isinstance(assets, list) and all(isinstance(asset, dict) for asset in assets),
            "Anonymous release API assets are malformed")
    matches = [asset for asset in assets if asset.get("name") == name]
    require(len(matches) == 1, "Anonymous release API must identify the exact asset once")
    asset = matches[0]
    asset_id = asset.get("id")
    require(type(asset_id) is int and asset_id > 0 and asset.get("state") == "uploaded"
            and asset.get("browser_download_url") == url, "Anonymous release API asset identity differs")
    asset_url = base + "/releases/assets/" + str(asset_id)
    require(asset.get("url") == asset_url, "Anonymous release API asset URL differs")
    require(type(asset.get("size")) is int and 0 < asset["size"] <= maximum,
            "Anonymous release API asset exceeds its size limit")
    request = urllib.request.Request(asset_url, headers=dict(headers, Accept="application/octet-stream"))
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(asset["size"] + 1)
    require(len(data) == asset["size"], "Anonymous release API asset size differs")
    return data


def anonymous_release_download_request(url, expected):
    """Resolve a pinned public asset after gateway failures, without credentials.

    The caller must still verify the complete downloaded size and hash. This
    changes only the public redirect endpoint, never the selected release/file.
    """
    parsed = urllib.parse.urlsplit(url)
    match = re.fullmatch(r"/([A-Za-z0-9][A-Za-z0-9_.-]*)/([A-Za-z0-9][A-Za-z0-9_.-]*)/releases/download/"
                         r"([A-Za-z0-9][A-Za-z0-9_.+-]*)/([A-Za-z0-9][A-Za-z0-9_.+-]*)", parsed.path)
    require(parsed.scheme == 'https' and parsed.netloc == 'github.com' and not parsed.query and not parsed.fragment
            and match and type(expected.get('size')) is int and expected['size'] > 0
            and re.fullmatch(r'[a-f0-9]{64}', expected.get('sha256', '')),
            'An exact public release asset URL and authenticated size/hash are required')
    owner, repository, tag, name = match.groups()
    base = 'https://api.github.com/repos/' + owner + '/' + repository
    release = json.loads(get_bytes(base + '/releases/tags/' + urllib.parse.quote(tag, safe=''), MAX_JSON_BYTES, api=True))
    require(isinstance(release, dict) and release.get('tag_name') == tag and release.get('draft') is False
            and isinstance(release.get('assets'), list), 'Anonymous public release API identity differs')
    matches = [asset for asset in release['assets'] if isinstance(asset, dict) and asset.get('name') == name]
    require(len(matches) == 1, 'The anonymous API must identify the exact public file once')
    asset = matches[0]; asset_id = asset.get('id')
    require(type(asset_id) is int and asset_id > 0 and asset.get('state') == 'uploaded'
            and asset.get('browser_download_url') == url and type(asset.get('size')) is int
            and asset['size'] == expected['size'] and asset.get('url') == base + '/releases/assets/' + str(asset_id)
            and asset.get('digest') in (None, 'sha256:' + expected['sha256']),
            'Anonymous public asset API URL, size or digest differs from the pinned input')
    print('Public asset GET anonymous API fallback: ' + url, file=sys.stderr)
    return urllib.request.Request(asset['url'], headers={
        'User-Agent': 'cbodotnet-public-release-download', 'Accept': 'application/octet-stream',
        'X-GitHub-Api-Version': '2022-11-28', 'Cache-Control': 'no-cache'})


def get_bytes(url, maximum, token=None, api=False):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in {"api.github.com", "github.com"}
            and parsed.username is None and parsed.password is None, "Untrusted GitHub metadata URL")

    def report_failure(error):
        location = parsed.scheme + "://" + parsed.hostname + parsed.path
        detail = "HTTP " + str(error.code) if isinstance(error, urllib.error.HTTPError) else type(error).__name__
        print("GitHub metadata GET failed: " + location + " (" + detail + ")", file=sys.stderr)

    headers = {"User-Agent": "cbodotnet-release-catalog", "Accept": "application/vnd.github+json" if api else "application/octet-stream"}
    if api:
        require(parsed.hostname == "api.github.com", "Credentials may only be sent to the GitHub API")
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if token:
            headers["Authorization"] = "Bearer " + token
    for attempt in range(3):
        request_url = fresh_release_url(url, attempt) if not api else url
        request_headers = dict(headers)
        if request_url != url:
            request_headers.update({"Cache-Control": "no-cache", "Pragma": "no-cache"})
        request = urllib.request.Request(request_url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read(maximum + 1)
        except urllib.error.HTTPError as error:
            if error.code not in {502, 503, 504}:
                report_failure(error)
                raise
            if attempt == 2:
                data = anonymous_release_metadata(url, maximum) if not api else None
                if data is None:
                    report_failure(error)
                    raise
                break
        except (urllib.error.URLError, TimeoutError) as error:
            if attempt == 2:
                data = anonymous_release_metadata(url, maximum) if not api else None
                if data is None:
                    report_failure(error)
                    raise
                break
        else:
            break
        time.sleep(2 * (attempt + 1))
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


def render_html(catalog, template, downstream_status=None, consumer_archives=None, installer_markup='', musl_markup=''):
    from distribution_site import render_channels
    escape = html.escape

    def link(url, label, attributes=''):
        return '<a href="' + escape(url, quote=True) + '"' + attributes + '>' + escape(label) + '</a>'

    sources = {release['sdkVersion']: release for release in catalog['releases']}
    versions = {}
    for record in consumer_archives or []:
        versions.setdefault(record['sdkVersion'], {})[record['architecture']] = record
    consumer_rows = []
    for version in sorted(versions, key=lambda value: tuple(map(int, value.split('.'))), reverse=True):
        downloads, verification = [], []
        for arch, label in (('x64', 'Linux x64'), ('aarch64', 'Linux AArch64')):
            record = versions[version].get(arch)
            if record is None:
                continue
            downloads.append(link(record['archiveUrl'], label,
                ' class="download-button" aria-label="Download SDK ' + escape(version, quote=True) + ' for ' + label + '"'))
            items = [link(record['manifestUrl'], 'Manifest'), link(record['signatureUrl'], 'Signature')]
            source = sources.get(version)
            if source:
                entry = source['architectures'][arch]
                items.extend((link(entry['source']['url'], 'Build sources'), link(entry['evidence']['url'], 'Build evidence'),
                              link(source['checksumsUrl'], 'Source checksums'), link(source['manifestUrl'], 'Source manifest')))
            dependencies = []
            for key, title in (('compatibility', 'Required SSL / ICU companion'),
                               ('nativeHttpCompatibility', 'Required Core 3 libcurl companion')):
                if record.get(key):
                    dependencies.append(link(record[key]['url'], title))
            spaces = ', '.join(record.get('userSpaces', []))
            verification.append('<div class="archive-verification"><h4>' + label + '</h4>'
                + ('<p class="muted">Verified on ' + escape(spaces) + '.</p>' if spaces else '')
                + '<p class="link-list">' + ' '.join(items) + '</p>'
                + ('<p class="dependency-note">' + '<br>'.join(dependencies) + '</p>' if dependencies else '')
                + '<p class="checksum-label">Archive SHA-256</p><code class="checksum">' + escape(record['archiveSha256']) + '</code></div>')
        consumer_rows.append('<tr><th scope="row"><span class="sdk-version">' + escape(version) + '</span></th>'
            + '<td><div class="download-buttons">' + ''.join(downloads) + '</div></td>'
            + '<td><details class="archive-details"><summary>Verification, sources &amp; dependencies'
            + '<span class="visually-hidden"> for SDK ' + escape(version) + '</span></summary>'
            + '<div class="verification-grid">' + ''.join(verification) + '</div></details></td></tr>')
    consumer_markup = ('<div class="downloads"><table><thead><tr><th scope="col">SDK version</th>'
        + '<th scope="col">Download archive</th><th scope="col">Release details</th></tr></thead>'
        + '<tbody>' + ''.join(consumer_rows) + '</tbody></table></div>' if consumer_rows else
        '<p class="empty-state">SDK archives will appear here after signed publication and native installation verification.</p>')
    replacements = {"{{GENERATED_AT}}": escape(catalog["generatedAt"]),
                    "{{CONSUMER_ARCHIVES}}": consumer_markup,
                    "{{INSTALLER_PANEL}}": installer_markup or '<p>The SDK manager is not available yet. Choose an archive or a verified package below.</p>',
                    "{{DOWNSTREAM_CHANNELS}}": render_channels(downstream_status or {}),
                    "{{REPOSITORY_URL}}": "https://github.com/" + escape(catalog["repository"], quote=True)}
    if '{{MUSL_DISTRIBUTIONS}}' in template or musl_markup:
        replacements['{{MUSL_DISTRIBUTIONS}}'] = musl_markup
    for key, value in replacements.items():
        require(template.count(key) >= 1, "Missing site template placeholder: " + key)
        template = template.replace(key, value)
    require("{{" not in template, "Unresolved site template placeholder")
    return template


def write_site(catalog, template_path, output_dir):
    """Publish the download index and its social image as one static site."""
    assets = template_path.parent / "assets"
    require(assets.is_dir() and (assets / "social-card.jpg").is_file(), "Missing site social-card image")
    require(not assets.is_symlink() and not any(path.is_symlink() for path in assets.rglob("*")),
            "Site assets must not contain symbolic links")
    policy = json.loads((ROOT / "releases/downstream-status.json").read_text(encoding="utf-8"))
    from distribution_site import prepare_site
    public_status = prepare_site(policy, output_dir, ROOT / "releases/downstream-signing-key.asc")
    from consumer_archive_site import archive_rows
    consumers = archive_rows()
    from cbodotnetup_site import prepare as prepare_installer
    installer_markup = prepare_installer(output_dir)
    from musl_site import prepare as prepare_musl
    musl_markup, _ = prepare_musl(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "index.html").write_text(render_html(catalog, template_path.read_text(encoding="utf-8"), public_status, consumers, installer_markup, musl_markup), encoding="utf-8")
    (output_dir / 'archive-status.json').write_text(json.dumps(dict(schemaVersion=1, repository=catalog['repository'],
        status='published-postverified' if consumers else 'not-published', archives=consumers), indent=2) + '\n', encoding='utf-8')
    (output_dir / "releases.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    (output_dir / "downstream-status.json").write_text(json.dumps(public_status, indent=2) + "\n", encoding="utf-8")
    (output_dir / ".nojekyll").write_text("", encoding="utf-8")
    shutil.copytree(assets, output_dir / "assets", dirs_exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "dotnetdev-kr/cbodotnet"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--template", type=Path, default=ROOT / "site" / "index.html.in")
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    releases = fetch_releases(args.repository, token)
    catalog = build_catalog(releases, lambda asset, limit: get_bytes(asset["browser_download_url"], limit), args.repository)
    write_site(catalog, args.template, args.output_dir)
    print(json.dumps({"status": "passed", "releases": len(catalog["releases"]), "output": str(args.output_dir)}))


if __name__ == "__main__":
    main()
