"""Exercise complete public releases, provenance binding and safe download pages."""
import copy
import hashlib
import html.parser
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_catalog", ROOT / "scripts/release_catalog.py")
CATALOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CATALOG)
REPOSITORY = "dotnetdev-kr/cbodotnet"


def fixture(version="10.0.403"):
    tag = "sdk-" + version
    manifest = {"schemaVersion": 1, "sdkVersion": version, "tag": tag,
                "repository": REPOSITORY, "architectures": {}}
    assets = []
    checksums = []

    def api_asset(name, data):
        return {"name": name, "size": len(data), "state": "uploaded",
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "browser_download_url": "https://github.com/" + REPOSITORY + "/releases/download/" + tag + "/" + name}

    for arch, rid in CATALOG.ARCHITECTURES.items():
        entry = {"provenance": {"targetRid": rid, "projectCommit": "a" * 40,
                    "runId": "123", "runAttempt": "1", "artifactId": 456,
                    "workflowUrl": "https://github.com/" + REPOSITORY + "/actions/runs/123"}}
        for kind in CATALOG.KINDS:
            name = ("evidence-" + arch if kind == "evidence" else
                    "cbodotnet-" + kind + "-" + version + "-linux-" + arch) + ".tar.gz"
            data = (kind + arch).encode()
            descriptor = {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            entry[kind] = descriptor
            assets.append(api_asset(name, data))
            checksums.append(descriptor["sha256"] + "  " + name + "\n")
        manifest["architectures"][arch] = entry
    checksum_bytes = "".join(checksums).encode()
    manifest["checksums"] = {"name": "SHA256SUMS", "size": len(checksum_bytes),
                              "sha256": hashlib.sha256(checksum_bytes).hexdigest()}
    manifest_bytes = json.dumps(manifest).encode()
    assets += [api_asset("SHA256SUMS", checksum_bytes), api_asset("release-manifest.json", manifest_bytes)]
    release = {"tag_name": tag, "draft": False, "prerelease": False,
               "html_url": "https://github.com/" + REPOSITORY + "/releases/tag/" + tag,
               "published_at": "2026-11-01T00:00:00Z", "assets": assets}
    return release, manifest, manifest_bytes, checksum_bytes


class CatalogTests(unittest.TestCase):
    def test_complete_release_binds_both_architectures_and_sources(self):
        release, _, manifest, checksums = fixture()
        result = CATALOG.validate_release(release, manifest, checksums, REPOSITORY)
        self.assertEqual({"x64", "aarch64"}, set(result["architectures"]))
        self.assertEqual("linux-arm64", result["architectures"]["aarch64"]["provenance"]["targetRid"])
        self.assertTrue(result["architectures"]["aarch64"]["sdk"]["url"].endswith("-aarch64.tar.gz"))

    def test_api_digest_mismatch_is_rejected(self):
        release, _, manifest, checksums = fixture()
        release["assets"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            CATALOG.validate_release(release, manifest, checksums, REPOSITORY)

    def test_manifest_download_digest_mismatch_is_rejected(self):
        release, _, manifest, checksums = fixture()
        modified = manifest.replace(b'"projectCommit": "aaaa', b'"projectCommit": "bbbb', 1)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            CATALOG.validate_release(release, modified, checksums, REPOSITORY)

    def test_historical_api_without_digest_still_requires_manifest_sizes(self):
        release, _, manifest, checksums = fixture()
        for asset in release["assets"]:
            asset.pop("digest")
        CATALOG.validate_release(release, manifest, checksums, REPOSITORY)
        release["assets"][0]["size"] += 1
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            CATALOG.validate_release(release, manifest, checksums, REPOSITORY)

    def test_foreign_download_url_is_rejected(self):
        release, _, manifest, checksums = fixture()
        release["assets"][0]["browser_download_url"] = "https://example.com/sdk.tar.gz"
        with self.assertRaisesRegex(ValueError, "download URL"):
            CATALOG.validate_release(release, manifest, checksums, REPOSITORY)

    def test_incomplete_or_duplicated_architecture_is_rejected(self):
        _, manifest, _, _ = fixture()
        for mutation in (lambda data: data["architectures"].pop("x64"),
                         lambda data: data["architectures"].update(arm64=data["architectures"]["aarch64"])):
            changed = copy.deepcopy(manifest)
            mutation(changed)
            with self.assertRaisesRegex(ValueError, "both aarch64 and x64"):
                CATALOG.validate_manifest(changed, REPOSITORY)

    def test_provenance_cannot_point_to_a_different_run_or_rid(self):
        _, manifest, _, _ = fixture()
        for key, value in (("targetRid", "linux-x64"), ("runId", "999"), ("projectCommit", "a" * 39),
                           ("runAttempt", False), ("artifactId", -1)):
            changed = copy.deepcopy(manifest)
            changed["architectures"]["aarch64"]["provenance"][key] = value
            with self.assertRaises(ValueError):
                CATALOG.validate_manifest(changed, REPOSITORY)

    def test_public_aliases_must_match_the_sdk_version(self):
        _, manifest, _, _ = fixture()
        for field, value in (("sdkVersion", "10.0.404"), ("tag", "sdk-10.0.404"), ("repository", "other/repo")):
            changed = copy.deepcopy(manifest)
            changed[field] = value
            with self.assertRaises(ValueError):
                CATALOG.validate_manifest(changed, REPOSITORY)
        manifest["architectures"]["aarch64"]["sdk"]["name"] = "cbodotnet-sdk-10.0.403-linux-arm64.tar.gz"
        with self.assertRaisesRegex(ValueError, "asset name"):
            CATALOG.validate_manifest(manifest, REPOSITORY)

    def test_checksum_missing_duplicate_and_unexpected_entries_are_rejected(self):
        release, manifest, _, checksums = fixture()
        for changed in (checksums.splitlines(keepends=True)[0], checksums + checksums.splitlines(keepends=True)[0],
                        checksums + b"0" * 64 + b"  unexpected.tar.gz\n"):
            changed_manifest = copy.deepcopy(manifest)
            changed_manifest["checksums"].update(size=len(changed), sha256=hashlib.sha256(changed).hexdigest())
            manifest_bytes = json.dumps(changed_manifest).encode()
            changed_release = copy.deepcopy(release)
            for asset in changed_release["assets"]:
                data = changed if asset["name"] == "SHA256SUMS" else manifest_bytes
                if asset["name"] in ("SHA256SUMS", "release-manifest.json"):
                    asset.update(size=len(data), digest="sha256:" + hashlib.sha256(data).hexdigest())
            with self.assertRaises(ValueError):
                CATALOG.validate_release(changed_release, manifest_bytes, changed, REPOSITORY)

    def test_release_must_be_public_stable_and_complete(self):
        release, _, manifest, checksums = fixture()
        for field in ("draft", "prerelease"):
            changed = copy.deepcopy(release)
            changed[field] = True
            with self.assertRaisesRegex(ValueError, "public and stable"):
                CATALOG.validate_release(changed, manifest, checksums, REPOSITORY)
        release["assets"][0]["state"] = "open"
        with self.assertRaisesRegex(ValueError, "incomplete"):
            CATALOG.validate_release(release, manifest, checksums, REPOSITORY)

    def test_catalog_skips_unpublished_releases_and_sorts_versions_numerically(self):
        fixtures = [fixture("9.0.123"), fixture("10.0.403"), fixture("3.1.426")]
        payloads = {}
        for release, _, manifest, checksums in fixtures:
            for asset in release["assets"]:
                if asset["name"] in ("release-manifest.json", "SHA256SUMS"):
                    payloads[asset["browser_download_url"]] = manifest if asset["name"] == "release-manifest.json" else checksums
        ignored = [{"draft": True, "tag_name": "sdk-11.0.100"},
                   {"prerelease": True, "tag_name": "sdk-11.0.100-preview"}, {"tag_name": "diagnostic"}]
        catalog = CATALOG.build_catalog([entry[0] for entry in fixtures] + ignored,
            lambda asset, limit: payloads[asset["browser_download_url"]], REPOSITORY, "2026-11-01T00:00:00Z")
        self.assertEqual(["10.0.403", "9.0.123", "3.1.426"], [row["sdkVersion"] for row in catalog["releases"]])
        self.assertEqual("2026-11-01T00:00:00Z", catalog["generatedAt"])

    def test_broken_public_sdk_release_fails_instead_of_hiding_it(self):
        with self.assertRaisesRegex(ValueError, "missing its publication manifest"):
            CATALOG.build_catalog([{"tag_name": "sdk-10.0.403", "assets": []}], lambda *_: b"", REPOSITORY)

    def test_duplicate_releases_are_rejected(self):
        release, _, manifest, checksums = fixture()
        with self.assertRaisesRegex(ValueError, "Duplicate public SDK"):
            CATALOG.build_catalog([release, release], lambda asset, _: manifest
                if asset["name"] == "release-manifest.json" else checksums, REPOSITORY)

    def test_page_contains_only_verified_asset_links_and_no_script(self):
        release, _, manifest, checksums = fixture()
        catalog = CATALOG.build_catalog([release], lambda asset, _: manifest
            if asset["name"] == "release-manifest.json" else checksums, REPOSITORY)
        document = CATALOG.render_html(catalog, (ROOT / "site/index.html.in").read_text())

        class Links(html.parser.HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []
                self.scripts = 0

            def handle_starttag(self, tag, attrs):
                if tag == "a":
                    self.links.append(dict(attrs)["href"])
                self.scripts += tag == "script"

        parser = Links()
        parser.feed(document)
        for asset in release["assets"]:
            self.assertIn(asset["browser_download_url"], parser.links)
        self.assertEqual(0, parser.scripts)
        self.assertNotIn("{{", document)
        self.assertIn("Linux aarch64", document)

    def test_empty_catalog_has_no_invented_downloads(self):
        catalog = CATALOG.build_catalog([], lambda *_: self.fail("Unexpected fetch"), REPOSITORY)
        document = CATALOG.render_html(catalog, (ROOT / "site/index.html.in").read_text())
        self.assertIn("No complete public builds", document)
        self.assertNotIn("/releases/download/", document)

    def test_metadata_fetch_never_sends_credentials_to_download_links(self):
        with mock.patch.object(CATALOG.urllib.request, "urlopen") as opener:
            opener.return_value.__enter__.return_value.read.return_value = b"data"
            CATALOG.get_bytes("https://github.com/example/repo/releases/download/sdk-1.0.100/SHA256SUMS", 100,
                              token="test-only-secret")
            request = opener.call_args.args[0]
            self.assertNotIn("Authorization", dict(request.header_items()))
            CATALOG.get_bytes("https://api.github.com/repos/example/repo/releases", 100,
                              token="test-only-secret", api=True)
            self.assertEqual("Bearer test-only-secret", dict(opener.call_args.args[0].header_items())["Authorization"])

    def test_untrusted_metadata_origins_are_rejected_before_a_request(self):
        with mock.patch.object(CATALOG.urllib.request, "urlopen") as opener:
            for url in ("http://github.com/x", "https://example.com/x", "https://user@github.com/x",
                        "file:///tmp/metadata"):
                with self.assertRaisesRegex(ValueError, "Untrusted"):
                    CATALOG.get_bytes(url, 100, token="test-only-secret")
            with self.assertRaisesRegex(ValueError, "Credentials"):
                CATALOG.get_bytes("https://github.com/example/repo", 100, token="test-only-secret", api=True)
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
