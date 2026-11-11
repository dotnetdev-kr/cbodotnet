"""Exercise complete public releases, provenance binding and safe download pages."""
import copy
import hashlib
import html.parser
import importlib.util
import io
import json
from pathlib import Path
import tempfile
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


def consumer_fixture(version="10.0.403"):
    base = "https://github.com/" + REPOSITORY + "/releases/download/distribution-archive-sdk-" + version + "-r1/"
    return [dict(sdkVersion=version, architecture=arch,
                 archiveName="cbodotnet-sdk-" + version + "-linux-" + arch + "-r1.tar.gz",
                 archiveUrl=base + "cbodotnet-sdk-" + version + "-linux-" + arch + "-r1.tar.gz",
                 archiveSha256=hashlib.sha256(arch.encode()).hexdigest(),
                 manifestUrl=base + "consumer-manifest.json", signatureUrl=base + "consumer-manifest.json.asc",
                 userSpaces=["ubuntu-24.04", "debian-13"])
            for arch in ("x64", "aarch64")]


class AnonymousMetadataFallbackTests(unittest.TestCase):
    url = "https://github.com/example/repo/releases/download/sdk-10.0.403/release-manifest.json"
    api_url = "https://api.github.com/repos/example/repo/releases/tags/sdk-10.0.403"
    asset_url = "https://api.github.com/repos/example/repo/releases/assets/123"
    payload = b"exact metadata"

    def api_release(self):
        return dict(tag_name="sdk-10.0.403", draft=False,
                    assets=[dict(id=123, name="release-manifest.json", state="uploaded", size=len(self.payload),
                                 browser_download_url=self.url, url=self.asset_url)])

    def response(self, data):
        response = mock.MagicMock()
        response.__enter__.return_value.read.side_effect = lambda maximum: data[:maximum]
        return response

    def failures(self, error=None):
        error = error or CATALOG.urllib.error.HTTPError(self.url, 504, "transient", {}, None)
        return [error] * 3

    def test_three_transient_failures_use_two_bounded_anonymous_api_gets_for_the_same_asset(self):
        for error in (CATALOG.urllib.error.HTTPError(self.url, 504, "transient", {}, None),
                      CATALOG.urllib.error.URLError("connection reset"), TimeoutError("timed out")):
            with self.subTest(error=type(error).__name__), mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                    mock.patch.object(CATALOG.time, "sleep") as sleep, \
                    mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO) as stderr:
                release = self.api_release()
                before = copy.deepcopy(release)
                metadata = self.response(json.dumps(release).encode())
                binary = self.response(self.payload)
                opener.side_effect = self.failures(error) + [metadata, binary]
                self.assertEqual(self.payload, CATALOG.get_bytes(self.url, 100, token="private-token"))
                self.assertEqual(before, release)
                self.assertEqual(5, opener.call_count)
                self.assertEqual([mock.call(2), mock.call(4)], sleep.call_args_list)
                self.assertEqual(self.url, opener.call_args_list[0].args[0].full_url)
                self.assertEqual(self.api_url, opener.call_args_list[3].args[0].full_url)
                self.assertEqual(self.asset_url, opener.call_args_list[4].args[0].full_url)
                self.assertEqual("application/vnd.github+json", opener.call_args_list[3].args[0].get_header("Accept"))
                self.assertEqual("application/octet-stream", opener.call_args_list[4].args[0].get_header("Accept"))
                metadata.__enter__.return_value.read.assert_called_once_with(8 * 1024**2 + 1)
                binary.__enter__.return_value.read.assert_called_once_with(len(self.payload) + 1)
                for call in opener.call_args_list:
                    self.assertNotIn("Authorization", dict(call.args[0].header_items()))
                    self.assertEqual({"timeout": 60}, call.kwargs)
                self.assertEqual("GitHub metadata GET anonymous API fallback: " + self.url + "\n", stderr.getvalue())

    def test_fallback_rejects_malformed_or_ambiguous_release_and_asset_identity_before_binary_get(self):
        mutations = [
            lambda value: value.update(tag_name="sdk-9.0.123"),
            lambda value: value.update(draft=True),
            lambda value: value.update(assets=None),
            lambda value: value.update(assets=[None]),
            lambda value: value.update(assets=[]),
            lambda value: value["assets"].append(copy.deepcopy(value["assets"][0])),
            lambda value: value["assets"][0].update(name="other-manifest.json"),
            lambda value: value["assets"][0].update(state="new"),
            lambda value: value["assets"][0].update(browser_download_url=self.url.replace("example/repo", "foreign/repo")),
            lambda value: value["assets"][0].update(browser_download_url=self.url + "?different=asset"),
            lambda value: value["assets"][0].update(url="https://example.com/asset"),
            lambda value: value["assets"][0].update(url=self.asset_url + "?different=asset"),
            lambda value: value["assets"][0].update(url=self.asset_url.replace("123", "456")),
        ]
        for field, invalid in (("id", 0), ("id", -1), ("id", True), ("id", "123"),
                               ("size", 0), ("size", -1), ("size", True), ("size", "14"), ("size", 101)):
            mutations.append(lambda value, field=field, invalid=invalid: value["assets"][0].update({field: invalid}))
        for index, mutate in enumerate(mutations):
            release = self.api_release()
            mutate(release)
            with self.subTest(case=index), mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                    mock.patch.object(CATALOG.time, "sleep"), mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO):
                opener.side_effect = self.failures() + [self.response(json.dumps(release).encode())]
                with self.assertRaises(ValueError):
                    CATALOG.get_bytes(self.url, 100)
                self.assertEqual(4, opener.call_count)

    def test_fallback_rejects_oversized_api_metadata_and_asset_size_mismatch(self):
        metadata = json.dumps(self.api_release()).encode()
        for response, expected_calls in ((self.response(b" " * (8 * 1024**2 + 1)), 4),
                                         (self.response(self.payload + b"extra"), 5),
                                         (self.response(self.payload[:-1]), 5)):
            with self.subTest(requests=expected_calls), mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                    mock.patch.object(CATALOG.time, "sleep"), mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO):
                opener.side_effect = self.failures() + ([response] if expected_calls == 4 else [self.response(metadata), response])
                with self.assertRaisesRegex(ValueError, "size"):
                    CATALOG.get_bytes(self.url, 100)
                self.assertEqual(expected_calls, opener.call_count)

    def test_fallback_api_failures_are_not_retried_or_followed_by_another_fallback(self):
        for calls in (4, 5):
            error = CATALOG.urllib.error.HTTPError(self.asset_url, 504, "transient", {}, None)
            with self.subTest(requests=calls), mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                    mock.patch.object(CATALOG.time, "sleep") as sleep, mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO):
                opener.side_effect = self.failures() + ([error] if calls == 4 else [self.response(json.dumps(self.api_release()).encode()), error])
                with self.assertRaises(CATALOG.urllib.error.HTTPError) as raised:
                    CATALOG.get_bytes(self.url, 100)
                self.assertIs(error, raised.exception)
                self.assertEqual(calls, opener.call_count)
                self.assertEqual([mock.call(2), mock.call(4)], sleep.call_args_list)

    def test_noncanonical_api_and_large_requests_never_use_the_fallback(self):
        for url, maximum, api in ((self.url + "?private-query=hidden", 100, False),
                                  (self.url + "#fragment", 100, False),
                                  (self.url, 16 * 1024**2 + 1, False),
                                  (self.api_url, 100, True)):
            error = CATALOG.urllib.error.HTTPError(url, 504, "transient", {}, None)
            with self.subTest(url=url, maximum=maximum), mock.patch.object(CATALOG.urllib.request, "urlopen", side_effect=error) as opener, \
                    mock.patch.object(CATALOG.time, "sleep"), mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO) as stderr:
                with self.assertRaises(CATALOG.urllib.error.HTTPError) as raised:
                    CATALOG.get_bytes(url, maximum, token="private-token", api=api)
                self.assertIs(error, raised.exception)
                self.assertEqual(3, opener.call_count)
                self.assertNotIn("fallback", stderr.getvalue())
                self.assertNotIn("private-query", stderr.getvalue())
                self.assertNotIn("private-token", stderr.getvalue())

    def test_permanent_canonical_download_error_never_uses_the_fallback(self):
        for status in (401, 403, 404, 429, 500):
            error = CATALOG.urllib.error.HTTPError(self.url, status, "permanent", {}, None)
            with self.subTest(status=status), mock.patch.object(CATALOG.urllib.request, "urlopen", side_effect=error) as opener, \
                    mock.patch.object(CATALOG.time, "sleep") as sleep, mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO):
                with self.assertRaises(CATALOG.urllib.error.HTTPError):
                    CATALOG.get_bytes(self.url, 100)
                opener.assert_called_once()
                sleep.assert_not_called()

    def test_fallback_body_still_must_pass_the_existing_caller_digest_check(self):
        body = b"{}" + b" " * (len(self.payload) - 2)
        release = self.api_release()
        original = dict(name="release-manifest.json", state="uploaded", size=len(self.payload),
                        browser_download_url=self.url, digest="sha256:" + CATALOG.sha256(self.payload))
        with mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, mock.patch.object(CATALOG.time, "sleep"), \
                mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO):
            opener.side_effect = self.failures() + [self.response(json.dumps(release).encode()), self.response(body)]
            data = CATALOG.get_bytes(self.url, 100)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            CATALOG.validate_api_asset(original, "release-manifest.json", "example/repo", "sdk-10.0.403", content=data)


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

    def test_page_shows_verified_archives_and_their_sources_without_original_sdk_downloads(self):
        release, _, manifest, checksums = fixture()
        catalog = CATALOG.build_catalog([release], lambda asset, _: manifest
            if asset["name"] == "release-manifest.json" else checksums, REPOSITORY)
        consumers = consumer_fixture()
        document = CATALOG.render_html(catalog, (ROOT / "site/index.html.in").read_text(), consumer_archives=consumers)

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
        for consumer in consumers:
            for field in ("archiveUrl", "manifestUrl", "signatureUrl"):
                self.assertIn(consumer[field], parser.links)
        for arch in ("x64", "aarch64"):
            for kind in ("source", "evidence"):
                self.assertIn(catalog["releases"][0]["architectures"][arch][kind]["url"], parser.links)
            self.assertNotIn(catalog["releases"][0]["architectures"][arch]["sdk"]["url"], parser.links)
        self.assertEqual(0, parser.scripts)
        self.assertNotIn("{{", document)
        self.assertNotIn("unbranded", document.lower())
        self.assertNotIn("experimental", document.lower())
        self.assertNotIn("Original source releases", document)
        self.assertIn("Linux AArch64", document)

    def test_archive_rows_group_architectures_by_version_and_collapse_release_details(self):
        catalog = CATALOG.build_catalog([], lambda *_: self.fail("Unexpected fetch"), REPOSITORY)
        consumers = consumer_fixture("8.0.133") + consumer_fixture()
        consumers[0]["compatibility"] = dict(url="https://github.com/companion.tar.gz")
        consumers[0]["nativeHttpCompatibility"] = dict(url="https://github.com/curl-companion.tar.gz")
        document = CATALOG.render_html(catalog, (ROOT / "site/index.html.in").read_text(), consumer_archives=consumers)
        self.assertEqual(2, document.count('<span class="sdk-version">'))
        self.assertLess(document.index('<span class="sdk-version">10.0.403'), document.index('<span class="sdk-version">8.0.133'))
        self.assertEqual(4, document.count('class="download-button"'))
        self.assertEqual(2, document.count('<details class="archive-details">'))
        self.assertNotIn('<details class="archive-details" open', document)
        self.assertIn('href="https://github.com/companion.tar.gz"', document)
        self.assertIn('href="https://github.com/curl-companion.tar.gz"', document)
        self.assertIn("Required SSL / ICU companion", document)
        self.assertIn("Required Core 3 libcurl companion", document)
        for consumer in consumers:
            self.assertIn(consumer["archiveSha256"], document)
        self.assertIn("Verified on ubuntu-24.04, debian-13", document)

    def test_installer_has_its_own_section_before_archives_and_channel_instructions(self):
        catalog = CATALOG.build_catalog([], lambda *_: self.fail("Unexpected fetch"), REPOSITORY)
        document = CATALOG.render_html(catalog, (ROOT / "site/index.html.in").read_text(),
                                       installer_markup='<h3>Verified installer fixture</h3>')
        self.assertLess(document.index('id="installer"'), document.index('id="downloads"'))
        self.assertLess(document.index('Verified installer fixture'), document.index('id="packages"'))
        for target in ("installer", "packages", "containers"):
            self.assertIn('class="choice" href="#' + target + '"', document)

    def test_empty_catalog_has_no_invented_downloads(self):
        catalog = CATALOG.build_catalog([], lambda *_: self.fail("Unexpected fetch"), REPOSITORY)
        document = CATALOG.render_html(catalog, (ROOT / "site/index.html.in").read_text())
        self.assertIn("SDK archives will appear here after signed publication", document)
        self.assertNotIn("/releases/download/", document)

    def test_site_delivery_includes_the_social_image_and_absolute_card_metadata(self):
        catalog = CATALOG.build_catalog([], lambda *_: self.fail("Unexpected fetch"), REPOSITORY)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source"
            (source / "assets").mkdir(parents=True)
            image = b"fixture-social-card-image"
            (source / "assets/social-card.jpg").write_bytes(image)
            template = source / "index.html.in"
            template.write_text((ROOT / "site/index.html.in").read_text(encoding="utf-8"), encoding="utf-8")
            output = directory / "published"
            empty_status = {"schemaVersion": 1, "repository": REPOSITORY, "status": "fixture",
                            "channels": {name: {"status": "not-published", "publications": []}
                                         for name in ("deb", "oci", "rpm", "aur")}}
            empty_musl_status = {"schemaVersion": 1, "kind": "musl-distribution-availability",
                                 "repository": REPOSITORY, "libc": "musl", "status": "not-published",
                                 "publications": [], "installerAdmission": "separate-issue-30"}
            with mock.patch("distribution_site.prepare_site", return_value=empty_status), \
                 mock.patch("consumer_archive_site.archive_rows", return_value=[]), \
                 mock.patch("cbodotnetup_site.prepare", return_value=""), \
                 mock.patch("musl_site.load_status", return_value=empty_musl_status), \
                 mock.patch("musl_site.get_bytes", side_effect=AssertionError("Unexpected musl metadata fetch")):
                CATALOG.write_site(catalog, template, output)
            import release_scorecard
            scorecard = release_scorecard.publish(output)
            self.assertEqual(image, (output / "assets/social-card.jpg").read_bytes())
            self.assertEqual(catalog, json.loads((output / "releases.json").read_text(encoding="utf-8")))
            availability = json.loads((output / "downstream-status.json").read_text(encoding="utf-8"))
            self.assertEqual({"deb", "oci", "rpm", "aur"}, set(availability["channels"]))
            self.assertTrue(all(row["publications"] == [] for row in availability["channels"].values()))
            self.assertNotIn("evidenceSigners", availability)
            musl_availability = json.loads((output / "musl-status.json").read_text(encoding="utf-8"))
            self.assertEqual("musl-download-catalog", musl_availability["kind"])
            self.assertEqual("not-published", musl_availability["status"])
            self.assertEqual([], musl_availability["publications"])
            self.assertEqual('release-qualification-scorecard', scorecard['kind'])
            self.assertEqual('separate', scorecard['installerAdmission'])
            self.assertTrue((output / ".nojekyll").is_file())
            document = (output / "index.html").read_text(encoding="utf-8")
            self.assertIn('id="qualification-scorecard"', document)
            self.assertIn('href="qualification-scorecard.json"', document)
            self.assertIn('docs/support-lifecycle.md', document)
            self.assertIn('docs/maintenance-objectives.md', document)
            self.assertIn('docs/platform-roadmap.md', document)
            self.assertIn('docs/release-incident-runbook.md', document)
            self.assertIn('property="og:image" content="https://dotnetdev.kr/cbodotnet/assets/social-card.jpg"', document)
            self.assertIn('name="twitter:card" content="summary_large_image"', document)
            self.assertIn('rel="canonical" href="https://dotnetdev.kr/cbodotnet/"', document)

    def test_missing_social_image_prevents_a_broken_site_delivery(self):
        catalog = CATALOG.build_catalog([], lambda *_: self.fail("Unexpected fetch"), REPOSITORY)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            template = source / "index.html.in"
            template.write_text((ROOT / "site/index.html.in").read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Missing site social-card image"):
                CATALOG.write_site(catalog, template, Path(temporary) / "published")
            self.assertFalse((Path(temporary) / "published").exists())

    def test_unverified_channel_claim_prevents_website_promotion(self):
        catalog = CATALOG.build_catalog([], lambda *_: self.fail("Unexpected fetch"), REPOSITORY)
        policy = json.loads((ROOT / "releases/downstream-status.json").read_text())
        for row in policy["channels"].values():
            row.update(status="not-published", publications=[], receipts=[])
        policy["channels"]["oci"].update(status="published", publisherConfigured=True,
                                           publications=[{"url": "https://example.com/unverified"}])
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "releases").mkdir()
            (directory / "releases/downstream-status.json").write_text(json.dumps(policy))
            with mock.patch.object(CATALOG, "ROOT", directory):
                with self.assertRaisesRegex(ValueError, "verified publication adapters"):
                    CATALOG.write_site(catalog, ROOT / "site/index.html.in", directory / "published")
            self.assertFalse((directory / "published").exists())

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

    def test_transient_metadata_http_errors_retry_fresh_public_redirects_with_bounded_backoff(self):
        url = "https://github.com/example/repo/releases/download/sdk-1.0.100/SHA256SUMS"
        for status in (502, 503, 504):
            with self.subTest(status=status), mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                    mock.patch.object(CATALOG.time, "sleep") as sleep:
                response = mock.MagicMock()
                response.__enter__.return_value.read.return_value = b"data"
                opener.side_effect = [CATALOG.urllib.error.HTTPError(url, status, "transient", {}, None),
                                      CATALOG.urllib.error.HTTPError(url, status, "transient", {}, None), response]
                self.assertEqual(b"data", CATALOG.get_bytes(url, 100, token="test-only-secret"))
                self.assertEqual(3, opener.call_count)
                self.assertEqual([mock.call(2), mock.call(4)], sleep.call_args_list)
                self.assertEqual(url, opener.call_args_list[0].args[0].full_url)
                original = CATALOG.urllib.parse.urlsplit(url)
                for attempt, call in enumerate(opener.call_args_list):
                    actual = CATALOG.urllib.parse.urlsplit(call.args[0].full_url)
                    self.assertEqual((original.scheme, original.netloc, original.path), (actual.scheme, actual.netloc, actual.path))
                    if attempt:
                        self.assertRegex(actual.query, r"^cbodotnet_retry=" + str(attempt) + r"-[0-9]+$")
                        self.assertEqual("no-cache", call.args[0].get_header("Cache-control"))
                        self.assertEqual("no-cache", call.args[0].get_header("Pragma"))
                    self.assertNotIn("Authorization", dict(call.args[0].header_items()))
                    self.assertEqual({"timeout": 60}, call.kwargs)

    def test_fresh_release_url_preserves_origin_path_and_existing_query_without_changing_non_release_urls(self):
        url = "https://github.com/example/repo/releases/download/tag/manifest.json?original=value#fragment"
        with mock.patch.object(CATALOG.time, "time_ns", return_value=123456):
            self.assertEqual(url, CATALOG.fresh_release_url(url, 0))
            self.assertEqual(url.replace("#fragment", "&cbodotnet_retry=2-123456#fragment"),
                             CATALOG.fresh_release_url(url, 2))
            for other in ("https://api.github.com/repos/example/repo/releases?per_page=100",
                          "https://github.com/example/repo/metadata", "https://example.com/x/releases/download/tag/file",
                          "http://github.com/example/repo/releases/download/tag/file",
                          "https://user@github.com/example/repo/releases/download/tag/file"):
                self.assertEqual(other, CATALOG.fresh_release_url(other, 1))

    def test_metadata_connection_errors_retry_and_keep_api_credentials_scoped(self):
        url = "https://api.github.com/repos/example/repo/releases"
        for error in (CATALOG.urllib.error.URLError("connection reset"), TimeoutError("timed out")):
            with self.subTest(error=type(error).__name__), mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                    mock.patch.object(CATALOG.time, "sleep") as sleep:
                response = mock.MagicMock()
                response.__enter__.return_value.read.return_value = b"data"
                opener.side_effect = [error, response]
                self.assertEqual(b"data", CATALOG.get_bytes(url, 100, token="test-only-secret", api=True))
                self.assertEqual(2, opener.call_count)
                sleep.assert_called_once_with(2)
                for call in opener.call_args_list:
                    self.assertEqual(url, call.args[0].full_url)
                    self.assertEqual("Bearer test-only-secret", dict(call.args[0].header_items())["Authorization"])
                    self.assertIsNone(call.args[0].get_header("Cache-control"))
                    self.assertIsNone(call.args[0].get_header("Pragma"))

    def test_metadata_read_timeout_retries_without_returning_partial_content(self):
        with mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                mock.patch.object(CATALOG.time, "sleep") as sleep:
            response = opener.return_value.__enter__.return_value
            response.read.side_effect = [TimeoutError("read timed out"), b"complete"]
            self.assertEqual(b"complete", CATALOG.get_bytes("https://github.com/example/repo/metadata", 100))
            self.assertEqual(2, opener.call_count)
            sleep.assert_called_once_with(2)

    def test_transient_metadata_failure_stops_after_three_attempts(self):
        url = "https://github.com/example/repo/metadata"
        errors = (CATALOG.urllib.error.HTTPError(url, 504, "transient", {}, None),
                  CATALOG.urllib.error.URLError("connection reset"), TimeoutError("timed out"))
        for error in errors:
            with self.subTest(error=type(error).__name__), mock.patch.object(CATALOG.urllib.request, "urlopen", side_effect=error) as opener, \
                    mock.patch.object(CATALOG.time, "sleep") as sleep:
                with self.assertRaises(type(error)) as raised:
                    CATALOG.get_bytes(url, 100)
                self.assertIs(error, raised.exception)
                self.assertEqual(3, opener.call_count)
                self.assertEqual([mock.call(2), mock.call(4)], sleep.call_args_list)

    def test_permanent_metadata_http_errors_are_not_retried(self):
        url = "https://github.com/example/repo/metadata"
        for status in (400, 401, 403, 404, 429, 500):
            error = CATALOG.urllib.error.HTTPError(url, status, "permanent", {}, None)
            with self.subTest(status=status), mock.patch.object(CATALOG.urllib.request, "urlopen", side_effect=error) as opener, \
                    mock.patch.object(CATALOG.time, "sleep") as sleep:
                with self.assertRaises(CATALOG.urllib.error.HTTPError) as raised:
                    CATALOG.get_bytes(url, 100)
                self.assertIs(error, raised.exception)
                opener.assert_called_once()
                sleep.assert_not_called()

    def test_metadata_failure_diagnostics_omit_query_token_and_redirect_url(self):
        canonical = "https://api.github.com/repos/example/repo/releases"
        url = canonical + "?private-query=hidden"
        redirect = "https://release-assets.githubusercontent.com/private-path?redirect-token=hidden"
        for error, attempts, detail in (
                (CATALOG.urllib.error.HTTPError(redirect, 403, "private-token", {}, None), 1, "HTTP 403"),
                (CATALOG.urllib.error.HTTPError(redirect, 504, "private-token", {}, None), 3, "HTTP 504"),
                (CATALOG.urllib.error.URLError(redirect + " private-token"), 3, "URLError"),
                (TimeoutError(redirect + " private-token"), 3, "TimeoutError")):
            with self.subTest(detail=detail), mock.patch.object(CATALOG.urllib.request, "urlopen", side_effect=error) as opener, \
                    mock.patch.object(CATALOG.time, "sleep"), mock.patch.object(CATALOG.sys, "stderr", new_callable=io.StringIO) as stderr:
                with self.assertRaises(type(error)) as raised:
                    CATALOG.get_bytes(url, 100, token="private-token", api=True)
                self.assertIs(error, raised.exception)
                self.assertEqual(attempts, opener.call_count)
                self.assertEqual("GitHub metadata GET failed: " + canonical + " (" + detail + ")\n", stderr.getvalue())
                for secret in ("private-query", "hidden", "private-token", "release-assets", "redirect-token"):
                    self.assertNotIn(secret, stderr.getvalue())

    def test_oversized_metadata_is_rejected_without_retry(self):
        with mock.patch.object(CATALOG.urllib.request, "urlopen") as opener, \
                mock.patch.object(CATALOG.time, "sleep") as sleep:
            response = opener.return_value.__enter__.return_value
            response.read.return_value = b"large"
            with self.assertRaisesRegex(ValueError, "size limit"):
                CATALOG.get_bytes("https://github.com/example/repo/metadata", 4)
            response.read.assert_called_once_with(5)
            opener.assert_called_once()
            sleep.assert_not_called()

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
