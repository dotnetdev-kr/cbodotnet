"""SDK6-only original literal source validation with ten closed publisher checkouts.

The original literal helper/policy and all actual compiler sources stay unchanged.
This entry adds exact checkout representations, never generic EOL normalization.
"""
import base64
from functools import lru_cache
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import posixpath
import tarfile
import zipfile

FP = ('bytes', 'sha256', 'sha512')
ORIGINAL_SHA = 'c38c7f751e334d9fdc9233f131cbea1505b4d5d1951489addb91fbc92fe8e397'
ORIGINAL_POLICY_SHA = '95d7d18006735ae27abebb5454031efb19d66ad117ec8953b56e7740153a7980'
CHECKOUT_POLICY_SHA = 'c5a80ab3b47cfeabd5a006a31793eb112d5fe96e0154bf31bd3e4a31ec26732b'


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@lru_cache(maxsize=1)
def original():
    path = Path(__file__).with_name('musl_legacy6_literal_inputs.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == ORIGINAL_SHA, 'Immutable original SDK6 literal helper changed')
    policy_path = path.with_name('musl-legacy6-literal-inputs.json')
    require(hashlib.sha256(policy_path.read_bytes()).hexdigest() == ORIGINAL_POLICY_SHA, 'Immutable original SDK6 literal policy changed')
    return module('sdk6_unchanged_original_literal_checks', path.name)


def policy():
    """The unchanged package/source policy; preserve the original public interface."""
    return original().policy()


@lru_cache(maxsize=1)
def checkout_policy():
    path = Path(__file__).with_name('musl-legacy6-literal-checkout-policy.json')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == CHECKOUT_POLICY_SHA, 'Closed SDK6 publisher-checkout policy differs')
    value = json.loads(raw)
    require(value['schemaVersion'] == 1 and value['sdkVersion'] == '6.0.136'
            and value['kind'] == 'closed-sdk6-original-publisher-checkout-representations'
            and value['originalLiteralModuleSha256'] == ORIGINAL_SHA
            and value['originalLiteralPolicySha256'] == ORIGINAL_POLICY_SHA
            and value['sourceKey'] == 'aspnetcore'
            and value['commit'] == '64ea4108e7dcf1ca575f8dd2028363b0b1ef6ebc'
            and value['tree'] == 'a85bad7ff48f23e2a19ad670359a474aa2ea7a63'
            and len(value['representations']) == 10
            and value['attribute']['path'] == 'src/Mvc/test/WebSites/HtmlGenerationWebSite/wwwroot/styles/.gitattributes'
            and value['attribute']['gitBlob'] == '54a3709b28e06ab33ffd545f855f8b5c9f95b220'
            and all(value[key] is False for key in ('compilerWorktreesRewritten', 'genericEolAcceptanceAllowed',
                'publisherCompilationClaimed', 'qualificationAllowed', 'sourceAdmissionAllowed')),
            'Exactly ten SDK6 publisher checkout representations required')
    return value


def package_origin(path, sha):
    return original().package_origin(path, sha)


def declared_product(name, sha, member, data):
    return original().declared_product(name, sha, member, data)


def _checkout(root, key, name, row, entry, raw, closed):
    expected = closed['representations'].get(name)
    if (key != closed['sourceKey'] or root.get('commit') != closed['commit'] or root.get('tree') != closed['tree']
            or expected is None or not entry.isfile() or entry.mode != 0o644
            or row.get('path') != root.get('name', '') + '/' + name or entry.name != row.get('path')
            or row.get('mode') != '100644'
            or row.get('baseline') != dict(mode='100644', blob=expected['canonicalGitBlob'])):
        return False
    if (fingerprint(raw) != expected['fingerprint'] or any(row.get(key) != expected['fingerprint'][key] for key in FP)
            or raw != base64.b64decode(expected['rawBase64'], validate=True)):
        return False
    actual_blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    canonical = raw.replace(b'\r\n', b'\n')
    return (b'\0' not in raw and b'\r' not in canonical and raw == canonical.replace(b'\n', b'\r\n')
        and actual_blob == expected['rawGitBlob']
        and hashlib.sha1(b'blob ' + str(len(canonical)).encode() + b'\0' + canonical).hexdigest() == expected['canonicalGitBlob'])


def _attribute(root, key, name, row, entry, raw, closed):
    expected = closed['attribute']
    require(key == closed['sourceKey'] and root.get('commit') == closed['commit'] and root.get('tree') == closed['tree']
            and name == expected['path'] and entry.isfile() and entry.mode == 0o644
            and row.get('path') == root.get('name', '') + '/' + name and entry.name == row.get('path')
            and row.get('mode') == '100644' and row.get('baseline') == dict(mode='100644', blob=expected['gitBlob'])
            and fingerprint(raw) == expected['fingerprint']
            and all(row.get(key) == expected['fingerprint'][key] for key in FP)
            and raw == base64.b64decode(expected['rawBase64'], validate=True)
            and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['gitBlob'],
            'Exact original SDK6 publisher attribute bytes/mode/Git proof required')
    return dict(path=name, gitBlob=expected['gitBlob'], fingerprint=fingerprint(raw), mode='100644')


def _finish_attribute(proof):
    require(proof is not None, 'Original SDK6 publisher attribute proof must complete before returning')
    return proof


def _sources(release, manifest):
    p, closed = policy(), checkout_policy()
    P = module('sdk6_literal_checkout_archive_primitives', 'package-used-source.py')
    selected = {}
    for key, expected in p['sources'].items():
        matches = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export')
                   and r.get('commit') == expected['commit'] and r.get('tree') == expected['tree']
                   and not r.get('deleted') and not r.get('exclude')]
        require(len(matches) == 1, 'Complete pristine original SDK6 literal source required: ' + key)
        selected[key] = matches[0]
    link = p['gitlink']
    require(any(r.get('path') == link['path'] and r.get('commit') == selected[link['child']]['commit']
                and r.get('root') == selected[link['child']]['name']
                for r in selected[link['parent']].get('submodules', [])),
            'Original ASP.NET-to-SPA Gitlink is required; the publisher repository URL is not rewritten')
    prefixes = {row['name'] + '/': key for key, row in selected.items()}
    indexed, baseline = {}, {key: {} for key in selected}
    with (release / 'sources' / original().portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            name = original().portable(row['path'])
            match = next(((pre, key) for pre, key in prefixes.items() if name.startswith(pre)), None)
            if match is None:
                continue
            pre, key = match
            relative = name[len(pre):]
            require(name not in indexed and row.get('baseline'), 'Unique original literal source baseline required')
            indexed[name] = (key, relative, row)
            baseline[key][relative] = row['baseline']
    for key, rows in baseline.items():
        for child in selected[key].get('submodules', []):
            rows[child['path']] = dict(mode='160000', blob=child['commit'])
        require(P.baseline_tree(rows) == p['sources'][key]['tree'], 'Complete original literal Git tree differs')
    seen, bodies = set(), {key: {} for key in selected}
    attribute_proof, representations = None, {}
    with tarfile.open(release / 'sources' / original().portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed:
                continue
            key, name, row = indexed[entry.name]
            require(entry.name not in seen and (entry.isfile() or entry.issym()) and entry.size <= 32 * 1024**2,
                    'Unique bounded original literal source file required')
            if entry.issym():
                require(row['baseline']['mode'] == '120000' and not entry.linkname.startswith('/')
                        and posixpath.normpath(posixpath.join(posixpath.dirname(entry.name), entry.linkname)).startswith(selected[key]['name'] + '/'),
                        'Original literal source symlink must remain inside its Git root')
                raw = entry.linkname.encode()
            else:
                require(row['mode'] == row['baseline']['mode'] and row['mode'] in ('100644', '100755')
                        and (entry.mode & 0o7777) == (0o755 if row['mode'] == '100755' else 0o644),
                        'Original literal source file mode differs')
                raw = archive.extractfile(entry).read()
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            require(fingerprint(raw) == {k: row[k] for k in FP}, 'Original SDK6 literal source fingerprint differs')
            pristine = P.pristine_blob(row, blob, raw if name.lower().endswith(('.cmd', '.bat')) else None)
            if not pristine:
                require(_checkout(selected[key], key, name, row, entry, raw, closed), 'Original SDK6 literal source was changed')
                representations[name] = dict(fingerprint=fingerprint(raw), rawGitBlob=blob,
                    canonicalGitBlob=row['baseline']['blob'], mode=row['mode'])
            if key == closed['sourceKey'] and name == closed['attribute']['path']:
                attribute_proof = _attribute(selected[key], key, name, row, entry, raw, closed)
            anchor = p['sources'][key]['files'].get(name)
            if anchor:
                require(fingerprint(raw) == {k: anchor[k] for k in FP} and row['baseline']['blob'] == anchor['gitBlob'],
                        'Closed original literal source anchor differs')
                bodies[key][name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys() and all(bodies[k].keys() == p['sources'][k]['files'].keys() for k in selected),
            'Complete original literal source and anchor coverage required')
    proof = dict(kind='sdk6-closed-original-publisher-checkout-representations', policySha256=CHECKOUT_POLICY_SHA,
        sourceCommit=closed['commit'], sourceTree=closed['tree'], attribute=_finish_attribute(attribute_proof),
        acceptedRepresentations=representations, completeOriginalSourceFiles=len(seen), originalSourceAnchors=sum(len(v) for v in bodies.values()),
        sourceFilesRewritten=False, genericEolAcceptanceAllowed=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
    return selected, bodies, proof


def validate(release, manifest, packages_by_sha):
    old, p = original(), policy()
    release = Path(release)
    require(manifest['sdkVersion'] == '6.0.136', 'SDK6-only literal source delivery required')
    roots, bodies, checkouts = _sources(release, manifest)
    old._source_contract(bodies)
    products = {}
    literals = 0
    for sha, expected in p['packages'].items():
        require(sha in packages_by_sha, 'All four exact literal packages must be retained')
        raw = old._package(packages_by_sha[sha], sha)
        key = expected['sourceKey']
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name, rule in expected['literalMembers'].items():
                rendered = old._literal(bodies[key][rule['source']], rule)
                require(rendered == archive.read(name) and fingerprint(rendered) == {k: rule[k] for k in FP},
                        'Original literal template/manifest source does not produce its package bytes')
                literals += 1
            if key in ('packaging', 'emsdk'):
                for name in (('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT') if key == 'packaging' else ('LICENSE',)):
                    require(archive.read(name).replace(b'\r\n', b'\n') == bodies[key][name].replace(b'\r\n', b'\n'),
                            'Original embedded and corresponding source license text differs')
            for name, row in p['products'].items():
                if row['packageSha256'] != sha:
                    continue
                data = raw if row['member'] is None else archive.read(row['member'])
                require(old.declared_product(name, sha, row['member'], data), 'Exact original SDK6 layout product bytes differ')
                products[name] = dict(row, sourceRoot=roots[key]['name'])
    require(len(products) == 128 and literals == 387, 'Complete128-layout/387-literal source coverage required')
    return dict(kind='sdk6-original-literal-input-source-chains', products=products,
        literalSourceMembers=literals, originalReferenceApiSources=83, publisherCheckoutRepresentations=checkouts,
        sourceCompileEqualityClaimed=False, templateExecutionQualified=False, emscriptenWorkloadQualified=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
