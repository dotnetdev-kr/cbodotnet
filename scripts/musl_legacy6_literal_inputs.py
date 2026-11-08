"""Closed original SDK6 reference, manifest and template source chains.

This module authenticates four unchanged publisher packages. It does not claim
that their assemblies were rebuilt or that templates/workloads were qualified.
"""
from functools import lru_cache
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import tarfile
import zipfile

POLICY_SHA = '95d7d18006735ae27abebb5454031efb19d66ad117ec8953b56e7740153a7980'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def portable(name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and name and not path.is_absolute() and '\\' not in name
            and ':' not in name and all(p not in ('', '.', '..') for p in name.split('/')),
            'Ordinary relative SDK6 literal path required')
    return name


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@lru_cache(maxsize=1)
def policy():
    raw = Path(__file__).with_name('musl-legacy6-literal-inputs.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Closed SDK6 literal policy bytes differ')
    value = json.loads(raw)
    require(value['schemaVersion'] == 1 and value['sdkVersion'] == '6.0.136'
            and len(value['packages']) == 4 and len(value['products']) == 128
            and len(value['sources']) == 6 and value['sourceCompileEqualityClaimed'] is False
            and value['templateExecutionQualified'] is value['emscriptenWorkloadQualified'] is False,
            'Isolated original SDK6 literal policy required')
    return value


def _package(path, sha):
    expected = policy()['packages'].get(sha)
    require(expected is not None, 'Unreviewed SDK6 literal package')
    raw = Path(path).read_bytes()
    require(len(raw) <= 4 * 1024**2 and fingerprint(raw) == {key: expected[key] for key in FP},
            'Exact original SDK6 literal package bytes required')
    X = module('sdk6_literal_xml', 'musl_legacy_msbuild_resources.py')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) == expected['members'], 'Original unique SDK6 package members required')
        for name in names:
            portable(name)
        spec = expected['nuspec']
        data = archive.read(spec['member'])
        require(fingerprint(data) == {key: spec[key] for key in FP}, 'Original publisher nuspec bytes differ')
        metadata = X.xml(data).find('{*}metadata')
        repository = metadata.find('{*}repository')
        license_node = metadata.find('{*}license')
        actual_license = None if license_node is None else dict(type=license_node.get('type'), text=license_node.text)
        require(metadata.findtext('{*}id') == expected['id'] and metadata.findtext('{*}version') == expected['version']
                and (None if repository is None else dict(repository.attrib)) == expected['repository']
                and actual_license == expected['license'] and metadata.findtext('{*}licenseUrl') == expected['licenseUrl'],
                'Original SDK6 package identity, repository and license must remain unchanged')
    return raw


def package_origin(path, sha):
    """Return only the four exact imported source identities; never infer one."""
    if sha not in policy()['packages']:
        return None
    _package(path, sha)
    row = policy()['packages'][sha]
    return dict(sourceCommit=row['sourceCommit'], sourceBasis=row['sourceBasis'])


def declared_product(name, sha, member, data):
    row = policy()['products'].get(name)
    return bool(row and row['packageSha256'] == sha and row['member'] == member
                and row['fingerprint'] == fingerprint(data))


def _sources(release, manifest):
    p = policy()
    P = module('sdk6_literal_source_archive_primitives', 'package-used-source.py')
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
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            name = portable(row['path'])
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
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
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
            require(fingerprint(raw) == {k: row[k] for k in FP}
                    and P.pristine_blob(row, blob, raw if name.lower().endswith(('.cmd', '.bat')) else None),
                    'Original SDK6 literal source was changed')
            anchor = p['sources'][key]['files'].get(name)
            if anchor:
                require(fingerprint(raw) == {k: anchor[k] for k in FP} and row['baseline']['blob'] == anchor['gitBlob'],
                        'Closed original literal source anchor differs')
                bodies[key][name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys() and all(bodies[k].keys() == p['sources'][k]['files'].keys() for k in selected),
            'Complete original literal source and anchor coverage required')
    return selected, bodies


def _source_contract(bodies):
    X = module('sdk6_literal_contract_xml', 'musl_legacy_msbuild_resources.py')
    details = X.xml(bodies['packaging']['eng/Version.Details.xml'])
    refs = [n for n in details.iter('Dependency') if n.get('Name') == 'NETStandard.Library']
    require(len(refs) == 1 and refs[0].get('Version') == '2.1.0'
            and refs[0].findtext('Uri') == 'https://github.com/dotnet/standard'
            and refs[0].findtext('Sha') == policy()['sources']['api']['commit'],
            'Original reference packaging-to-API dependency differs')
    project = X.xml(bodies['api']['src/netstandard/ref/netstandard.csproj'])
    names = [n.get('Include') for n in project.iter('Compile')]
    require(len(names) == len(set(names)) == 83 and all(isinstance(n, str) and not any(c in n for c in '*?;') for n in names),
            'All83 original explicit C# reference API declarations required')
    for name in names:
        path = posixpath.normpath('src/netstandard/ref/' + name.replace('\\', '/'))
        require(path in bodies['api'], 'Original C# reference API source is absent')
    em = X.xml(bodies['emsdk']['eng/Versions.props'])
    props = {n.tag.rsplit('}', 1)[-1]: (n.text or '').strip() for n in em.iter()}
    require([props.get(k) for k in ('MajorVersion', 'MinorVersion', 'PatchVersion', 'EmscriptenVersion')]
            == ['6', '0', '36', '2.0.23'], 'Original emscripten version declarations differ')
    asp = X.xml(bodies['aspnetcore']['eng/Versions.props'])
    props = {n.tag.rsplit('}', 1)[-1]: (n.text or '').strip() for n in asp.iter()}
    require([props.get(k) for k in ('AspNetCoreMajorVersion', 'AspNetCoreMinorVersion', 'AspNetCorePatchVersion', 'DefaultNetCoreTargetFramework')]
            == ['6', '0', '36', 'net6.0'], 'Original SPA parent version declarations differ')


def _literal(raw, rule):
    for key, value in rule['replacements'].items():
        token = bytes([36, 123]) + key.encode() + b'}'
        require(token in raw, 'Only declared original template placeholders may be rendered')
        raw = raw.replace(token, value.encode())
    if rule['replacements']:
        require(bytes([36, 123]) not in raw, 'An original template placeholder remains unresolved')
    if rule['transform'] == 'lf-to-crlf':
        raw = raw.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    else:
        require(rule['transform'] == 'identity', 'Unreviewed literal byte transformation')
    return raw


def validate(release, manifest, packages_by_sha):
    p = policy()
    release = Path(release)
    require(manifest['sdkVersion'] == '6.0.136', 'SDK6-only literal source delivery required')
    roots, bodies = _sources(release, manifest)
    _source_contract(bodies)
    products = {}
    literals = 0
    for sha, expected in p['packages'].items():
        require(sha in packages_by_sha, 'All four exact literal packages must be retained')
        raw = _package(packages_by_sha[sha], sha)
        key = expected['sourceKey']
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name, rule in expected['literalMembers'].items():
                rendered = _literal(bodies[key][rule['source']], rule)
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
                require(declared_product(name, sha, row['member'], data), 'Exact original SDK6 layout product bytes differ')
                products[name] = dict(row, sourceRoot=roots[key]['name'])
    require(len(products) == 128 and literals == 387, 'Complete128-layout/387-literal source coverage required')
    return dict(kind='sdk6-original-literal-input-source-chains', products=products,
                literalSourceMembers=literals, originalReferenceApiSources=83,
                sourceCompileEqualityClaimed=False, templateExecutionQualified=False, emscriptenWorkloadQualified=False)
