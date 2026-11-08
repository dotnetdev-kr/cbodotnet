#!/usr/bin/env python3
"""Generate Core3 VSTest localized RESX from its exact original XLF targets.

No satellite assembly or translated string is imported from a binary package.
This bounded source-data conversion does not qualify VSTest or an SDK product.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import xml.etree.ElementTree as ET

from core3_musl_restore_inputs import ordinary, require, write_new

COMMIT = 'c1b6b2c1ab4c8f181f3cb1a436afb6428009c7ab'
SOURCE_SHA256 = '5d43f9285b8a5d46fcd60c744599d4df4bca13ab68408865f30e4a5e159d8f0b'
SOURCE_BYTES = 1910641
CULTURES = {'cs', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'pl', 'pt-BR', 'ru', 'tr', 'zh-Hans', 'zh-Hant'}
NS = {'x': 'urn:oasis:names:tc:xliff:document:1.2'}


def xml(raw):
    require(len(raw) < 2 * 1024 * 1024 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),
            'bounded source XML without DTD/entities is required')
    return ET.fromstring(raw)


def generate(source, source_archive, receipt):
    source, source_archive, receipt = ordinary(source), ordinary(source_archive), ordinary(receipt)
    raw_archive = source_archive.read_bytes()
    require(len(raw_archive) == SOURCE_BYTES and hashlib.sha256(raw_archive).hexdigest() == SOURCE_SHA256,
            'the exact original VSTest source archive is required')
    with tarfile.open(source_archive) as archive:
        originals = {}
        for member in archive:
            if not member.isfile():
                continue
            relative = PurePosixPath(*PurePosixPath(member.name).parts[1:])
            require(not relative.is_absolute() and '..' not in relative.parts, 'invalid original source path')
            if str(relative).startswith('src/') and relative.suffix in ['.xlf', '.resx']:
                require(str(relative) not in originals, 'duplicate original source-data path')
                originals[str(relative)] = archive.extractfile(member).read()
    original_xlfs = sorted(name for name in originals if name.endswith('.xlf'))
    require(len(original_xlfs) == 252, 'the complete252 original XLF files are required')
    xlfs = [name for name in original_xlfs if PurePosixPath(name).stem.rsplit('.', 1)[-1] in CULTURES]
    require(len(xlfs) == 234, 'all234 original XLF source files are required')
    actual = sorted(path.relative_to(source).as_posix() for path in (source / 'src').rglob('*.xlf'))
    require(actual == original_xlfs, 'the source worktree XLF set differs from the original archive')
    for name in original_xlfs:
        require(ordinary(source / name).read_bytes() == originals[name],
                'an original localized or neutral XLF differs')
    rows = []
    for name in xlfs:
        path = source / name
        require(not path.is_symlink() and path.read_bytes() == originals[name], 'an original XLF differs')
        culture = path.stem.rsplit('.', 1)[-1]
        require(culture in CULTURES and path.parent.name == 'xlf', 'an unreviewed source culture/layout was found')
        raw = originals[name]
        document = xml(raw)
        files = document.findall('x:file', NS)
        require(len(files) == 1 and files[0].attrib['target-language'].lower() == culture.lower(),
                'an XLF target-language differs from its declared source culture')
        neutral = path.parent.parent / (path.name.removesuffix('.' + culture + '.xlf') + '.resx')
        ordinary(neutral)
        neutral_name = neutral.relative_to(source).as_posix()
        neutral_raw = originals.get(neutral_name)
        require(neutral_raw is not None and not neutral.is_symlink() and neutral.read_bytes() == neutral_raw,
                'the original neutral RESX differs')
        original = xml(neutral_raw)
        base_values = {item.attrib['name']: item.find('value').text for item in original.findall('data')}
        target = ET.Element('root')
        for child in original:
            if child.tag != 'data':
                target.append(copy.deepcopy(child))
        ids, values, differences, obsolete = set(), [], [], []
        for unit in files[0].findall('.//x:trans-unit', NS):
            key = unit.attrib['id']
            require(key not in ids, 'duplicate original XLF translation identifier')
            ids.add(key)
            translated, english = unit.find('x:target', NS), unit.find('x:source', NS)
            require(translated is not None and len(translated) == 0, 'a literal original translation target is required')
            value = translated.text or ''
            require(value or english is not None and not (english.text or ''), 'an original translation is empty')
            if key not in base_values:
                obsolete.append(key)
            elif english is not None and (english.text or '') != (base_values[key] or ''):
                differences.append(key)
            item = ET.SubElement(target, 'data', {'name': key, '{http://www.w3.org/XML/1998/namespace}space': 'preserve'})
            ET.SubElement(item, 'value').text = value
            values.append(dict(key=key, value=value, state=translated.attrib.get('state')))
        require(values, 'an original XLF has no translation targets')
        destination = neutral.with_name(neutral.stem + '.' + culture + '.resx')
        require(not destination.exists(), 'a generated RESX would overwrite an existing source file')
        ET.indent(target, space='  ')
        generated = ET.tostring(target, encoding='utf-8', xml_declaration=True)
        round_trip = {item.attrib['name']: item.find('value').text or '' for item in ET.fromstring(generated).findall('data')}
        require(round_trip == {item['key']: item['value'] for item in values}, 'literal source translations did not round-trip')
        write_new(destination, generated)
        rows.append(dict(culture=culture, xlf=name, xlfSha256=hashlib.sha256(raw).hexdigest(),
            neutral=neutral_name, neutralSha256=hashlib.sha256(neutral_raw).hexdigest(),
            generated=destination.relative_to(source).as_posix(), generatedSha256=hashlib.sha256(generated).hexdigest(),
            targetCount=len(values), obsoleteOriginalXlfIds=obsolete, upstreamEnglishSourceDifferences=differences,
            originalTargetDataSha256=hashlib.sha256(json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()))
    require({row['culture'] for row in rows} == CULTURES, 'the complete13culture set is required')
    result = dict(qualification=False, releaseAdmission=False, sourceSdkProduct=False,
        sourceCommit=COMMIT, sourceArchive=dict(bytes=len(raw_archive), sha256=SOURCE_SHA256),
        generatedFromOriginalTargetsOnly=True, translatedTextEdited=False, englishFallbackGenerated=False,
        originalNeutralXlfFilesPreserved=18,
        compiledResourceAssembliesImported=False, originalNeutralHeadersPreserved=True,
        cultures=sorted(CULTURES), rows=rows)
    write_new(receipt, (json.dumps(result, indent=2) + '\n').encode())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.source_dir, args.source_archive, args.receipt)
    print(json.dumps(dict(cultures=len(result['cultures']), files=len(result['rows']),
                          targets=sum(row['targetCount'] for row in result['rows']), qualification=False)))
