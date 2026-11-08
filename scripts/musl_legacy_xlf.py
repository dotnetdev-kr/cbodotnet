"""Convert bounded original VSTest XLF string data into compiler input RESX.

This preserves every original translation target. It loads no assemblies and
does not invent translations or substitute an English fallback.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

CULTURES = {'cs', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'pl', 'pt-BR', 'ru', 'tr', 'zh-Hans', 'zh-Hant'}
NS = {'x': 'urn:oasis:names:tc:xliff:document:1.2'}


def require(value, message):
    if not value: raise ValueError(message)


def xml(path):
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
            'An ordinary original resource source file is required')
    raw = path.read_bytes()
    require(len(raw) <= 2 * 1024**2, 'A bounded original resource source file is required')
    text = raw.decode('utf-8-sig')
    require('<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper(),
            'Resource XML may not declare document types or entities')
    return raw, ET.fromstring(text)


def generate(source, receipt, source_commit):
    source, receipt = Path(source), Path(receipt)
    require(re.fullmatch('[a-f0-9]{40}', source_commit), 'A declared original source commit is required')
    require(not receipt.exists(), 'A fresh original-resource generation receipt is required')
    rows = []
    for xlf in sorted((source / 'src').rglob('*.xlf')):
        culture = xlf.stem.rsplit('.', 1)[-1]
        if culture not in CULTURES: continue
        require(len(rows) < 10000 and xlf.parent.name == 'xlf', 'Unexpected original translation source layout')
        raw, document = xml(xlf)
        files = document.findall('x:file', NS)
        require(len(files) == 1 and files[0].get('target-language', '').lower() == culture.lower(),
                'The original XLF target language differs from its file name')
        neutral = xlf.parent.parent / (xlf.name.removesuffix('.' + culture + '.xlf') + '.resx')
        neutral_raw, original = xml(neutral)
        require(original.tag == 'root', 'An original RESX root is required')
        base_values = {}
        for item in original.findall('data'):
            value = item.find('value'); key = item.get('name')
            require(key and key not in base_values and item.get('type') is None
                    and value is not None and len(value) == 0, 'Only original unique plain-string RESX values are supported')
            base_values[key] = value.text or ''
        target = ET.Element('root')
        for child in original:
            if child.tag != 'data': target.append(copy.deepcopy(child))
        ids, values, differing_source, obsolete = set(), [], [], []
        for unit in files[0].findall('.//x:trans-unit', NS):
            key = unit.get('id'); translated = unit.find('x:target', NS); english = unit.find('x:source', NS)
            require(key and len(key) <= 4096 and key not in ids and len(ids) < 100000,
                    'Unique bounded original XLF string identifiers are required')
            ids.add(key)
            require(translated is not None and len(translated) == 0, 'Plain original translation target data is required')
            value = translated.text or ''
            require(value or english is not None and not (english.text or ''), 'An original translation target is empty')
            if key not in base_values: obsolete.append(key)
            elif english is not None and (english.text or '') != base_values[key]: differing_source.append(key)
            item = ET.SubElement(target, 'data', {'name': key, '{http://www.w3.org/XML/1998/namespace}space': 'preserve'})
            ET.SubElement(item, 'value').text = value
            values.append(dict(key=key, value=value, state=translated.get('state')))
        require(values, 'Original translated string values are required')
        destination = neutral.with_name(neutral.stem + '.' + culture + '.resx')
        require(not destination.exists(), 'Refusing to replace an existing translated compiler source')
        ET.indent(target, space='  ')
        data = ET.tostring(target, encoding='utf-8', xml_declaration=True)
        parsed = {item.attrib['name']: item.find('value').text or '' for item in ET.fromstring(data).findall('data')}
        require(parsed == {item['key']: item['value'] for item in values}, 'Generated RESX changed original translation values')
        destination.write_bytes(data)
        rows.append(dict(culture=culture, xlf=xlf.relative_to(source).as_posix(),
            xlfSha256=hashlib.sha256(raw).hexdigest(), neutral=neutral.relative_to(source).as_posix(),
            neutralSha256=hashlib.sha256(neutral_raw).hexdigest(), generated=destination.relative_to(source).as_posix(),
            generatedSha256=hashlib.sha256(data).hexdigest(), targetCount=len(values), obsoleteOriginalXlfIds=obsolete,
            upstreamEnglishSourceDifferences=differing_source,
            originalTargetDataSha256=hashlib.sha256(json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()))
    require({row['culture'] for row in rows} == CULTURES, 'All thirteen original resource cultures are required')
    result = dict(schemaVersion=1, sourceCommit=source_commit, generatedFromOriginalTargetsOnly=True,
        translatedTextEdited=False, englishFallbackGenerated=False, compiledResourceAssembliesImported=False,
        originalNeutralHeadersPreserved=True, cultures=sorted(CULTURES), rows=rows, qualificationAllowed=False)
    with receipt.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    return result
