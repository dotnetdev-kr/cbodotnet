"""Build a concise scorecard only from authenticated release and delivery feeds."""
import html
import json
from pathlib import Path


STATUSES = ('passed', 'pending', 'unsupported', 'failed')
ARCHITECTURES = ('x64', 'aarch64')
MUSL_CHANNELS = ('archive', 'apk', 'oci')
ROOT = Path(__file__).resolve().parents[1]
MARKER = '<!-- QUALIFICATION_SCORECARD -->'


def _status(value, *, candidate=False):
    if value in ('failed', 'failure'):
        return 'failed'
    if candidate or value in ('pending', 'not-published', 'deferred', 'in-progress'):
        return 'pending'
    if value in ('passed', 'published', 'published-postverified', 'published-public-bytes-verified'):
        return 'passed'
    if value in ('unsupported', 'not-qualified') or value is None:
        return 'unsupported'
    raise ValueError('Unknown qualification cell state: ' + str(value))


def build(catalog, archive_rows, downstream_policy, downstream_status, musl_feed, musl_qualification):
    """Derive cells from validated site inputs; absence never implies failure."""
    glibc = {row['sdkVersion']: row for row in catalog['releases']}
    archives = {(row['sdkVersion'], row['architecture']): row for row in archive_rows}
    distributions = {}
    for channel, data in downstream_status.get('channels', {}).items():
        for row in data.get('publications', []):
            key = (row['sdkVersion'], channel, row['variant'], row['architecture'])
            previous = distributions.get(key)
            revision = row.get('packageRevision')
            if type(revision) is not int or revision <= 0:
                raise ValueError('A positive package revision is required for a published scorecard cell')
            if previous is None or revision > previous['packageRevision']:
                distributions[key] = row
            elif revision == previous['packageRevision']:
                raise ValueError('Duplicate published scorecard revision: ' + str(key))
    musl = {}
    for row in musl_feed.get('publications', []):
        identity = row['identity']
        for record in row['records']:
            key = (identity['sdkVersion'], identity['channel'], record['architecture'])
            if key in musl:
                raise ValueError('Duplicate published musl scorecard cell: ' + str(key))
            musl[key] = (row, record)
    musl_qualified = {row['sdkVersion']: row for row in musl_qualification.get('builds', [])}
    versions = set(glibc) | {row['sdkVersion'] for row in archive_rows}
    versions.update(row['sdkVersion'] for rows in downstream_status.get('channels', {}).values()
                    for row in rows.get('publications', []))
    versions.update(row['identity']['sdkVersion'] for row in musl_feed.get('publications', []))
    versions.update(musl_qualified)
    releases = []

    for version in sorted(versions, key=lambda value: tuple(map(int, value.split('.'))), reverse=True):
        release = glibc.get(version)
        source_identity = {}
        cells = []
        if release:
            for architecture in ARCHITECTURES:
                entry = release['architectures'][architecture]
                source_identity[architecture] = dict(targetRid=entry['provenance']['targetRid'],
                    projectCommit=entry['provenance']['projectCommit'], sourceUrl=entry['source']['url'],
                    sourceSha256=entry['source']['sha256'], evidenceUrl=entry['evidence']['url'],
                    evidenceSha256=entry['evidence']['sha256'])
        for architecture in ARCHITECTURES:
            archive = archives.get((version, architecture))
            cells.append(dict(libc='glibc', channel='archive', architecture=architecture,
                target=', '.join(archive.get('userSpaces', [])) if archive else 'native archive consumer',
                status=_status('published-postverified' if archive else 'pending' if release else None),
                sourceManifestSha256=(release['architectures'][architecture]['source']['sha256']
                    if release else None),
                signingFingerprint=archive.get('signingFingerprint') if archive else None,
                evidence=([dict(label='Archive', url=archive['archiveUrl']),
                    dict(label='Signed consumer manifest', url=archive['manifestUrl']),
                    dict(label='Signature', url=archive['signatureUrl'])] if archive else [])))

        for channel, configuration in downstream_policy.get('channels', {}).items():
            candidates = configuration.get('candidateMatrix', [])
            for candidate in candidates:
                architecture, variant = candidate['architecture'], candidate['variant']
                row = distributions.get((version, channel, variant, architecture))
                status = _status(row.get('status')) if row else _status(configuration.get('status'), candidate=True)
                if row:
                    evidence = [dict(label='Artifact', url=row['artifactUrl']),
                        dict(label='Signed manifest', url=row['manifestUrl']),
                        dict(label='Signature', url=row['signatureUrl']),
                        dict(label='Native verification', url=row['verificationReportUrl'])]
                    source_sha = row.get('sourceManifestSha256')
                    signer = row.get('signingFingerprint')
                else:
                    evidence, source_sha, signer = [], None, None
                cells.append(dict(libc='glibc', channel=channel, architecture=architecture, target=variant,
                    status=status, packageRevision=row.get('packageRevision') if row else None,
                    sourceManifestSha256=source_sha, signingFingerprint=signer, evidence=evidence))
            if channel == 'aur' and 'aarch64' not in {row['architecture'] for row in candidates}:
                cells.append(dict(libc='glibc', channel=channel, architecture='aarch64', target='arch-rolling',
                    status='unsupported', sourceManifestSha256=None, signingFingerprint=None, evidence=[]))

        for channel in MUSL_CHANNELS:
            for architecture in ARCHITECTURES:
                published = musl.get((version, channel, architecture))
                if published:
                    row, record = published
                    evidence = [dict(label='Signed manifest', url=row['manifestUrl']),
                        dict(label='Signature', url=row['signatureUrl']),
                        dict(label='Public verification', url=row['verification']['manifestUrl'])]
                    status = 'passed'
                    source_sha = row['identity']['sourceManifestSha256']
                    signer = row['signingFingerprint']
                else:
                    evidence, source_sha, signer = [], None, None
                    status = 'pending' if version in musl_qualified else 'unsupported'
                cells.append(dict(libc='musl', channel=channel, architecture=architecture,
                    target='Alpine 3.24.4', status=status, sourceManifestSha256=source_sha,
                    sourceReleaseTag=(musl_qualified.get(version, {}).get('sourceReleaseTag')
                        if version in musl_qualified else None), signingFingerprint=signer, evidence=evidence))

        counts = {status: sum(cell['status'] == status for cell in cells) for status in STATUSES}
        releases.append(dict(sdkVersion=version, sdkQualification='passed' if release else 'pending',
            glibcSourceIdentity=source_identity,
            muslSourceIdentity=({'sourceReleaseTag': musl_qualified[version].get('sourceReleaseTag'),
                'sourceManifestSha256': musl_qualified[version].get('sourceManifestSha256')}
                if version in musl_qualified else None), counts=counts, cells=cells))

    planned = []
    for channel, configuration in downstream_policy.get('channels', {}).items():
        for candidate in configuration.get('candidateMatrix', []):
            if channel == 'aur' and candidate['architecture'] == 'x64':
                planned.append(dict(libc='glibc', channel=channel, architecture='aarch64',
                    target=candidate['variant'], status='unsupported'))
        if not configuration.get('candidateMatrix'):
            planned.append(dict(libc='glibc', channel=channel, architecture='*', target='*',
                status=_status(configuration.get('status'))))
    return dict(schemaVersion=1, kind='release-qualification-scorecard', repository=catalog['repository'],
        generatedAt=catalog['generatedAt'], installerAdmission='separate',
        installerStatusUrl='https://github.com/' + catalog['repository']
            + '/blob/main/releases/cbodotnetup-status.json', statuses=dict(passed='Authenticated qualification or public post-verification',
            pending='A selected candidate has no completed public receipt',
            unsupported='No qualification or candidate is recorded for this cell',
            failed='An authoritative input explicitly records failure; absence is never treated as failure'),
        releases=releases, plannedCells=planned,
        sourceFeeds=['releases.json', 'downstream-status.json', 'musl-status.json'])


def render(scorecard):
    escape = html.escape
    sections = []
    for release in scorecard['releases']:
        rows = []
        for cell in release['cells']:
            evidence = ' '.join('<a href="' + escape(item['url'], quote=True) + '">' + escape(item['label']) + '</a>'
                for item in cell['evidence'])
            rows.append('<tr><td>' + escape(cell['libc']) + '</td><td>' + escape(cell['channel']) + '</td><td>'
                + escape(cell['architecture']) + '</td><td>' + escape(cell['target']) + '</td><td><span class="score-status score-'
                + escape(cell['status']) + '">' + escape(cell['status']) + '</span></td><td>' + evidence + '</td></tr>')
        identity = []
        for architecture, source in release['glibcSourceIdentity'].items():
            identity.append('<p><strong>' + escape(architecture) + '</strong> <code>'
                + escape(source['projectCommit']) + '</code> · source SHA-256 <code>'
                + escape(source['sourceSha256']) + '</code> · '
                + '<a href="' + escape(source['sourceUrl'], quote=True) + '">source</a> · '
                + '<a href="' + escape(source['evidenceUrl'], quote=True) + '">evidence</a></p>')
        musl_source = release['muslSourceIdentity']
        if musl_source:
            identity.append('<p><strong>musl source</strong> <a href="https://github.com/'
                + escape(scorecard['repository'], quote=True) + '/releases/tag/'
                + escape(musl_source['sourceReleaseTag'], quote=True) + '">'
                + escape(musl_source['sourceReleaseTag']) + '</a> · source manifest SHA-256 <code>'
                + escape(musl_source['sourceManifestSha256']) + '</code></p>')
        counts = ' · '.join(status + ' ' + str(count) for status, count in release['counts'].items())
        sections.append('<details class="score-release"><summary>SDK ' + escape(release['sdkVersion'])
            + ' · glibc qualification ' + escape(release['sdkQualification']) + ' · ' + escape(counts)
            + '</summary><div class="score-content">' + ''.join(identity)
            + '<div class="score-table"><table><thead><tr><th>libc</th><th>channel</th><th>CPU</th><th>qualified target</th>'
            + '<th>state</th><th>evidence</th></tr></thead><tbody>' + ''.join(rows)
            + '</tbody></table></div></div></details>')
    if not sections:
        sections.append('<p class="empty-state">No authenticated release records are available.</p>')
    return ('<section id="qualification-scorecard" class="panel" aria-labelledby="scorecard-title">'
        '<div class="section-heading"><p class="eyebrow">Evidence, not a certification</p>'
        '<h2 id="scorecard-title">Release qualification scorecard</h2></div>'
        '<p class="section-description">Passed cells require an authenticated release or signed post-verification receipt. '
        'Pending means a selected candidate has no completed receipt; unsupported means no target qualification is recorded. '
        'A missing record is never labeled failed. SDK qualification is separate from cbodotnetup admission and upstream support. '
        '<a href="qualification-scorecard.json">Machine-readable scorecard</a> · '
        '<a href="' + escape(scorecard['installerStatusUrl'], quote=True) + '">installer admission status</a>.</p>'
        + ''.join(sections) + '</section>')


def publish(output_dir):
    """Finalize the scorecard from feeds already validated by the Pages build."""
    output = Path(output_dir).absolute()
    if not output.is_dir() or output.is_symlink():
        raise ValueError('An ordinary completed Pages output directory is required')
    index = output / 'index.html'
    if not index.is_file() or index.is_symlink():
        raise ValueError('An ordinary generated Pages index is required')
    document = index.read_text(encoding='utf-8')
    if document.count(MARKER) != 1:
        raise ValueError('The generated Pages index must contain exactly one scorecard marker')

    def load(name):
        path = output / name
        if not path.is_file() or path.is_symlink():
            raise ValueError('A completed Pages feed is required: ' + name)
        return json.loads(path.read_bytes())

    policy_path = ROOT / 'releases/downstream-status.json'
    musl_qualification_path = ROOT / 'releases/qualified-musl-builds.json'
    policy = json.loads(policy_path.read_bytes())
    musl_qualification = json.loads(musl_qualification_path.read_bytes())
    scorecard = build(load('releases.json'), load('archive-status.json')['archives'], policy,
        load('downstream-status.json'), load('musl-status.json'), musl_qualification)
    index.write_text(document.replace(MARKER, render(scorecard)), encoding='utf-8')
    scorecard_path = output / 'qualification-scorecard.json'
    if scorecard_path.exists() or scorecard_path.is_symlink():
        raise ValueError('A fresh scorecard output is required')
    scorecard_path.write_text(json.dumps(scorecard, indent=2) + '\n', encoding='utf-8')
    return scorecard