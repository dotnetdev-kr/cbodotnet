"""Download one complete, pinned HTTPS input with retained attempt evidence."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

FP = ('bytes', 'sha256', 'sha512')
HEADERS = ('Content-Length', 'Content-Range', 'Content-Encoding', 'Content-Type',
           'ETag', 'Last-Modified', 'Date', 'Accept-Ranges', 'Via', 'X-Cache', 'X-Ms-Request-Id')


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary pinned-download path required')
    return path


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def download_pinned(expected, destination, reports, *, opener=None, sleep=None):
    """Expose the final file only after HTTP and all three fingerprints match.

    Failed response bytes are never used as inputs. Their observed fingerprints
    and HTTP metadata remain in the reports; temporary payloads are removed.
    """
    url = urlsplit(expected.get('url', ''))
    require(set(expected) == {'url', *FP} and type(expected['bytes']) is int and expected['bytes'] > 0
            and re.fullmatch('[a-f0-9]{64}', expected['sha256'])
            and re.fullmatch('[a-f0-9]{128}', expected['sha512'])
            and url.scheme == 'https' and url.netloc and not url.username and not url.password
            and not url.query and not url.fragment, 'Complete static HTTPS input pin required')
    destination, reports = ordinary(destination), ordinary(reports)
    require(destination.parent.is_dir() and not destination.exists() and not reports.exists(),
            'Fresh pinned-download input and report directory required')
    reports.mkdir(parents=True)
    opener, sleep = opener or urllib.request.urlopen, sleep or time.sleep
    attempts = []
    for attempt in range(1, 4):
        partial = destination.with_name(destination.name + '.attempt-' + str(attempt) + '.part')
        require(not partial.exists(), 'Fresh private pinned-download attempt required')
        started = datetime.now(timezone.utc).isoformat()
        hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
        observed = 0
        status = None
        headers = {}
        final_url = None
        complete = False
        error_type = None
        problem = None
        accepted = False
        try:
            request = urllib.request.Request(expected['url'], headers={
                'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache'})
            try:
                incoming = opener(request, timeout=120)
            except urllib.error.HTTPError as error:
                incoming = error
            with incoming, partial.open('xb') as target:
                status = incoming.getcode()
                headers = {name: incoming.headers.get(name) for name in HEADERS if incoming.headers.get(name) is not None}
                location = urlsplit(incoming.geturl())
                final_url = location._replace(query='', fragment='').geturl()
                while observed <= expected['bytes']:
                    block = incoming.read(min(1024 * 1024, expected['bytes'] + 1 - observed))
                    if not block:
                        complete = True
                        break
                    target.write(block)
                    observed += len(block)
                    for digest in hashes.values():
                        digest.update(block)
            actual = dict(bytes=observed, **{name: digest.hexdigest() for name, digest in hashes.items()})
            length = headers.get('Content-Length')
            require(status == 200 and not headers.get('Content-Range')
                    and headers.get('Content-Encoding', 'identity').lower() == 'identity'
                    and (length is None or (length.isdecimal() and int(length) == expected['bytes'])),
                    'Full HTTP 200 response with consistent length and no range/encoding is required')
            require(complete and actual == {name: expected[name] for name in FP},
                    'Complete pinned input size, SHA256 and SHA512 must all match')
            # Creating a hard link fails if another file unexpectedly acquired
            # the destination name; an existing input is never overwritten.
            os.link(partial, destination)
            accepted = True
        except Exception as error:
            error_type = type(error).__name__
            problem = str(error)[:1000]
        actual = dict(bytes=observed, **{name: digest.hexdigest() for name, digest in hashes.items()})
        row = dict(attempt=attempt, requestedUrl=expected['url'], responseUrl=final_url,
                   startedAtUtc=started, completedAtUtc=datetime.now(timezone.utc).isoformat(),
                   httpStatus=status, responseHeaders=headers, observedFingerprint=actual,
                   responseBodyCompletelyRead=complete, accepted=accepted,
                   errorType=error_type, error=problem, failedPayloadRetained=False)
        write(reports / ('attempt-' + str(attempt) + '.json'), row)
        attempts.append(row)
        if partial.exists():
            partial.unlink()
        if accepted:
            write(reports / 'download.json', dict(schemaVersion=1, status='passed', expected=expected,
                attempts=attempts, canonicalUrlUnchanged=True, maximumAttempts=3))
            return dict(expected)
        if attempt < 3:
            sleep(attempt)
    write(reports / 'download.json', dict(schemaVersion=1, status='failed', expected=expected,
        attempts=attempts, canonicalUrlUnchanged=True, maximumAttempts=3))
    raise ValueError('Pinned HTTPS input failed after 3 recorded attempts; no input was admitted')
