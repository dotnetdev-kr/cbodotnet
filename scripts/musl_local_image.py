"""Bind a local Docker/Podman image ID to a usable Dockerfile FROM reference."""
import json
import re

from downstream_release import require


def bind_parent(producer, image_id, role):
    # Dockerfile FROM treats sha256:<id> as a repository:tag and may pull it.
    # A unique local tag is resolvable by the default Docker builder. Keep all
    # execution and evidence bound to the original immutable image ID.
    require(isinstance(image_id, str) and re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', image_id),
            'An inspected immutable local parent image ID is required')
    require(re.fullmatch(r'[a-z][a-z0-9-]*', role)
            and re.fullmatch(r'[1-9][0-9]*', producer.args.run_id)
            and producer.args.arch in {'x64', 'aarch64'}, 'A unique local parent image role/run/CPU is required')
    tag = ('localhost/cbodotnet-musl-parent:' + producer.args.run_id + '-' + producer.args.arch
           + '-' + role + '-' + image_id.removeprefix('sha256:')[:16])
    def inspect(reference):
        rows = json.loads(producer.run(producer.engine + ['image', 'inspect', reference], capture=True))
        require(isinstance(rows, list) and len(rows) == 1 and rows[0]['Id'] == image_id
                and rows[0]['Architecture'] == producer.id['image'] and rows[0]['Os'] == 'linux',
                'Local parent tag must retain the exact inspected immutable native Linux image')
    inspect(image_id)
    producer.run(producer.engine + ['image', 'tag', image_id, tag])
    inspect(tag)
    return tag
