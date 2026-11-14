"""Check Linux flow provenance and node references; optionally check v6.6 source files.

python -B tools/verify_linux_flow.py --source-root /path/to/linux-v6.6
This verifies references and hashes, not runtime grouping or VMware behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def verify(source_root=None):
    data = json.loads((ROOT / 'linux-flow-evidence.json').read_text(encoding='utf-8'))
    files = {f['id']: f for f in data['files']}
    fragments = {f['id']: f for f in data['fragments']}
    assert len(files) == len(data['files']) and len(fragments) == len(data['fragments'])
    verified_sources = 0
    for source in files.values():
        assert source['ref'] == 'v6.6'
        assert source['gitBlobSha1Verified'] is True
        if source_root:
            raw = (Path(source_root) / source['path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == source['sha256'], source['path']
            blob = b'blob ' + str(len(raw)).encode() + b'\0' + raw
            assert hashlib.sha1(blob).hexdigest() == source['gitBlobSha1'], source['path']
            lines = raw.decode('utf-8').splitlines(keepends=True)
            for fragment in fragments.values():
                if fragment['file'] == source['id']:
                    block = ''.join(lines[fragment['startLine'] - 1:fragment['endLine']]).encode()
                    assert hashlib.sha256(block).hexdigest() == fragment['sha256'], fragment['id']
                    assert fragment['function'] in block.decode(), fragment['id']
            verified_sources += 1
    for fragment in fragments.values():
        assert fragment['file'] in files
        assert 0 < fragment['startLine'] <= fragment['endLine'] <= files[fragment['file']]['lineCount']
    for mapping in data['diagrams']:
        source = (ROOT / mapping['path']).read_text(encoding='utf-8')
        declared = re.search(r'^%% linux-evidence: (.+)$', source, re.M)
        assert declared and all(ref in fragments for ref in declared[1].split())
        for node in mapping['nodes']:
            assert re.search(r'\b' + re.escape(node['node']) + r'\[', source), node['node']
            assert all(ref in fragments for ref in node['sources']), node['node']
    return {'status': 'PASS', 'sourceFilesChecked': verified_sources,
            'sourceMapSha256': hashlib.sha256((ROOT / 'linux-flow-evidence.json').read_bytes()).hexdigest(),
            'fragments': len(fragments), 'diagrams': len(data['diagrams']),
            'scope': 'Source and diagram provenance; not execution of the grouping algorithm'}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--source-root')
    args = p.parse_args()
    print(json.dumps(verify(args.source_root)))
