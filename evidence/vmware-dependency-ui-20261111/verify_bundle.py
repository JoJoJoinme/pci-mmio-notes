#!/usr/bin/env python3
"""Read-only integrity and cross-receipt checks. No lab connection or imports."""
import ast
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent
A, B = '0000:02:01.0', '0000:02:01.1'
CHECKS = 0


def require(condition, message):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise ValueError(message)


def read(name):
    return json.loads((ROOT / name).read_text(encoding='utf-8-sig'))


def pair(rows, enabled, label):
    require({p['id'] for p in rows} == {A, B}, label + ': device identities')
    require(all(p['enabled'] is enabled and p['active'] is enabled for p in rows), label + ': state')
    require(all(p['dependentDevice'] == '0000:01:00.0' for p in rows), label + ': shared bridge')


def devices(rows, expected, label):
    require(len(rows) == len(expected), label + ': count')
    actual = set()
    for row in rows:
        backing = row['backing']
        require('VirtualPCIPassthrough.DeviceBackingInfo' in backing, label + ': static backing')
        match = re.search(r"\bid = '([^']+)'", backing)
        require(match is not None, label + ': backing id')
        actual.add(match.group(1))
    require(actual == set(expected), label + ': IDs')


def check_manifest():
    manifest = read('manifest.json')
    listed = {entry['path'] for entry in manifest['files']}
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
              if p.is_file() and p.name != 'manifest.json' and '__pycache__' not in p.parts}
    require(listed == actual, 'Manifest file set differs')
    for entry in manifest['files']:
        path = ROOT / entry['path']
        require(path.resolve().is_relative_to(ROOT), 'Manifest path escapes package')
        data = path.read_bytes()
        require(len(data) == entry['bytes'], entry['path'] + ': size')
        require(hashlib.sha256(data).hexdigest() == entry['sha256'], entry['path'] + ': SHA-256')
        if entry.get('provenance', {}).get('transformation', '').startswith('byte-identical'):
            require(entry['sha256'] == entry['provenance']['sourceSha256'], entry['path'] + ': source bytes')


def check_enable_and_config():
    for path in ['raw/esxi/api-02-enable-only-a.json', 'raw/vcenter/api-01-host-enable-a.json']:
        value = read(path)
        require(value['request'] == [A], path + ': only A requested')
        pair(value['before'], False, path)
        pair(value['after'], True, path)
    for lane in ['esxi', 'vcenter']:
        for suffix, expected in [('a', [A]), ('b', [B]), ('both', [A, B])]:
            name = f'api-03-configure-{suffix}' if lane == 'esxi' else f'api-02-config-vcdep-20261111-{suffix}'
            path = f'raw/{lane}/{name}.json'
            value = read(path)
            require(value['task']['state'] == 'success', path + ': save')
            devices(value['after']['devices'], expected, path)
        value = read(f'raw/{lane}/ui-both-saved.json')
        for suffix, expected in [('a', [A]), ('b', [B]), ('both', [A, B])]:
            vm = next(v for v in value['vms'] if v['name'].endswith('-' + suffix))
            devices(vm['devices'], expected, lane + ': UI saved ' + suffix)


def check_power():
    api_cases = {
        'esxi': [('api-04-a-first', True), ('api-05-b-while-a', False), ('api-07-b-first', True),
                 ('api-08-a-while-b', False), ('api-10-same-vm-both', False)],
        'vcenter': [('api-03-a-first', True), ('api-04-b-after-a-attempt', False), ('api-06-b-first', True),
                    ('api-07-a-after-b-attempt', False), ('api-09-same-vm-both', False)]}
    for lane, cases in api_cases.items():
        for stem, success in cases:
            value = read(f'raw/{lane}/{stem}.json')
            require(value['task']['state'] == ('success' if success else 'error'), stem + ': task')
            require(value['after']['powerState'] == ('poweredOn' if success else 'poweredOff'), stem + ': power')
            if not success:
                require('DevicePowerOn' in json.dumps(value['task']), stem + ': failure detail')
    cases = [('ui-a-first-on', 'a', True, 'a'), ('ui-b-while-a', 'b', False, 'a'),
             ('ui-b-first-on', 'b', True, 'b'), ('ui-a-while-b', 'a', False, 'b'),
             ('ui-same-vm-both', 'both', False, None)]
    for lane in ['esxi', 'vcenter']:
        for stem, target, success, on in cases:
            if lane == 'vcenter' and target == 'both':
                stem += '-final'
            value = read(f'raw/{lane}/{stem}.json')
            for vm in value['vms']:
                suffix = vm['name'].rsplit('-', 1)[1]
                require(vm['powerState'] == ('poweredOn' if suffix == on else 'poweredOff'), stem + ': VM state')
            tasks = [t for t in value['tasks']
                     if t.get('entity', t.get('entityName', '')).endswith('-' + target)
                     and t.get('operation', t.get('descriptionId')) in ['VirtualMachine.powerOn', 'Datacenter.ExecuteVmPowerOnLRO']]
            require(bool(tasks), stem + ': power task present')
            latest = max(tasks, key=lambda t: t.get('startTime') or '')
            require(latest['state'] == ('success' if success else 'error'), stem + ': final UI task')
            if not success:
                require('DevicePowerOn' in json.dumps(latest), stem + ': UI failure detail')


def check_disable():
    for endpoint in ['esxi', 'vcenter']:
        for suffix, bdf in [('a', A), ('b', B)]:
            stem = f'raw/disable/{endpoint}-single-disable-disable-{suffix}.json'
            value = read(stem)
            require(value['request'] == {'ids': [bdf], 'passthruEnabled': False, 'applyNow': True}, stem + ': exact request')
            require(value['callOutcome'] == 'success', stem + ': call')
            pair(value['before']['pci'], True, stem)
            pair(value['after']['pci'], False, stem)
            require(value['before']['hostBootTime'] == value['after']['hostBootTime'], stem + ': no reboot')
            for native in value['after']['native'].values():
                require(native['Configured Owner'] == native['Current Owner'] == 'VMkernel', stem + ': owners')
                require(native['Module Name'] == 'ne1000', stem + ': driver')
    for prefix in ['esxi-host', 'vcenter-vc']:
        for suffix in ['a', 'b']:
            stem = f'raw/disable/{prefix}-ui-{suffix}-disabled.json'
            value = read(stem)
            pair(value['pci'], False, stem)
            require(all(v['Configured Owner'] == v['Current Owner'] == 'VMkernel' and v['Module Name'] == 'ne1000'
                        for v in value['native'].values()), stem + ': UI native ownership')
    for suffix, selected, other in [('a', A, B), ('b', B, A)]:
        name = 'vc-02-select-a' if suffix == 'a' else 'vc-04-only-b-selected'
        text = (ROOT / f'screenshots/disable/{name}.txt').read_text(encoding='utf-8-sig')
        require(f'checkbox "{selected}" [checked]' in text, name + ': selected member')
        require(f'checkbox "{other}" [checked]' not in text, name + ': other not selected')
    stale = (ROOT / 'screenshots/disable/vc-03-a-disable-complete.txt').read_text(encoding='utf-8-sig')
    final = (ROOT / 'screenshots/disable/vc-03e-all-devices-disabled.txt').read_text(encoding='utf-8-sig')
    require('Passthrough has been disabled' in stale, 'vCenter disabled success message')
    for bdf in [A, B]:
        require(f'{bdf} {bdf} Enabled' in stale, 'vCenter retained stale row')
        require(f'{bdf} {bdf} Disabled' in final, 'vCenter final row disabled')


def check_documents():
    for path in ROOT.rglob('*.json'):
        json.loads(path.read_text(encoding='utf-8-sig'))
    for path in (ROOT / 'source-snapshots').glob('*.py.txt'):
        ast.parse(path.read_text(encoding='utf-8-sig'), filename=path.name)
    ast.parse(Path(__file__).read_text(encoding='utf-8'))
    for path in list(ROOT.rglob('*.md')) + [ROOT.parent / 'README.md']:
        for raw in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', path.read_text(encoding='utf-8')):
            url = raw.strip('<>')
            if urlsplit(url).scheme or url.startswith('#'):
                continue
            destination = (path.parent / unquote(url.split('#', 1)[0])).resolve()
            require(destination.is_relative_to(ROOT.parents[1]) and destination.exists(), f'{path.name}: broken link {raw}')
    excluded = read('raw/excluded-functional/policy-validation.json')
    require(excluded['status'] == 'SETUP_INVALID_BOOTBANK_VOLATILE' and not excluded['usableAsDependencyEvidence'], 'Invalid setup must remain excluded')


def main():
    check_manifest()
    check_enable_and_config()
    check_power()
    check_disable()
    check_documents()
    print(json.dumps({'status': 'PASS', 'checks': CHECKS, 'scope': 'Offline bundle consistency; no hardware re-test'}))


if __name__ == '__main__':
    main()
