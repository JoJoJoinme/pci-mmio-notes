"""Read-only extraction / independent verification of one ACS quirk function.

Export: python -B tools/export_acs_detail.py --kernel /licensed/kernel.elf
        --dependency-path /path/to/capstone-and-pyelftools
Verify: python -B tools/export_acs_detail.py --kernel /licensed/kernel.elf
        --verify-only --objdump objdump
No target code is executed or patched.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
DOSSIER = ROOT.parent / 'vmware-pci-assembly-dossier-20261114'
OUT = ROOT / 'acs-supplement'


def sha(data): return hashlib.sha256(data).hexdigest()
def write(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--kernel', required=True)
    p.add_argument('--dependency-path')
    p.add_argument('--verify-only', action='store_true')
    p.add_argument('--objdump', default='objdump')
    a = p.parse_args()
    if a.verify_only:
        src = OUT / 'snippets.json'
        data = json.loads(src.read_text(encoding='utf-8'))
        assert sha(Path(a.kernel).read_bytes()) == data['images']['kernel242']['sha256']
        count, branches = 0, 0
        for selected in data['snippets']:
            text = subprocess.check_output([a.objdump, '-d', '-w', '-Mintel', '--insn-width=16',
                '--start-address=' + selected['startAddress'],
                '--stop-address=' + selected['endAddressExclusive'], a.kernel], text=True)
            rows = {}
            for line in text.splitlines():
                m = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$', line)
                if m: rows[int(m[1], 16)] = (''.join(m[2].split()), m[3])
            assert set(rows) == {int(i['address'], 16) for i in selected['instructions']}
            for instruction in selected['instructions']:
                raw, asm = rows[int(instruction['address'], 16)]
                assert raw == instruction['bytes']
                count += 1
                if instruction['branch']:
                    target = re.match(r'^j\S+\s+(?:0x)?([0-9a-f]+)', asm)
                    assert target and int(target[1], 16) == int(instruction['branch']['target'], 16)
                    branches += 1
        proof = {'status': 'PASS', 'decoder': subprocess.check_output([a.objdump, '--version'], text=True).splitlines()[0],
                 'sourceSnippetsSha256': sha(src.read_bytes()), 'windows': len(data['snippets']),
                 'instructionsCompared': count, 'directBranchTargetsCompared': branches,
                 'newRuntimeExperiment': False,
                 'scope': 'Independent instruction boundaries, machine bytes and direct branch targets; no hardware test'}
        write(OUT / 'objdump-verification.json', proof)
        print(json.dumps(proof))
        return

    if a.dependency_path: sys.path.insert(0, a.dependency_path)
    sys.path.insert(0, str(DOSSIER / 'tools'))
    from export_snippets import Image
    from evidence_format import code, markdown
    import capstone
    import elftools
    old = json.loads((DOSSIER / 'evidence/snippets.json').read_text(encoding='utf-8'))
    meta = old['images']['kernel242']
    image = Image(a.kernel, meta['sha256'])
    selection = {'id': 'Q01', 'image': 'kernel242', 'symbol': 'PCIQuirks_GetAcsCtrlOffset',
                 'functionLabel': 'PCIQuirks_GetAcsCtrlOffset', 'title': '按设备型号返回 ACS Control 偏移'}
    selected = image.decode_window(selection)
    data = {'schemaVersion': 1, 'images': {'kernel242': meta}, 'snippets': [selected],
            'tools': {'capstone': capstone.__version__, 'pyelftools': elftools.__version__},
            'newRuntimeExperiment': False}
    (OUT / 'snippets').mkdir(parents=True, exist_ok=True)
    write(OUT / 'snippets.json', data)
    write(OUT / 'selection-plan.json', {'schemaVersion': 1, 'selections': [selection]})
    header = f"; Q01 build {meta['build']} / {meta['component']}\n; image SHA256 {meta['sha256']}\n; window SHA256 {selected['windowSha256']}\n\n"
    (OUT / 'snippets/Q01.asm').write_text(header + code(selected), encoding='utf-8', newline='\n')
    intro = ('# ACS quirk 的完整函数证据\n\n'
             '本函数按 vendor/device 字段返回 ACS Control 的相对偏移，默认 6，特定 Intel 范围返回 8。'
             'M07 的调用点将该结果加到 ACS capability 起始地址后读取控制值；该 quirk 本身没有返回通过/拒绝结论。\n\n'
             '16 位加法分支对应的 device 范围为 a110–a11f、9d10–9d1b、a290–a29f、9db0–9dbf。'
             '这里没有据此声称取得了芯片勘误或厂商原始结构体定义。\n\n'
             '[返回 ACS 规则详解](../03-acs-rule-details.md#quirk) · '
             '[独立 objdump 核对](objdump-verification.json)\n\n')
    (OUT / 'README.md').write_text(intro + markdown(selected, data['images']) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'windows': 1, 'instructions': selected['instructionCount'], 'bytes': selected['windowBytes']}))


if __name__ == '__main__': main()
