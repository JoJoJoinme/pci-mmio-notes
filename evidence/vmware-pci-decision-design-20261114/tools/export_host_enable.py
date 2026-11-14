"""Export selected host-enable instruction evidence from a licensed local ELF.

python -B tools/export_host_enable.py --image /path/libvmkctl.so \
    --dependency-path /path/to/capstone-and-pyelftools
Reads the binary only; never executes VMware code or connects to a host.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
DOSSIER = ROOT.parent / 'vmware-pci-assembly-dossier-20261114'


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--dependency-path')
    args = parser.parse_args()
    if args.dependency_path:
        sys.path.insert(0, args.dependency_path)
    sys.path.insert(0, str(DOSSIER / 'tools'))
    from export_snippets import Image
    from evidence_format import code, markdown
    import capstone
    import elftools

    old = json.loads((DOSSIER / 'evidence/snippets.json').read_text(encoding='utf-8'))
    plan = json.loads((ROOT / 'supplement/selection-plan.json').read_text(encoding='utf-8'))
    metadata = old['images']['vmkctl242']
    binary = Image(args.image, metadata['sha256'])
    rows = [binary.decode_window(s) for s in plan['selections']]
    witnesses = []
    for row in rows:
        for ins in row['instructions']:
            for ref in ins['references']:
                if ref['kind'] not in ('plt', 'got'):
                    continue
                slot = int(ref['gotAddress'] if ref['kind'] == 'plt' else ref['address'], 16)
                raw, offset = binary.at_alloc(slot, 8)
                item = {'instructionAddress': ins['address'], 'kind': ref['kind'],
                        'slotAddress': hex(slot), 'rawSlotBytes': raw.hex(), 'slotFileOffset': hex(offset),
                        'relocation': {k: ref[k] for k in ['symbol', 'symbolValue', 'symbolSection', 'addend', 'type', 'relocationSection']}}
                if ref['kind'] == 'plt':
                    stub, _ = binary.at_alloc(int(ref['address'], 16), 6)
                    item.update({'pltAddress': ref['address'], 'pltStubBytes': stub.hex()})
                witnesses.append(item)
    result = {'schemaVersion': 1, 'tools': {'capstone': capstone.__version__, 'pyelftools': elftools.__version__},
              'images': {'vmkctl242': metadata}, 'snippets': rows,
              'vtable': old['vtable'], 'linkageWitnesses': witnesses,
              'newRuntimeExperiment': False}
    out = ROOT / 'supplement'
    (out / 'snippets').mkdir(parents=True, exist_ok=True)
    write_json(out / 'snippets.json', result)
    intro = ('# 主机启用直通的补充汇编证据\n\n'
             '补齐原证据集未展示的依赖非空检查、切换入口和网络占用拒绝。固定 build 24280767；'
             '不包含 hostd 的完整 API 编排，也不执行新的主机切换。\n\n'
             'E01/E02 证明依赖对象必须非空；E03 展示 capable、已配置状态和启动设备判断；'
             'E04 是网络信息来源；E05 是设备名查找与配置写入的分叉；E06 展示拒绝分支中的业务原因。'
             '网络收集循环中的全部虚表槽尚未逐项命名。\n\n'
             '[返回 API 设计](../02-host-api-enable.md) · '
             '[独立 objdump 核对](objdump-verification.json)\n\n')
    for s in rows:
        header = (f"; {s['id']} {s['title']}\n; build {metadata['build']} / {metadata['component']}\n"
                  f"; image SHA256 {metadata['sha256']}\n; {s['addressKind']}\n"
                  f"; window SHA256 {s['windowSha256']}\n\n")
        (out / 'snippets' / f"{s['id']}.asm").write_text(header + code(s), encoding='utf-8', newline='\n')
        intro += markdown(s, result['images']) + '\n\n'
    (out / 'README.md').write_text(intro.rstrip() + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'windows': len(rows), 'instructions': sum(s['instructionCount'] for s in rows)}))


if __name__ == '__main__':
    main()
