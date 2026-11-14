"""Verify selected facts against exact licensed local ELF copies, without loading them.

Only Python's standard library is required. This is a reproducibility check of
recorded bytes, symbols and relocations, not a hardware test or a repaired build.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path


class Elf:
    def __init__(self, path, expected):
        self.data = Path(path).read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        if self.sha256 != expected:
            raise ValueError('Unexpected ELF SHA-256: ' + str(path))
        h = struct.unpack_from('<16sHHIQQQIHHHHHH', self.data)
        if h[0][:7] != b'\x7fELF\x02\x01\x01' or h[2] != 62 or h[11] != 64:
            raise ValueError('Expected ELF64 little-endian x86-64')
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', self.data, h[6]+i*64)
                         for i in range(h[12])]
        names = self.payload(self.sections[h[13]])
        self.named = {self.string(names, s[0]): (i, s)
                      for i, s in enumerate(self.sections)}
        self.symbols = {}
        tables = {}
        for i, section in enumerate(self.sections):
            if section[1] not in (2, 11):
                continue
            strings = self.payload(self.sections[section[6]])
            rows = []
            for j in range(section[5]//section[9]):
                row = struct.unpack_from('<IBBHQQ', self.data, section[4]+j*section[9])
                name = self.string(strings, row[0])
                rows.append((name, row))
                if name and (name not in self.symbols or row[5]):
                    self.symbols[name] = row
            tables[i] = rows
        self.relocations = {}
        self.absolute_relocations = {}
        for section in self.sections:
            if section[1] != 4:
                continue
            for j in range(section[5]//section[9]):
                offset, info, addend = struct.unpack_from('<QQq', self.data, section[4]+j*section[9])
                name, _ = tables[section[6]][info >> 32]
                value = (name, info & 0xffffffff, addend)
                self.relocations[section[7], offset] = value
                if h[1] != 1:
                    self.absolute_relocations[offset] = value

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b'\0', offset)].decode()

    def payload(self, section):
        return self.data[section[4]:section[4]+section[5]]

    def at(self, address, size, section_name=None):
        sections = ([self.named[section_name][1]] if section_name else self.sections)
        for s in sections:
            if s[1] == 8 or not s[2] & 2:
                continue
            offset = address-s[3]
            if 0 <= offset <= s[5]-size:
                return self.data[s[4]+offset:s[4]+offset+size]
        raise ValueError('Address outside file-backed allocated sections: ' + hex(address))

    def call_target(self, address):
        data = self.at(address, 5, '.text')
        if data[0] != 0xe8:
            raise ValueError('Expected direct CALL at ' + hex(address))
        return address+5+struct.unpack_from('<i', data, 1)[0]

    def plt_name(self, address):
        target = self.call_target(address)
        stub = self.at(target, 6, '.plt')
        if stub[:2] != b'\xff\x25':
            raise ValueError('Unexpected PLT stub')
        got = target+6+struct.unpack_from('<i', stub, 2)[0]
        return self.absolute_relocations[got][0]


def main():
    parser = argparse.ArgumentParser()
    for name in ('kernel', 'pcip', 'vmkctl'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--output')
    args = parser.parse_args()
    facts = json.loads(Path(__file__).with_name('static-facts.json').read_text(encoding='utf-8'))
    images = {name: Elf(getattr(args, name), row['sha256'])
              for name, row in facts['images'].items()}
    checked = []
    for f in facts['functions']:
        image = images[f['image']]
        s = image.symbols[f['symbol']]
        address = int(f['address'], 16)
        assert s[4] == address and s[5] == f['bytes'], f['symbol']
        body = image.at(address, f['bytes'], '.text')
        assert hashlib.sha256(body).hexdigest() == f['codeSha256'], f['symbol']
        checked.append(f['id'])
    for f in facts['assertions']:
        image = images[f['image']]
        address = int(f['address'], 16)
        kind = f['kind']
        if kind == 'bytes':
            value = bytes.fromhex(f['hex'])
            assert image.at(address, len(value), '.text') == value, f['id']
        elif kind == 'direct_call':
            assert image.call_target(address) == image.symbols[f['target']][4], f['id']
        elif kind == 'relocated_call':
            assert image.at(address, 1, '.text') == b'\xe8', f['id']
            key = (image.named['.text'][0], address+1)
            assert image.relocations[key] == (f['target'], 2, -4), f['id']
        elif kind == 'plt_call':
            assert image.plt_name(address) == f['target'], f['id']
        elif kind == 'got_load':
            code = image.at(address, 7, '.text')
            assert code[:3] == b'\x48\x8b\x05', f['id']
            target = address+7+struct.unpack_from('<i', code, 3)[0]
            assert image.absolute_relocations[target][0] == f['target'], f['id']
        elif kind == 'vtable_pointer':
            assert image.absolute_relocations[address] == (f['target'], 1, 0), f['id']
        else:
            raise ValueError('Unknown assertion kind: ' + kind)
        checked.append(f['id'])
    result = {'status': 'PASS', 'build': facts['build'], 'checks': len(checked),
              'scope': 'Selected static bytes, functions, calls and relocations; no new hardware run',
              'images': {n: e.sha256 for n, e in images.items()}, 'verifiedFacts': checked}
    if args.output:
        Path(args.output).write_bytes((json.dumps(result, indent=2)+'\n').encode())
    print(json.dumps({'status': result['status'], 'checks': len(checked), 'build': facts['build']}))


if __name__ == '__main__':
    main()
