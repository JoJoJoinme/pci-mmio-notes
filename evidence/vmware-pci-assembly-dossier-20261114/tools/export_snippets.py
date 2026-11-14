"""Read-only extraction of reviewed x86-64 instruction windows.

Requires pyelftools and Capstone. Inputs must match the pinned SHA-256 values.
The tool reads ELF files and writes evidence JSON; it never loads target code.
"""
import argparse
import bisect
import hashlib
import io
import json
import re
import struct
import sys
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, path, expected):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_64
        from elftools.elf.elffile import ELFFile
        self.raw=Path(path).read_bytes()
        if digest(self.raw)!=expected:raise ValueError('Image SHA-256 differs: '+str(path))
        self.elf=ELFFile(io.BytesIO(self.raw))
        if self.elf['e_machine']!='EM_X86_64' or self.elf.elfclass!=64:raise ValueError('Expected ELF64 x86-64')
        self.sections=list(self.elf.iter_sections())
        self.payloads={i:s.data() for i,s in enumerate(self.sections) if s['sh_type']!='SHT_NOBITS'}
        self.symbols={};self.at_symbols={};self.function_at={};self.object_spans=[]
        for table in self.sections:
            if table['sh_type'] not in ['SHT_SYMTAB','SHT_DYNSYM']:continue
            for s in table.iter_symbols():
                if not s.name:continue
                if s.name not in self.symbols or s['st_size']:self.symbols[s.name]=s
                if isinstance(s['st_shndx'],int):
                    self.at_symbols.setdefault(s['st_value'],[]).append(s.name)
                    if s['st_info']['type']=='STT_FUNC' and s['st_shndx']==self.elf.get_section_index('.text'):
                        self.function_at.setdefault(s['st_value'],[]).append(s.name)
                    if s['st_info']['type']=='STT_OBJECT' and s['st_size']:
                        self.object_spans.append((s['st_value'],s['st_value']+s['st_size'],s.name))
        self.relocations={};self.rel_offsets={};self.absolute_relocations={}
        for sec in self.sections:
            if sec['sh_type']!='SHT_RELA':continue
            table=self.elf.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                s=table.get_symbol(r['r_info_sym']);idx=r['r_offset']
                row={'symbol':s.name,'symbolValue':hex(s['st_value']),'symbolSection':s['st_shndx'],
                     'addend':r['r_addend'],'type':r['r_info_type'],'relocationSection':sec.name}
                self.relocations[sec['sh_info'],idx]=row
                self.rel_offsets.setdefault(sec['sh_info'],[]).append(idx)
                if self.elf['e_type']!='ET_REL':self.absolute_relocations[idx]=row
        for rows in self.rel_offsets.values():rows.sort()
        self.md=Cs(CS_ARCH_X86,CS_MODE_64);self.md.detail=True
        self.plt={}
        import capstone
        for sec in self.sections:
            if sec.name not in ['.plt','.plt.got','.plt.sec']:continue
            for ins in self.md.disasm(sec.data(),sec['sh_addr']):
                if ins.mnemonic=='jmp' and ins.operands[0].type==capstone.x86.X86_OP_MEM and ins.operands[0].mem.base==capstone.x86.X86_REG_RIP:
                    got=ins.address+ins.size+ins.operands[0].mem.disp
                    if got in self.absolute_relocations:
                        self.plt[ins.address]={'gotAddress':hex(got),**self.absolute_relocations[got]}

    def function(self, selection):
        if 'symbol' in selection:
            s=self.symbols[selection['symbol']];idx=s['st_shndx'];start=s['st_value'];size=s['st_size']
        else:
            idx=self.elf.get_section_index('.text');start=int(selection['functionAddress'],16);size=selection['functionBytes']
        sec=self.sections[idx];off=start-sec['sh_addr'];body=self.payloads[idx][off:off+size]
        assert len(body)==size
        return idx,start,body

    def at_alloc(self,address,size):
        for idx,sec in enumerate(self.sections):
            if idx not in self.payloads or not sec['sh_flags']&2:continue
            off=address-sec['sh_addr']
            if 0<=off<=sec['sh_size']-size:return self.payloads[idx][off:off+size],sec['sh_offset']+off
        raise ValueError('Address outside allocated data')

    def literal(self,idx,offset):
        sec=self.sections[idx]
        if idx not in self.payloads or not sec['sh_flags']&2 or offset<0 or offset>=sec['sh_size']:return None
        data=self.payloads[idx][offset:offset+300];end=data.find(b'\0')
        if 3<=end<300 and all(c in [9,10,13] or 32<=c<127 for c in data[:end]):
            return {'text':data[:end].decode(),'bytesWithNul':data[:end+1].hex(),'fileOffset':hex(sec['sh_offset']+offset)}
        return None

    def decode_window(self, selection):
        import capstone
        idx,start,body=self.function(selection);sec=self.sections[idx]
        all_instructions=list(self.md.disasm(body,start))
        assert sum(x.size for x in all_instructions)==len(body),'Incomplete function decode'
        begin=int(selection.get('startAddress',hex(start)),16)
        if 'instructionCount' in selection:
            k=next(i for i,x in enumerate(all_instructions) if x.address==begin)
            chosen=all_instructions[k:k+selection['instructionCount']]
            assert len(chosen)==selection['instructionCount']
            end=chosen[-1].address+chosen[-1].size
        else:
            end=int(selection.get('endAddress',hex(start+len(body))),16)
            chosen=[x for x in all_instructions if begin<=x.address<end]
        assert chosen and chosen[0].address==begin and chosen[-1].address+chosen[-1].size==end
        rows=[]
        for ins in chosen:
            refs=[];offsets=self.rel_offsets.get(idx,[])
            for rpos in offsets[bisect.bisect_left(offsets,ins.address):bisect.bisect_left(offsets,ins.address+ins.size)]:
                row=self.relocations[idx,rpos]
                ref={'kind':'relocation','address':hex(rpos),**row}
                if ins.mnemonic=='lea' and row['type']==2 and isinstance(row['symbolSection'],int):
                    ri=row['symbolSection'];rs=self.sections[ri];off=int(row['symbolValue'],16)-rs['sh_addr']+row['addend']+4
                    lit=self.literal(ri,off)
                    if lit:ref['literal']=lit
                refs.append(ref)
            if ins.mnemonic in ['call','jmp'] and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM:
                target=ins.operands[0].imm
                if target in self.plt:refs.append({'kind':'plt','address':hex(target),**self.plt[target]})
                elif target in self.function_at:refs.append({'kind':'directSymbol','address':hex(target),'symbols':self.function_at[target]})
            for op in ins.operands:
                if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                    target=ins.address+ins.size+op.mem.disp
                    if target in self.absolute_relocations:refs.append({'kind':'got','address':hex(target),**self.absolute_relocations[target]})
                    elif target in self.at_symbols:refs.append({'kind':'ripSymbol','address':hex(target),'symbols':self.at_symbols[target]})
                    elif self.elf['e_type']!='ET_REL':
                        objects=[(a,b,n) for a,b,n in self.object_spans if a<=target<b]
                        if objects:
                            a,b,n=min(objects,key=lambda v:v[1]-v[0]);refs.append({'kind':'objectInterior','address':hex(target),'symbol':n,'offset':hex(target-a)})
                        elif ins.mnemonic=='lea':
                            for ri,rs in enumerate(self.sections):
                                if rs['sh_addr']<=target<rs['sh_addr']+rs['sh_size']:
                                    lit=self.literal(ri,target-rs['sh_addr'])
                                    if lit:refs.append({'kind':'literal','address':hex(target),**lit});break
            branch=None
            if ins.mnemonic.startswith('j') and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM:
                target=ins.operands[0].imm;branch={'target':hex(target),'insideWindow':begin<=target<end,'insideFunction':start<=target<start+len(body),
                    'fallthrough':None if ins.mnemonic=='jmp' else hex(ins.address+ins.size)}
            rows.append({'address':hex(ins.address),'functionOffset':hex(ins.address-start),'fileOffset':hex(sec['sh_offset']+ins.address-sec['sh_addr']),
                         'bytes':ins.bytes.hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str,'references':refs,'branch':branch})
        raw=body[begin-start:end-start]
        return {'id':selection['id'],'title':selection['title'],'image':selection['image'],'symbol':selection.get('symbol'),
                'functionLabel':selection['functionLabel'],'functionAddress':hex(start),'functionBytes':len(body),'functionSha256':digest(body),
                'addressKind':'section-relative .text offset' if self.elf['e_type']=='ET_REL' else 'ELF linked virtual address',
                'section':sec.name,'startAddress':hex(begin),'endAddressExclusive':hex(end),'startFileOffset':hex(sec['sh_offset']+begin-sec['sh_addr']),
                'windowBytes':len(raw),'windowSha256':digest(raw),'instructionCount':len(rows),'instructions':rows}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--inputs',required=True,help='JSON mapping image IDs to licensed local ELF paths')
    p.add_argument('--out',required=True)
    p.add_argument('--package-root',default=str(Path(__file__).resolve().parents[1]))
    p.add_argument('--dependency-path')
    a=p.parse_args()
    if a.dependency_path:sys.path.insert(0,a.dependency_path)
    import capstone
    import elftools
    root=Path(a.package_root);plan=json.loads((root/'selection-plan.json').read_text(encoding='utf-8'))
    paths=json.loads(Path(a.inputs).read_text(encoding='utf-8'))
    out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    images={};rows=[]
    for image_id,meta in plan['images'].items():
        image=Image(paths[image_id],meta['sha256']);images[image_id]=image
        for s in plan['selections']:
            if s['image']==image_id:rows.append(image.decode_window(s))
    rows.sort(key=lambda r:next(i for i,s in enumerate(plan['selections']) if s['id']==r['id']))
    vm=images['vmkctl242'];vtable_symbol='_ZTVN6VmkCtl8Hardware13PciDeviceImplE';start=vm.symbols[vtable_symbol]['st_value'];slots=[]
    for offset in [0x38,0x40,0x48,0x50,0xe0,0x138,0x148,0x158,0x160]:
        addr=start+0x48+offset;r=vm.absolute_relocations[addr]
        raw,file_offset=vm.at_alloc(addr,8)
        slots.append({'vptrSlotOffset':hex(offset),'elfAddress':hex(addr),'rawPointerBytes':raw.hex(),'fileOffset':hex(file_offset),**r})
    linkage=[]
    for row in rows:
        if row['id'] not in ['A01','A02']:continue
        for ins in row['instructions']:
            for ref in ins['references']:
                if ref['kind'] not in ['got','plt']:continue
                slot=int(ref['gotAddress'] if ref['kind']=='plt' else ref['address'],16)
                raw,file_offset=vm.at_alloc(slot,8)
                witness={'instructionAddress':ins['address'],'kind':ref['kind'],'slotAddress':hex(slot),'rawSlotBytes':raw.hex(),'slotFileOffset':hex(file_offset),'relocation':{k:ref[k] for k in ['symbol','symbolValue','symbolSection','addend','type','relocationSection']}}
                if ref['kind']=='plt':
                    stub,_=vm.at_alloc(int(ref['address'],16),6);witness.update({'pltAddress':ref['address'],'pltStubBytes':stub.hex()})
                linkage.append(witness)
    pcip=images['pcip242'];table=pcip.symbols['passthruImpls'];index=table['st_shndx'];section=pcip.sections[index];dispatch=[]
    for mode in range(5):
        offset=table['st_value']+mode*56
        relocation=pcip.relocations.get((index,offset))
        target=None
        if relocation and isinstance(relocation['symbolSection'],int):
            address=int(relocation['symbolValue'],16)+relocation['addend'];target=pcip.function_at.get(address)
        raw=struct.unpack_from('<Q',pcip.payloads[index],offset-section['sh_addr'])[0]
        dispatch.append({'mode':mode,'tableSlotOffset':hex(mode*56),'section':section.name,'sectionOffset':hex(offset),'rawPointer':hex(raw),'relocation':relocation,'resolvedFunctions':target})
    result={'schemaVersion':1,'tools':{'capstone':capstone.__version__,'pyelftools':elftools.__version__},'images':plan['images'],'snippets':rows,
            'registrationDispatch':{'image':'pcip242','symbol':'passthruImpls','strideBytes':56,'precheckSlots':dispatch},
            'linkageWitnesses':linkage,
            'vtable':{'image':'vmkctl242','symbol':vtable_symbol,'address':hex(start),'primaryAddressPointOffset':'0x48','slots':slots}}
    (out/'snippets.json').write_bytes((json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode())
    print(json.dumps({'snippets':len(rows),'instructions':sum(r['instructionCount'] for r in rows),'decodedBytes':sum(r['windowBytes'] for r in rows),'images':len(images)}))


if __name__=='__main__':main()
