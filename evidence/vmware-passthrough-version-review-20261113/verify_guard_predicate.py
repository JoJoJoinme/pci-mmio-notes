"""Check the same registration guard in exact licensed local ELF copies.

Requires capstone and pyelftools. It reads files only; it does not patch or load
the module. Original VMware binaries are not distributed in this package.
"""
import argparse,hashlib,io,json,sys
from pathlib import Path
HASHES={
    '24280767':'ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca',
    '25595708':'f5911caac9fa163786ce59a78bfc20284696d205b4a76c8180a141fd0214e089',
    '25433460':'47d5ac91f8c8e2ddc0b68ef2a8c145aa427ad6a99f0c863ed380091cc2fcc8ca',
}
def main():
    p=argparse.ArgumentParser();p.add_argument('--module',required=True);p.add_argument('--build',required=True,choices=HASHES);p.add_argument('--output');p.add_argument('--dependency-path');args=p.parse_args()
    if args.dependency_path:sys.path.insert(0,args.dependency_path)
    import capstone
    from elftools.elf.elffile import ELFFile
    data=Path(args.module).read_bytes();digest=hashlib.sha256(data).hexdigest();assert digest==HASHES[args.build],'Exact module hash differs'
    elf=ELFFile(io.BytesIO(data));assert elf.elfclass==64 and elf['e_machine']=='EM_X86_64'
    symbols=elf.get_section_by_name('.symtab');by_name={x.name:x for x in symbols.iter_symbols()};text=elf.get_section_by_name('.text');text_index=elf.get_section_index('.text')
    relocs={}
    for sec in elf.iter_sections():
        if sec['sh_type']!='SHT_RELA' or sec['sh_info']!=text_index:continue
        table=elf.get_section(sec['sh_link'])
        for relocation in sec.iter_relocations():relocs[relocation['r_offset']]=table.get_symbol(relocation['r_info_sym'])
    fn=by_name['PCIPassthruRegisterDeviceInt'];start=fn['st_value'];body=text.data()[start:start+fn['st_size']]
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;instructions=list(md.disasm(body,start))
    def referenced(ins):return [s for off,s in relocs.items() if ins.address<=off<ins.address+ins.size]
    def cstring(symbol):
        if not isinstance(symbol['st_shndx'],int):return b''
        section=elf.get_section(symbol['st_shndx']);value=section.data();off=symbol['st_value']
        if off>=len(value):return b''
        end=value.find(b'\0',off);return value[off:end] if end>=0 else b''
    warnings=[i for i,ins in enumerate(instructions) if any(b'Expected no IOMMU domain' in cstring(s) for s in referenced(ins))]
    assert len(warnings)==1,'Diagnostic is not unique'
    wi=warnings[0];queries=[i for i in range(wi) if instructions[i].mnemonic=='call' and any(s.name=='IOMMU_GetAddressDomain' for s in referenced(instructions[i]))]
    assert queries;qi=queries[-1];region=instructions[qi+1:wi]
    comparisons=[ins for ins in region if ins.mnemonic=='cmp' and ins.op_str.startswith('eax, ')]
    assert len(comparisons)==1 and comparisons[0].operands[1].imm==0x0bad0003,'Expected no-guest-domain status check changed'
    conditional=[ins for ins in region if ins.mnemonic.startswith('j')]
    assert len(conditional)==1 and conditional[0].mnemonic=='je','Unexpected alternative reuse branch before warning'
    continuation=conditional[0].operands[0].imm;assert start<=continuation<instructions[qi].address
    source_lines=[ins.operands[1].imm for ins in region if ins.mnemonic=='mov' and ins.op_str.startswith('esi, ') and ins.operands[1].type==capstone.x86.X86_OP_IMM]
    assert source_lines,'Warning source line missing'
    after=instructions[wi:wi+18]
    assert any(ins.mnemonic=='call' and any(s.name=='_Warning' for s in referenced(ins)) for ins in after)
    assert any(ins.mnemonic=='mov' and len(ins.operands)==2 and ins.operands[1].type==capstone.x86.X86_OP_IMM and ins.operands[1].imm==0x0bad0005 for ins in after)
    assert any(ins.mnemonic=='call' and any(s.name=='PCISbdfMap_Find' for s in referenced(ins)) for ins in instructions[:qi])
    assert any(ins.mnemonic=='call' and any(s.name=='VMKPCIPassthru_GetDeviceDependencies' for s in referenced(ins)) for ins in instructions[:qi])
    result={'status':'PASS','build':args.build,'moduleSha256':digest,'function':'PCIPassthruRegisterDeviceInt','functionAddress':hex(start),'functionBytes':len(body),
            'queryCallAddress':hex(instructions[qi].address),'statusCompareAddress':hex(comparisons[0].address),'normalContinuationAddress':hex(continuation),
            'expectedAbsenceStatus':'0x0bad0003','successStatusRejectedByThisGuard':True,'sameOwnerAlternativeBetweenQueryAndWarning':False,
            'warningSourceLine':source_lines[-1],'failureStatus':'0x0bad0005','registrationFunctionContainsSbdfAndDependencyChecks':True,
            'scope':'Selected guard and surrounding conditions only; runtime is recorded separately; no claim that all versions or registration modes are equivalent',
            'tools':{'capstone':capstone.__version__}}
    if args.output:Path(args.output).write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps(result))
if __name__=='__main__':main()
