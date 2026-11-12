"""Read-only checks against the user's licensed ESXi 24280767 ELF copies.

No binaries are distributed or executed. This verifies selected static facts,
not a repaired runtime or general hardware support.
"""
import argparse,hashlib,json,struct
from pathlib import Path

EXPECTED_PCIP='ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca'
EXPECTED_KERNEL='5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775'
checks=[]
def require(condition,label):
    if not condition:raise ValueError(label)
    checks.append(label)
class Elf:
    def __init__(self,path,expected):
        self.data=Path(path).read_bytes();self.sha=hashlib.sha256(self.data).hexdigest()
        require(self.sha==expected,'Exact ELF hash '+Path(path).name)
        h=struct.unpack_from('<16sHHIQQQIHHHHHH',self.data)
        require(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[2]==62 and h[11]==64,'ELF64 little endian x86-64')
        self.sections=[struct.unpack_from('<IIQQQQIIQQ',self.data,h[6]+i*64) for i in range(h[12])]
        strings=self.payload(self.sections[h[13]])
        self.named={self.string(strings,s[0]):s for s in self.sections}
        self.symbols={};self.symbol_tables={}
        for i,s in enumerate(self.sections):
            if s[1]!=2:continue
            names=self.payload(self.sections[s[6]]);rows=[]
            for j in range(s[5]//s[9]):
                row=struct.unpack_from('<IBBHQQ',self.data,s[4]+j*s[9]);name=self.string(names,row[0]);rows.append((name,row))
                if name:self.symbols[name]=row
            self.symbol_tables[i]=rows
        self.relocs={}
        for s in self.sections:
            if s[1]!=4 or s[7]!=self.sections.index(self.named['.text']):continue
            for j in range(s[5]//s[9]):
                offset,info,addend=struct.unpack_from('<QQq',self.data,s[4]+j*s[9]);name,_=self.symbol_tables[s[6]][info>>32]
                self.relocs[offset]=(name,info&0xffffffff,addend)
    @staticmethod
    def string(data,offset):return data[offset:data.index(b'\0',offset)].decode()
    def payload(self,section):return self.data[section[4]:section[4]+section[5]]
    def code(self,address,count):
        s=self.named['.text'];offset=address-s[3]
        if not 0<=offset<=s[5]-count:raise ValueError('Code range outside .text')
        return self.data[s[4]+offset:s[4]+offset+count]
    def signature(self,address,hexbytes,label):require(self.code(address,len(bytes.fromhex(hexbytes)))==bytes.fromhex(hexbytes),label)
    def symbol_address(self,name):return self.symbols[name][4]
    def rel_call(self,address,name):
        require(self.code(address,1)==b'\xe8' and self.relocs[address+1]==(name,2,-4),'Relocated call '+name+' @ '+hex(address))
    def direct_call(self,address,name):
        code=self.code(address,5);require(code[0]==0xe8,'Direct call opcode '+hex(address))
        require(address+5+struct.unpack_from('<i',code,1)[0]==self.symbol_address(name),'Resolved call '+name)

def main():
    p=argparse.ArgumentParser();p.add_argument('--pcip-module',required=True);p.add_argument('--kernel',required=True);p.add_argument('--output');args=p.parse_args()
    module=Elf(args.pcip_module,EXPECTED_PCIP);kernel=Elf(args.kernel,EXPECTED_KERNEL)
    require(module.symbol_address('PCIPassthruRegisterDeviceInt')==0x4b6c,'Registration function identity')
    module.rel_call(0x4ca7,'PCISbdfMap_Find')
    module.rel_call(0x4df6,'VMKPCIPassthru_GetDeviceDependencies')
    module.rel_call(0x4e41,'VMKPCIPassthru_GetDeviceDependencies')
    module.signature(0x4e80,'44 3b 6a 70 74 a3','Dependency loop has matching-owner continuation')
    module.rel_call(0x53da,'IOMMU_GetAddressDomain')
    module.signature(0x53e4,'3d 03 00 ad 0b','Registration compares query status with 0x0bad0003')
    branch=module.code(0x53eb,6);require(branch[:2]==b'\x0f\x84','Only equality branch continues')
    require(0x53eb+6+struct.unpack_from('<i',branch,2)[0]==0x50c9,'Equality branch reaches normal continuation')
    module.signature(0x5410,'be ae 14 00 00','Warning source line is 5294')
    require(module.relocs[0x5418]==('.LC58',2,-4),'Warning format relocation')
    symbol=module.symbols['.LC58'];section=module.sections[symbol[3]];offset=section[4]+symbol[4]
    require(b'Expected no IOMMU domain' in module.data[offset:module.data.index(b'\0',offset)],'Exact runtime warning format')
    module.signature(0x5425,'41 bd 05 00 ad 0b','Failure status set on query mismatch')
    kernel.direct_call(0x420000165450,'PCI_GetDevice')
    kernel.direct_call(0x420000165458,'IOMMU_GetDeviceDomain')
    kernel.signature(0x420000165476,'41 b8 03 00 ad 0b','Domain query no-guest-domain return value')
    kernel.signature(0x4200001653de,'4c 8b a3 78 03 00 00','Domain getter reads per-device state at +0x378')
    kernel.direct_call(0x42000016553f,'PCI_GetTopmostAliasingBridge')
    kernel.direct_call(0x42000016555b,'PCI_IterateDeviceTree')
    lea=kernel.code(0x420000165549,7)
    require(lea[:3]==b'\x48\x8d\x35' and 0x420000165550+struct.unpack_from('<i',lea,3)[0]==kernel.symbol_address('IOMMUSwitchDeviceIterator'),'Aliasing-tree iterator callback')
    kernel.signature(0x420000164532,'48 89 8b 78 03 00 00','Iterator writes the same +0x378 domain field')
    kernel.signature(0x420000164499,'4c 39 ef','Iterator compares existing and requested domains')
    kernel.signature(0x42000016458e,'41 83 c4 01 44 89 a3 70 03 00 00','Same-domain path has a reference-count increment')
    result={'status':'PASS','build':'8.0.3-0.35.24280767','checks':len(checks),'scope':'Exact static instruction/relocation facts, combined with separately retained runtime evidence; no binary patch or repaired runtime',
            'moduleSha256':module.sha,'kernelSha256':kernel.sha,'verifiedFacts':checks,
            'mechanism':'Per-SBDF registration newness is checked against domain state that the IOMMU layer updates across an aliasing bridge subtree',
            'fixValidated':False,'vendorDefectClassification':'UNCONFIRMED'}
    if args.output:Path(args.output).write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps(result))
if __name__=='__main__':main()
