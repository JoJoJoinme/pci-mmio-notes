"""Cross-check each published window using GNU objdump, without executing ELF code."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',required=True);p.add_argument('--snippets',required=True);p.add_argument('--out',required=True);p.add_argument('--objdump',default='objdump');a=p.parse_args()
    paths=json.loads(Path(a.inputs).read_text(encoding='utf-8'));source=Path(a.snippets);d=json.loads(source.read_text(encoding='utf-8'))
    for key,meta in d['images'].items():assert hashlib.sha256(Path(paths[key]).read_bytes()).hexdigest()==meta['sha256'],key
    version=subprocess.check_output([a.objdump,'--version'],text=True).splitlines()[0]
    compared=0;branches=0;alias=[];windows=[]
    for s in d['snippets']:
        command=[a.objdump,'-d','-w','-Mintel','--insn-width=16','--start-address='+s['startAddress'],'--stop-address='+s['endAddressExclusive'],paths[s['image']]]
        out=subprocess.check_output(command,text=True);rows={}
        for line in out.splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$',line)
            if m:rows[int(m[1],16)]=(''.join(m[2].split()),m[3])
        expected={int(x['address'],16) for x in s['instructions']}
        assert set(rows)==expected,(s['id'],'Instruction boundaries differ')
        for ins in s['instructions']:
            raw,asm=rows[int(ins['address'],16)];assert raw==ins['bytes'],(s['id'],ins['address'],'bytes')
            compared+=1
            first=asm.split()[0]
            if first!=ins['mnemonic'].split()[0]:alias.append({'snippet':s['id'],'address':ins['address'],'capstone':ins['mnemonic'],'objdump':first})
            if ins['branch']:
                m=re.match(r'^j\S+\s+(?:0x)?([0-9a-f]+)',asm)
                assert m and int(m[1],16)==int(ins['branch']['target'],16),(s['id'],ins['address'],'branch target')
                branches+=1
        windows.append({'id':s['id'],'instructions':len(expected),'windowSha256':s['windowSha256'],'status':'PASS'})
    dynamic=subprocess.check_output([a.objdump,'-R',paths['vmkctl242']],text=True);dynamic_rows={}
    for line in dynamic.splitlines():
        m=re.match(r'^([0-9a-f]+)\s+(R_X86_64_\S+)\s+(\S+)',line)
        if m:dynamic_rows[int(m[1],16)]=(m[2],m[3])
    relocation_checks={}
    for row in d['vtable']['slots']:relocation_checks[int(row['elfAddress'],16)]=row
    for row in d.get('linkageWitnesses',[]):relocation_checks[int(row['slotAddress'],16)]=row['relocation']
    names={1:'R_X86_64_64',6:'R_X86_64_GLOB_DAT',7:'R_X86_64_JUMP_SLOT'}
    for address,row in relocation_checks.items():
        typ,name=dynamic_rows[address]
        assert typ==names[row['type']] and name.split('@')[0].split('+')[0]==row['symbol'],(hex(address),'dynamic relocation')
    result={'status':'PASS','decoder':version,'sourceSnippetsSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'windows':len(windows),'instructionsCompared':compared,'directBranchTargetsCompared':branches,
            'dynamicRelocationsCompared':len(relocation_checks),
            'scope':'Independent instruction boundaries, raw bytes, direct branch destinations and selected dynamic relocation targets; semantic interpretation remains separately documented',
            'mnemonicSpellingDifferences':alias,'results':windows,'newRuntimeExperiment':False}
    Path(a.out).write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps({k:result[k] for k in ['status','windows','instructionsCompared','directBranchTargetsCompared']}))


if __name__=='__main__':main()
