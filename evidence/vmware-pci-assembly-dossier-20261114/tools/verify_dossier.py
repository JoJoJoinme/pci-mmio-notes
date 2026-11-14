"""Check dossier integrity and exact inline evidence. Does not access an ESXi host."""
import ast,hashlib,json,re,subprocess
from pathlib import Path
from urllib.parse import unquote,urlsplit
from evidence_format import code,markdown
ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parents[1]
checks=0
def require(ok,label):
    global checks
    checks+=1
    if not ok:raise AssertionError(label)
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(data):return hashlib.sha256(data).hexdigest()
def headings(text):
    result=set();used={}
    for h in re.findall(r'^#{1,6}\s+(.+)$',text,re.M):
        h=re.sub(r'\[([^\]]+)\]\([^)]*\)',r'\1',h).replace('`','').replace('*','')
        h=re.sub(r'[^\w\-\s]','',h.lower()).replace(' ','-')
        count=used.get(h,0);used[h]=count+1;result.add(h+('-'+str(count) if count else ''))
    return result

def main():
    manifest=read(ROOT/'manifest.json');actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts}
    require(actual=={r['path'] for r in manifest['files']},'Complete manifest')
    for r in manifest['files']:
        p=(ROOT/r['path']).resolve();require(p.is_relative_to(ROOT),'Package path boundary')
        data=p.read_bytes();require(len(data)==r['bytes'] and sha(data)==r['sha256'],r['path'])
    path=ROOT/'evidence/snippets.json';d=read(path);snips={s['id']:s for s in d['snippets']};plan=read(ROOT/'selection-plan.json')
    require(len(snips)==len(d['snippets'])==len(plan['selections']),'Unique window IDs')
    require(d['images']==plan['images'],'Pinned images')
    instructions=branches=0
    for s in snips.values():
        pos=int(s['startAddress'],16);fo=int(s['startFileOffset'],16);raw=b''
        for r in s['instructions']:
            data=bytes.fromhex(r['bytes']);require(1<=len(data)<=15,'x86 instruction size')
            require(int(r['address'],16)==pos and int(r['fileOffset'],16)==fo,'Contiguous instruction addresses')
            require(int(r['functionOffset'],16)==pos-int(s['functionAddress'],16),'Function relative offset')
            if r['branch']:
                target=int(r['branch']['target'],16)
                require(r['branch']['insideWindow']==(int(s['startAddress'],16)<=target<int(s['endAddressExclusive'],16)),'Branch window boundary')
                require(r['branch']['fallthrough']==(None if r['mnemonic']=='jmp' else hex(pos+len(data))),'Branch fallthrough')
                branches+=1
            for ref in r['references']:
                literal=ref.get('literal') or (ref if ref['kind']=='literal' else None)
                if literal:require(bytes.fromhex(literal['bytesWithNul'])==literal['text'].encode()+b'\0','Literal bytes')
            raw+=data;pos+=len(data);fo+=len(data);instructions+=1
        require(pos==int(s['endAddressExclusive'],16) and len(raw)==s['windowBytes'],'Window extent')
        require(sha(raw)==s['windowSha256'],'Window byte digest')
        require(len(s['instructions'])==s['instructionCount'],'Window instruction count')
        require((ROOT/'snippets'/f"{s['id']}.asm").read_text(encoding='utf-8').endswith(code(s)),'Standalone assembly '+s['id'])
    decoded=read(ROOT/'evidence/objdump-verification.json')
    require(decoded['status']=='PASS' and decoded['sourceSnippetsSha256']==sha(path.read_bytes()),'Exact independently decoded evidence')
    require(decoded['windows']==len(snips) and decoded['instructionsCompared']==instructions and decoded['directBranchTargetsCompared']==branches,'Independent coverage counts')
    require(decoded['dynamicRelocationsCompared']>=16,'PLT GOT and vtable targets independently checked')
    seen=set();occurrences=0
    for p in ROOT.glob('*.md'):
        text=p.read_text(encoding='utf-8');require('{{' not in text,'No template markers')
        for m in re.finditer(r'<!-- evidence:([A-Z]\d{2}):begin -->.*?<!-- evidence:\1:end -->',text,re.S):
            id=m[1];require(id in snips,'Known inline ID')
            require(m[0]==markdown(snips[id],d['images']),'Exact inline bytes '+p.name+' '+id)
            seen.add(id);occurrences+=1
        require(len(re.findall(r'^```',text,re.M))%2==0,'Balanced code fences')
        for raw in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',text):
            if urlsplit(raw).scheme:continue
            rel,_,fragment=unquote(raw).partition('#');target=(p.parent/rel).resolve() if rel else p
            require(target.exists(),'Link '+raw)
            if fragment and target.suffix=='.md':require(fragment in headings(target.read_text(encoding='utf-8')),'Anchor '+raw)
    require(seen==set(snips),'All selected evidence visible in prose')
    docmap=read(ROOT/'evidence/document-map.json');require(sum(docmap['snippetOccurrences'].values())==occurrences,'Inline occurrence count')
    rt=read(ROOT/'evidence/runtime-crosswalk.json');require(not rt['newRuntimeExperiment'],'No invented new runtime')
    refs=[c['source'] for c in rt['cases']]+[rt['mappingSample']['source']]+[c['source'] for c in rt['warningSamples']]
    for r in refs:
        p=(REPO/r['repoPath']).resolve();require(p.is_relative_to(REPO),'Runtime source path')
        try:data=subprocess.check_output(['git','show',rt['baselineRepoCommit']+':'+r['repoPath']],cwd=REPO,stderr=subprocess.DEVNULL)
        except (OSError,subprocess.CalledProcessError):data=p.read_bytes()
        require(len(data)==r['bytes'] and sha(data)==r['sha256'],'Pinned runtime source')
    for p in (ROOT/'tools').glob('*.py'):ast.parse(p.read_text(encoding='utf-8'))
    print(json.dumps({'status':'PASS','checks':checks,'snippets':len(snips),'instructions':instructions,'directBranches':branches,'inlineBlocks':occurrences,'scope':'Evidence and documentation integrity; not hardware acceptance'}))

if __name__=='__main__':main()
