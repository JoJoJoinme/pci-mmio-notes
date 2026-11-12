"""Offline evidence consistency checks; does not access an ESXi host."""
import ast,hashlib,json,re
from pathlib import Path
from urllib.parse import urlsplit,unquote
ROOT=Path(__file__).resolve().parent
checks=0
def require(condition,label):
    global checks
    checks+=1
    if not condition:raise AssertionError(label)
def read(name):return json.loads((ROOT/name).read_text(encoding='utf-8-sig'))
def main():
    manifest=read('manifest.json')
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and p!=ROOT/'manifest.json' and '__pycache__' not in p.parts}
    require(actual=={x['path'] for x in manifest['files']},'Complete manifest coverage')
    for item in manifest['files']:
        path=(ROOT/item['path']).resolve();require(path.is_relative_to(ROOT),'Path boundary')
        data=path.read_bytes();require(len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256'],item['path'])
        if item.get('provenance',{}).get('transformation')=='byte-identical copy':require(item['sha256']==item['provenance']['sourceSha256'],'Source bytes '+item['path'])
    for phase,cases in [('native-mf',['both','reverse','a','b']),('nonshareable',['both','reverse'])]:
        for case in cases:
            value=read('raw/'+phase+'-power-'+case+'.json');pair=case in {'both','reverse'}
            require(value['task']['state']==('error' if pair else 'success'),phase+' '+case+' task')
            require(value['after']['powerState']==('poweredOff' if pair else 'poweredOn'),phase+' '+case+' VM state')
            require(len(value['before']['devices'])==(2 if pair else 1),'Device count')
            sample=read('raw/'+phase+'-context-'+case+'.json')
            require(not sample['samplingErrors'] and sample['polls']>=2,'Successful context sampling')
            states=sample['changes'];require(len(states)>=2,'Context transition')
            group=['01:00.0','02:00.0','02:01.0','02:01.1']
            for state in states:
                require(state['translationEnabled'],'IOMMU enabled')
                values=[state['contexts'][x] for x in group]
                require(all(x['present'] for x in values),'All contexts present')
                require(len({(x['domainId'],x['pageTable']) for x in values})==1,'Shared domain and page table')
            baseline=states[0]['contexts']['02:00.0'];changed=[s for s in states if s['contexts']['02:00.0']['pageTable']!=baseline['pageTable']]
            require(bool(changed),'Group moved from baseline')
            if pair:
                require(states[-1]['contexts']['02:00.0']['pageTable']==baseline['pageTable'],'Rollback to baseline')
                log=(ROOT/('log-excerpts/'+phase+'-'+case+'-vmkernel.txt')).read_text()
                second='0000:02:01.1' if case=='both' else '0000:02:01.0'
                require('Expected no IOMMU domain for '+second+', got Success' in log,'Second function fails in selected task window')
    for fn in [0,1]:
        text=(ROOT/f'raw/native-mf-function-{fn}-config.txt').read_text()
        require(int(re.search(r'\[14\]:\s*0x([0-9a-f]+)',text).group(1),16)==0x80,'Both multifunction bits set')
    policy=read('raw/control-map-effective.json')
    require(policy['valid'] and set(policy['vsiFptShareable'].values())=={'0'},'Both explicit policy flags effective')
    require(all(x['byteIdentical'] and x['upstreamSha256']==x['localSha256'] for x in read('source-analysis/comparison.json')['files']),'Upstream source equality')
    require(read('raw/control-map-restore.json')['rule'] is None,'Original map restored')
    for case in ['both','reverse']:
        power=read('raw/root-control/root-control-power-'+case+'.json')
        require(power['task']['state']=='success' and power['after']['powerState']=='poweredOn' and len(power['after']['devices'])==2,'PCIe paired success')
        sample=read('raw/root-control/root-control-context-'+case+'.json')
        values=[sample['after']['contexts'][x] for x in ['01:00.0','01:00.1']]
        require(all(x['present'] for x in values) and len({(x['domainId'],x['pageTable']) for x in values})==1,'PCIe same VM shares domain and page table')
    for case,active,idle in [('a','01:00.0','01:00.1'),('b','01:00.1','01:00.0')]:
        power=read('raw/root-control/root-single-power-'+case+'.json');require(power['task']['state']=='success' and power['after']['powerState']=='poweredOn','PCIe single success')
        sample=read('raw/root-control/root-single-context-'+case+'.json');before=sample['changes'][0]['contexts'];after=sample['after']['contexts']
        require(after[active]['pageTable']!=before[active]['pageTable'],'Only active function moves to VM map')
        require(after[idle]['pageTable']==before[idle]['pageTable'],'Idle function stays in baseline map')
        require(after[active]['domainId']!=after[idle]['domainId'],'Independent requester associations in PCIe single control')
    rootCleanup=read('raw/root-control/finish-runtime.json');require(rootCleanup['qemuStopped'] and rootCleanup['tapRemoved'],'PCIe control shutdown')
    require(read('raw/finish-hyperv-restoration.json')['restored'],'Hyper-V original running state restored')
    cleanup=read('raw/finish-runtime.json');require(cleanup['qemuStopped'] and cleanup['tapRemoved'],'Owned lab stopped')
    require(all(x['unchanged'] for x in cleanup['baseImageHashes']),'Base images unchanged')
    for path in (ROOT/'source-snapshots').glob('*.py.txt'):ast.parse(path.read_text(encoding='utf-8-sig'))
    for path in ROOT.rglob('*.md'):
        for raw in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if urlsplit(raw).scheme or raw.startswith('#'):continue
            target=(path.parent/unquote(raw.strip('<>').split('#')[0])).resolve();require(target.exists(),'Link '+raw)
    print(json.dumps({'status':'PASS','checks':checks,'scope':'Offline consistency, not a hardware re-run'}))
if __name__=='__main__':main()
