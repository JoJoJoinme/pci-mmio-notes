"""Offline consistency of receipts, mappings, code checks and provenance."""
import ast,hashlib,json,re
from pathlib import Path
from urllib.parse import unquote,urlsplit
ROOT=Path(__file__).resolve().parent
CASES=[('u3k','u3k-default','25595708',0x10d3),('esx91','esx91-default','25433460',0x10d3),('esx91-native','esx91-nativepci','25433460',0x100e)]
checks=0
def require(condition,label):
    global checks
    checks+=1
    if not condition:raise AssertionError(label)
def load(relative):return json.loads((ROOT/relative).read_text(encoding='utf-8-sig'))
def pci_config(path):
    values={int(i):int(v,16) for i,v in re.findall(r'\[(\d+)\]:\s*0x([0-9a-fA-F]+)',path.read_text(encoding='utf-8-sig'))}
    require(all(i in values for i in range(64)),'PCI header available')
    caps=[];ptr=(values[0x34]&0xfc) if values[6]&0x10 else 0;visited=set()
    while ptr:
        require(ptr>=0x40 and ptr not in visited and ptr+1 in values,'Bounded capability list')
        visited.add(ptr);caps.append(values[ptr]);ptr=values[ptr+1]&0xfc
    return values,caps
def main():
    manifest=load('manifest.json');actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and p!=ROOT/'manifest.json' and '__pycache__' not in p.parts}
    require(actual=={x['path'] for x in manifest['files']},'Manifest coverage')
    for item in manifest['files']:
        path=(ROOT/item['path']).resolve();require(path.is_relative_to(ROOT),'Path boundary')
        data=path.read_bytes();require(len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256'],item['path'])
        if item.get('provenance',{}).get('transformation')=='byte-identical copy':require(item['sha256']==item['provenance']['sourceSha256'],'Original source hash '+item['path'])
    for build,line in [('24280767',5294),('25595708',5304),('25433460',5808)]:
        guard=load('static/'+build+'-guard.json')
        require(guard['status']=='PASS' and guard['build']==build,'Static build check')
        require(guard['warningSourceLine']==line and guard['successStatusRejectedByThisGuard'],'Exact guard matched')
    group=['01:00.0','02:00.0','02:01.0','02:01.1']
    for label,phase,build,device in CASES:
        prefix='raw/'+label+'/'
        verified=load(prefix+'upgrade-verified.json');require(verified['targetBuildVerified'] and "build = '"+build+"'" in verified['product'],'Actual running build '+label)
        require(verified['bootTime']!=verified['oldBootTime'],'New boot observed '+label)
        for fn in [0,1]:
            config,caps=pci_config(ROOT/(prefix+phase+f'-function-{fn}-config.txt'))
            require(config[0]|config[1]<<8==0x8086 and config[2]|config[3]<<8==device,'Model identity '+label)
            require(config[14]==0x80,'Complete multifunction flags '+label)
            require((0x10 in caps)==(device==0x10d3),'PCIe versus native PCI control '+label)
        for role in ['both','reverse','a','b']:
            power=load(prefix+phase+'-power-'+role+'.json');paired=role in {'both','reverse'}
            require(power['task']['state']==('error' if paired else 'success'),'Task result '+label+' '+role)
            require(power['after']['powerState']==('poweredOff' if paired else 'poweredOn'),'Power state '+label+' '+role)
            require(len(power['before']['devices'])==(2 if paired else 1),'Configured device count')
            sampling=load(prefix+phase+'-context-'+role+'.json');require(not sampling['samplingErrors'] and sampling['polls']>=2,'Context sampler valid')
            before=sampling['changes'][0]['contexts']['02:00.0'];coherent=[]
            for state in sampling['changes']:
                require(state['translationEnabled'],'IOMMU remains enabled')
                rows=[state['contexts'][x] for x in group]
                if all(x['present'] for x in rows) and len({(x['domainId'],x['pageTable']) for x in rows})==1 and rows[0]['pageTable']!=before['pageTable']:coherent.append(state)
            require(bool(coherent),'Shared group entered a non-baseline mapping')
            if paired:
                require('DevicePowerOn' in json.dumps(power['task']),'Failure stage')
                second='0000:02:01.1' if role=='both' else '0000:02:01.0'
                kernel=(ROOT/('logs/'+label+'-'+role+'-vmkernel.txt')).read_text(encoding='utf-8')
                expected_line=load('static/'+build+'-guard.json')['warningSourceLine']
                require(f'PCIPassthru: {expected_line}: Expected no IOMMU domain for {second}, got Success' in kernel,'Runtime matches exact static guard')
                after=sampling['after']['contexts'];require(all(after[x]['pageTable']==before['pageTable'] for x in group),'Mapping rolled back after failed VM')
            else:require(load(prefix+phase+'-off-'+role+'.json')['state']=='success','Positive control powered off')
        finish=load(prefix+'finish-host-state.json')
        require(len(finish['vms'])==4 and all(x['powerState']=='poweredOff' for x in finish['vms']),'Owned guests off at finish')
        require(all(not x['enabled'] and not x['active'] for x in finish['pci']),'Targets disabled at finish')
        cleanup=load(prefix+'finish-runtime.json');require(cleanup['qemuStopped'] and cleanup['tapRemoved'],'Outer instance stopped')
        require(all(x['unchanged'] for x in cleanup['baseImageHashes']),'Base images preserved')
        if label!='esx91-native':
            require(load(prefix+'upgrade-apply-result.json')['returncode']==0,'Profile update succeeded')
            require(not load(prefix+'upgrade-apply-intent.json')['noSignatureCheckUsed'],'No signature bypass')
            require(load('sources/'+label+'-download-receipt.json')['vendorSha1Matched'],'Vendor bundle checksum')
    require(all(x['unchanged'] for x in load('raw/esx91-native/finish-parent-integrity.json')['hashes']),'Native control parent overlays unchanged')
    require(load('raw/resource-restored.json')['restored'],'Original host resource state restored')
    latest=load('summary.json')['latestKnownEsx91'];require(latest['build']=='25782009' and not latest['runtimeTested'] and latest['fixStatus']=='UNKNOWN','No invented latest-9.1 result')
    for path in (ROOT/'source-snapshots').glob('*.py.txt'):ast.parse(path.read_text(encoding='utf-8-sig'))
    ast.parse((ROOT/'verify_guard_predicate.py').read_text(encoding='utf-8'))
    for path in ROOT.rglob('*.md'):
        for raw in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if urlsplit(raw).scheme or raw.startswith('#'):continue
            target=(path.parent/unquote(raw.strip('<>').split('#')[0])).resolve();require(target.exists(),'Link '+raw)
    print(json.dumps({'status':'PASS','checks':checks,'scope':'Offline consistency; not another hardware run'}))
if __name__=='__main__':main()
