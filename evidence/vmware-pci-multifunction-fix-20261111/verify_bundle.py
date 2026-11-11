#!/usr/bin/env python3
"""Read-only evidence checks; does not connect to or mutate the lab."""
import ast
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote,urlsplit

ROOT=Path(__file__).resolve().parent
A,B='0000:01:00.0','0000:01:00.1'
checks=0
def require(value,message):
    global checks
    checks+=1
    if not value:raise ValueError(message)
def read(name):return json.loads((ROOT/name).read_text(encoding='utf-8-sig'))
def task(name,state,device_count=None):
    value=read('raw/'+name+'.json')
    require(value['task']['state']==state,name+': task state')
    require(value['after']['powerState']==('poweredOn' if state=='success' else 'poweredOff'),name+': power state')
    if device_count is not None:
        require(len(value['after']['devices'])==device_count,name+': device count')
    if state=='error': require('DevicePowerOn' in json.dumps(value['task']),name+': error stage')
    return value

def main():
    manifest=read('manifest.json')
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and p.name!='manifest.json' and '__pycache__' not in p.parts}
    require(actual=={f['path'] for f in manifest['files']},'Manifest coverage')
    for item in manifest['files']:
        path=(ROOT/item['path']).resolve()
        require(path.is_relative_to(ROOT),'Manifest path outside package')
        data=path.read_bytes()
        require(len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256'],item['path']+': bytes')
        if item.get('provenance',{}).get('transformation')=='byte-identical copy':
            require(item['sha256']==item['provenance']['sourceSha256'],item['path']+': source hash')
    for phase in ['pcie-baseline','functional-effective-probe','mf-header-matrix','native-mf-matrix','ui6-matrix']:
        task(phase+'-on-both','success',2)
        task(phase+'-on-reverse','success',2)
        blocked=phase not in ['pcie-baseline','functional-effective-probe']
        for order in ['a-then-b','b-then-a']:
            first=task(phase+'-'+order+'-first','success',1)
            second=task(phase+'-'+order+'-second','error' if blocked else 'success',1)
            require(first['task']['completeTime']<=second['task']['startTime'],phase+': ordered requests')
        summary=read('raw/'+phase+'-results.json')
        require(len(summary['results'])==4,phase+': all cases recorded')
    for suffix,bdf in [('a',A),('b',B)]:
        for action,enabled in [('enable',True),('disable',False)]:
            value=read('raw/native-mf-owner-'+suffix+'-'+action+'.json')
            require(value['ids']==[bdf] and value['enabled'] is enabled,'One requested function')
            require(value['outcome']=='success','Owner call success')
            require({v['id'] for v in value['after']}=={A,B},'Owner pair identities')
            require(all(v['enabled'] is enabled and v['active'] is enabled for v in value['after']),'Both owner flags follow request')
    for label,expected in [('before-header-fix',[0x80,0]),('after-header-fix',[0x80,0x80])]:
        text=(ROOT/('raw/'+label+'-config-space.txt')).read_text(encoding='utf-8-sig')
        require([int(x,16) for x in re.findall(r'\[14\]:\s*0x([0-9a-fA-F]+)',text)]==expected,label+': header bytes')
    for filename in ['native-mf-policy-final.json','ui6-policy-verified.json']:
        value=read('raw/'+filename)
        require(value['valid'] and value['policyAction']=='remove' and value['matchingRows']==[],filename+': no override')
        require(set(value['vsiFptShareable'].values())=={'1'},filename+': default sharing flags')
        target=[d for d in value['pci'] if d['id'] in {A,B}]
        require(len(target)==2 and {d['dependentDevice'] for d in target}=={'0000:00:08.0'},filename+': common reset dependency')
    for filename,memory in [('mf-header-runtime.json','8192'),('resume-runtime.json','6144')]:
        value=read('raw/'+filename)
        argv=value['qemuArgv']
        require(argv[argv.index('-m')+1]==memory,filename+': actual RAM')
        require(any('id=test_fn1,' in x and 'multifunction=on' in x for x in argv),filename+': Function 1 property')
    host=read('raw/ui-host-both-on.json')
    both=next(v for v in host['vms'] if v['name'].endswith('-both'))
    require(both['powerState']=='poweredOn' and len(both['devices'])==2,'Host UI actual state')
    tasks=[t for t in host['tasks'] if t['entity']==both['name'] and t['operation']=='VirtualMachine.powerOn']
    require(max(tasks,key=lambda t:t['startTime'])['state']=='success','Host UI power task')
    blocked=read('raw/vc-reconnect.json')
    require(blocked['task']['taskId']=='task-7110' and blocked['task']['state']=='error','vCenter reconnect result')
    require(blocked['task']['fault']['type']=='vmodl.fault.NotEnoughLicenses','vCenter license blocker')
    require(any(m['key'].endswith('licenseExpired') for m in blocked['task']['fault']['faultMessages']),'Expired evaluation fault')
    require(read('summary.json')['vcenterUiStatus']=='BLOCKED_EXPIRED_VCENTER_EVALUATION_LICENSE','No false vCenter UI completion')
    preserved=read('raw/final-preserved-state.json')
    require(len(preserved['vms'])==4 and all(v['powerState']=='poweredOff' for v in preserved['vms']),'Four retained test VMs powered off')
    require(all(not p['enabled'] and not p['active'] for p in preserved['after']),'Targets disabled at finish')
    network=read('raw/final-network-cleanup.json')
    require(all(network[k] for k in ['qemuStopped','remoteDedicatedListenerStopped','tunnelProcessStopped','tunRemoved','tapRemoved','ownedHostRouteRemoved']),'Task network cleanup')
    require(all(v['unchanged'] for v in network['baseImageHashes']),'Base images unchanged')
    require(not read('raw/final-windows-cleanup.json')['vcsaRunning'],'VCSA suspended')
    require(read('raw/wsl-cap-restored.json')['sha256']==read('raw/wsl-cap-change.json')['originalSha256'],'WSL config byte restoration')
    for path in ROOT.rglob('*.json'):json.loads(path.read_text(encoding='utf-8-sig'))
    for path in (ROOT/'source-snapshots').glob('*.py.txt'):ast.parse(path.read_text(encoding='utf-8-sig'),filename=path.name)
    for path in ROOT.rglob('*.md'):
        for raw in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            url=raw.strip('<>')
            if urlsplit(url).scheme or url.startswith('#'):continue
            target=(path.parent/unquote(url.split('#',1)[0])).resolve()
            require(target.is_relative_to(ROOT.parents[1]) and target.exists(),path.name+': missing '+raw)
    print(json.dumps({'status':'PASS','checks':checks,'scope':'Offline consistency; not a hardware re-run'}))

if __name__=='__main__':main()
