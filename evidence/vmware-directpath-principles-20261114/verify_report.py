"""Offline report, source and evidence consistency; no ESXi connection or mutation."""
import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote,urlsplit

ROOT=Path(__file__).resolve().parent
REPO=ROOT.parents[1]
checks=0
def require(condition,label):
    global checks
    checks+=1
    if not condition:raise AssertionError(label)
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    manifest=read(ROOT/'manifest.json')
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and p!=ROOT/'manifest.json' and '__pycache__' not in p.parts}
    require(actual=={r['path'] for r in manifest['files']},'Manifest coverage')
    for r in manifest['files']:
        p=(ROOT/r['path']).resolve();require(p.is_relative_to(ROOT),'Path boundary')
        require(p.stat().st_size==r['bytes'] and digest(p)==r['sha256'],r['path'])
    sources=read(ROOT/'sources.json')['sources'];claims=read(ROOT/'claims.json')['claims']
    ids={s['id'] for s in sources};claim_ids={c['id'] for c in claims}
    require(len(ids)==len(sources)==29,'Source identities')
    require(len(claim_ids)==len(claims)==30,'Claim identities')
    for s in sources:
        require(bool(s['scope']) and urlsplit(s['url']).scheme=='https','Source scope and URL')
        if 'repoPath' in s:
            p=(REPO/s['repoPath']).resolve();require(p.is_relative_to(REPO),'Source path boundary')
            revision=re.search(r'/blob/([0-9a-f]{40})/',s['url'])
            data=None
            if revision:
                try:data=subprocess.check_output(['git','show',revision[1]+':'+s['repoPath']],cwd=REPO,stderr=subprocess.DEVNULL)
                except (OSError,subprocess.CalledProcessError):pass
            if data is None:data=p.read_bytes()
            require(hashlib.sha256(data).hexdigest()==s['sha256'],'Pinned source '+s['id'])
    for c in claims:
        require(set(c['sources'])<=ids and bool(c['sources']),'Claim source '+c['id'])
        require(all(c[k] for k in ['scope','limitation','evidenceKinds','productImplication']),'Claim limits '+c['id'])
    body=(ROOT/'REPORT.md').read_text(encoding='utf-8')
    require(set(re.findall(r'\[(C\d{2})\]',body))==claim_ids,'Report claim references')
    require(not any(x in body for x in ['[[FIGURE','[[CLAIMS]]','[[SOURCES]]']),'No authoring placeholders')
    for p in [ROOT/'README.md',ROOT/'REPORT.md']:
        for link in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if urlsplit(link).scheme or link.startswith('#'):continue
            require((p.parent/unquote(link.split('#')[0])).exists(),'Local link '+link)
    qa=read(ROOT/'qa.json');pdf=ROOT/qa['pdf']
    require(qa['status']=='PASS' and qa['visualReview']['reviewedPages']==list(range(1,qa['pages']+1)),'Every PDF page reviewed')
    require(qa['pages']==17 and digest(pdf)==qa['pdfSha256'],'Reviewed exact PDF')
    require(digest(ROOT/'REPORT.md')==qa['reportSha256'],'Reviewed report text')
    require(pdf.read_bytes().startswith(b'%PDF-'),'PDF signature')
    obs=read(ROOT/'observations/release-fault-review.json')
    require(not obs['newRuntimeExperiment'],'Historical observation labelled')
    require(obs['outcomes']['releaseTaskSucceeded'] and not obs['outcomes']['healthySiblingPowerOnSucceeded'],'Release versus allocatability')
    require(obs['afterRelease']['allActive'] and obs['afterRelease']['dynamicCandidateCounts']['e1000e']>0,'Candidate remains advertised')
    require(obs['guestRecovery']['dmaPassCount']>=1 and obs['outcomes']['freshEduRecoveredWithoutHostOrQemuRestart'],'Functional recovery scope')
    require(not obs['semantics']['explicitVendorQuarantineStateObserved'],'No invented internal quarantine state')
    hist=read(ROOT/'observations/host-dpdk-context.json');require(not hist['newRuntimeExperiment'],'DPDK historical scope')
    require('Enhanced DirectPath' in body and '未实测' in body,'Enhanced evidence boundary present')
    ast.parse((ROOT/'verify_report.py').read_text(encoding='utf-8'))
    print(json.dumps({'status':'PASS','checks':checks,'claims':len(claims),'sources':len(sources),'scope':'Report consistency; not a new hardware acceptance run'}))

if __name__=='__main__':main()
