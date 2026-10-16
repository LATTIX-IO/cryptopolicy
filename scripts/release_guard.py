#!/usr/bin/env python3
"""Fail-closed release publishing guard for bootstrap workspace."""
import sys, tomllib, re
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[1]
class GuardFailure(ValueError): pass
def require(ok, msg):
    if not ok: raise GuardFailure(msg)
def check_workspace(root):
    doc = tomllib.loads((root/'Cargo.toml').read_text())
    members = doc['workspace']['members']
    require(isinstance(members,list) and len(members)>0, 'missing members')
    require(all(isinstance(m,str) and re.fullmatch(r'crates/[a-z0-9-]+',m) for m in members),'explicit crate names required')
    require(len(members)==len(set(members)), 'duplicate member')
    discovered = {p.parent.relative_to(root).as_posix() for p in (root/'crates').glob('*/Cargo.toml')}
    require(discovered==set(members), 'unlisted crate detected')
    names=[]
    for m in members:
        pkg=tomllib.loads((root/m/'Cargo.toml').read_text())['package']
        require(pkg.get('publish') is False, m+': publish must be false')
        names.append(pkg['name'])
    require(len(names)==len(set(names)),'duplicate package names')
    return sorted(names)
def workflow(text):
    value=yaml.load(text,Loader=yaml.BaseLoader)
    require(isinstance(value,dict),'invalid workflow')
    return value
def check_workflows(root):
    paths=list((root/'.github/workflows').glob('*.yml'))+list((root/'.github/workflows').glob('*.yaml'))
    flows={p.name:workflow(p.read_text()) for p in paths}
    require('release-publish.yml' in flows,'manual workflow missing')
    publish_jobs=[]
    for filename,flow in flows.items():
        on=flow.get('on')
        require(isinstance(on,(dict,list,str)),'missing triggers')
        events=set(on) if not isinstance(on,str) else {on}
        for name,job in flow.get('jobs',{}).items():
            steps=job.get('steps',[])
            release=any(('release-plz/action@' in str(s.get('uses','')) and (s.get('with') or {}).get('command')=='release') or re.search(r'\bcargo\s+publish\b|\brelease-plz\s+release\b',str(s.get('run',''))) for s in steps)
            if release: publish_jobs.append((filename,name,job))
            if filename!='release-publish.yml':
                require(not release,filename+': automatic publisher')
                require('CARGO_REGISTRY_TOKEN' not in str(job),filename+': registry token exposure')
            else: require(events=={'workflow_dispatch'},'publish trigger must be manual')
    require(len(publish_jobs)==1 and publish_jobs[0][:2]==('release-publish.yml','publish'),'exactly one guarded publisher required')
    flow=flows['release-publish.yml']
    require(set(flow['on'])=={'workflow_dispatch'},'publish must be manual only')
    confirm=flow['on']['workflow_dispatch']['inputs']['confirm']
    require(confirm.get('required')=='true' and confirm.get('type')=='string','confirmation input missing')
    job=publish_jobs[0][2]
    require(job.get('environment')=='crates-io-publish','release environment missing')
    cond=''.join(job.get('if','').split())
    for token in ["github.event_name=='workflow_dispatch'","github.repository=='LATTIX-IO/cryptopolicy'","github.ref=='refs/heads/main'","inputs.confirm=='PUBLISH'","vars.CRYPTOPOLICY_RELEASES_ENABLED=='true'"]:
        require(token in cond,'missing condition: '+token)
    require('CARGO_REGISTRY_TOKEN' in str(job['steps'][-1].get('env',{})),'registry credential missing from publisher')
def verify(root=ROOT):
    names=check_workspace(root)
    check_workflows(root)
    return names
if __name__=='__main__':
    try: print('PASS release guard:', ', '.join(verify()))
    except (GuardFailure, OSError, ValueError, KeyError, yaml.YAMLError) as exc:
        print('FAIL release guard:',exc,file=sys.stderr)
        sys.exit(1)
