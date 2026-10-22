#!/usr/bin/env python3
"""Update VulnLab KEV + recent NVD + EPSS, using only stdlib.

Safeguards:
- failed source retains last good data; does not claim success
- CVE metadata only, no generated fixes or exploit descriptions
- NVD pulls last 7 days, capped at 500 recent records
- EPSS batched for a bounded relevant subset of CVEs (not bulk mirroring)
"""
from __future__ import annotations
import datetime as dt
import json
import os
import pathlib
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / 'data' / 'feed-data.js'
PREVIOUS = ROOT / 'data' / 'feed-data.json'
UTC = dt.timezone.utc


def get_json(url: str, headers: dict | None = None):
    req = urllib.request.Request(url, headers={
        'User-Agent': 'VulnLabStudy/4.0 (+https://github.com/; educational feed synchronizer)',
        'Accept': 'application/json',
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=35) as response:
        if response.status != 200:
            raise RuntimeError(f'HTTP {response.status}')
        return json.load(response)


def last_good():
    if PREVIOUS.exists():
        try:
            old = json.loads(PREVIOUS.read_text(encoding='utf-8'))
            if isinstance(old, dict):
                return old
        except (ValueError, OSError):
            pass
    return {'updated': None, 'kevDate': None, 'nvdDate': None, 'epssDate': None,
            'kev': [], 'nvd': [], 'epss': {}, 'status': {}}


def nvd_score(cve):
    metrics = cve.get('metrics') or {}
    for name in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'):
        entries = metrics.get(name) or []
        if entries:
            rank = sorted(entries,key=lambda x: 0 if x.get('type')=='Primary' else 1)
            d = rank[0].get('cvssData') or {}
            return d.get('baseScore'),d.get('baseSeverity') or rank[0].get('baseSeverity')
    return None,None


def update_kev(out):
    urls = [
        'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    ]
    errors=[]
    for url in urls:
        try:
            obj=get_json(url)
            records=obj['vulnerabilities']
            if not isinstance(records,list) or len(records)<100:
                raise RuntimeError('KEV dataset too small/invalid')
            out['kev']=[{
                'id':x.get('cveID'), 'title':x.get('vulnerabilityName'),
                'vendor':x.get('vendorProject'), 'product':x.get('product'),
                'description':x.get('shortDescription'), 'action':x.get('requiredAction'),
                'date':x.get('dateAdded'), 'ransomware':x.get('knownRansomwareCampaignUse'),
                'cwes':x.get('cwes') or [],
            } for x in records if str(x.get('cveID','')).startswith('CVE-')]
            out['kev'].sort(key=lambda x:x.get('date') or '',reverse=True)
            out['kevDate']=obj.get('dateReleased') or dt.datetime.now(UTC).isoformat()
            out['status']['kev']=f'OK: {len(out["kev"])} CVE (CISA)'
            print(out['status']['kev'])
            return
        except Exception as exc:
            errors.append(f'{type(exc).__name__}: {exc}')
    out['status']['kev']='FAILED (kept last good): '+'; '.join(errors)[:400]
    print(out['status']['kev'])


def update_nvd(out):
    end=dt.datetime.now(UTC)
    start=end-dt.timedelta(days=7)
    params={'pubStartDate':start.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'pubEndDate':end.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'resultsPerPage':500,'startIndex':0}
    url='https://services.nvd.nist.gov/rest/json/cves/2.0?'+urllib.parse.urlencode(params)
    headers={}
    if os.getenv('NVD_API_KEY'):
        headers['apiKey']=os.environ['NVD_API_KEY']
    try:
        result=get_json(url,headers)
        records=[]
        for wrapper in result.get('vulnerabilities',[]):
            c=wrapper.get('cve') or {}
            cid=c.get('id')
            if not isinstance(cid,str) or not cid.startswith('CVE-'):
                continue
            en=next((d.get('value','') for d in c.get('descriptions',[]) if d.get('lang')=='en'),'')
            score,severity=nvd_score(c)
            cwes=[]
            for item in c.get('weaknesses',[]):
                for desc in item.get('description',[]):
                    value=desc.get('value')
                    if value and value.startswith('CWE-') and value not in cwes:
                        cwes.append(value)
            records.append({'id':cid,'title':cid,'description':en[:1700],
                            'date':c.get('published'),'severity':severity,
                            'cvss':score,'cwes':cwes[:5]})
        if not records:
            raise RuntimeError('Empty NVD response')
        records.sort(key=lambda x:x.get('date') or '',reverse=True)
        out['nvd']=records
        out['nvdDate']=end.isoformat()
        out['status']['nvd']=f'OK: {len(records)} recent CVEs; total in 7d window {result.get("totalResults", "?")} (display cap 500)'
        print(out['status']['nvd'])
    except Exception as exc:
        out['status']['nvd']=f'FAILED (kept last good): {type(exc).__name__}: {str(exc)[:280]}'
        print(out['status']['nvd'])


def chunks(items,max_chars=1850):
    group=[]; n=0
    for item in items:
        if n+len(item)+1>max_chars and group:
            yield group;group=[];n=0
        group.append(item);n+=len(item)+1
    if group: yield group


def update_epss(out):
    ids=[]
    for item in out.get('nvd',[])[:100]+out.get('kev',[])[:110]:
        i=item.get('id')
        if i and i not in ids: ids.append(i)
    ids += [i for i in ['CVE-2025-32463','CVE-2024-6387','CVE-2025-53770','CVE-2023-34362','CVE-2021-44228'] if i not in ids]
    if not ids:
        out['status']['epss']='SKIPPED: no CVEs';return
    scores=dict(out.get('epss') or {});succeeded=0
    for group in chunks(ids):
        try:
            url='https://api.first.org/data/v1/epss?'+urllib.parse.urlencode({'cve':','.join(group),'limit':200})
            response=get_json(url)
            for item in response.get('data',[]):
                try: scores[item['cve']]=float(item['epss']);succeeded+=1
                except (KeyError,ValueError,TypeError): pass
        except Exception as exc:
            print('EPSS batch failed:',type(exc).__name__,str(exc)[:160])
        time.sleep(.7)
    if succeeded:
        out['epss']={k:v for k,v in scores.items() if k in ids}
        out['epssDate']=dt.datetime.now(UTC).isoformat()
        out['status']['epss']=f'OK: {succeeded} EPSS records (subset)'
    else:
        out['status']['epss']='FAILED or no EPSS values (kept last good)'
    print(out['status']['epss'])


def main():
    out=last_good()
    out.setdefault('status',{})
    update_kev(out)
    update_nvd(out)
    update_epss(out)
    if not out.get('kev') and not out.get('nvd'):
        print('No valid feed records available. Keeping existing outputs unchanged.')
        raise SystemExit(1)
    out['updated']=dt.datetime.now(UTC).isoformat()
    PREVIOUS.parent.mkdir(parents=True,exist_ok=True)
    # Script-safe escaping is important: titles/descriptions are remote untrusted data.
    body=json.dumps(out,ensure_ascii=False,separators=(',',':')).replace('</','<\\/')
    OUT.write_text('window.VULNLAB_FEED = '+body+';\n',encoding='utf-8')
    PREVIOUS.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Updated:',OUT)

if __name__=='__main__':
    main()
