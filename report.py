"""Report generation — spec 12, 13, 15. Human + machine output with redaction."""
import json, csv, time, os
from datetime import datetime
from pathlib import Path
from .redact import redact, safe_fingerprint

REPORTS_DIR=Path(os.path.expanduser("~/sec-osint/reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SEVERITY_ORDER={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
LABEL={s:f"[{s}]" for s in SEVERITY_ORDER}

def _sort(findings): return sorted(findings,key=lambda f:SEVERITY_ORDER.get(f.get("severity","INFO"),4))

def print_human(findings):
    if not findings: print("ℹ️ No findings."); return
    for f in _sort(findings):
        sev=LABEL.get(f.get("severity","INFO"),"[INFO]")
        target=f.get("target","")
        ft=f.get("finding_type",f.get("type","finding"))
        conf=f.get("confidence",0)
        exp=f.get("exposure_class","").replace("_"," ").title()
        ev=safe_fingerprint(f.get("evidence",""),200)
        rem=f.get("remediation","Review exposure.")
        print(f"\n{sev} Potential {exp} at {target}")
        print(f"Finding: {ft}")
        print(f"Evidence: {ev}")
        print(f"Confidence: {conf:.0%}")
        print(f"Remediation: {rem}")

def generate_json_report(findings, output_path=None):
    data={"generated":datetime.utcnow().isoformat()+"Z","count":len(findings),"findings":_sort(findings)}
    if output_path:
        Path(output_path).write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
        return f"✅ JSON report: {output_path}"
    return json.dumps(data,indent=2,ensure_ascii=False)

def generate_csv_report(findings, output_path=None):
    cols=["id","target","finding_type","severity","confidence","exposure_class","evidence","search_query","fingerprint","timestamp","remediation"]
    rows=[]
    for i,f in enumerate(_sort(findings)):
        rows.append([i+1,f.get("target",""),f.get("finding_type",f.get("type","")),f.get("severity",""),f.get("confidence",0),f.get("exposure_class",""),safe_fingerprint(f.get("evidence",""),300),safe_fingerprint(f.get("query",""),200),safe_fingerprint(f.get("fingerprint",""),300),f.get("timestamp",datetime.utcnow().isoformat()+"Z"),safe_fingerprint(f.get("remediation",""),200)])
    if output_path:
        with open(output_path,"w",newline="",encoding="utf-8") as w:
            writer=csv.writer(w); writer.writerow(cols); writer.writerows(rows)
        return f"✅ CSV report: {output_path}"
    return "\n".join(",".join(map(str,r)) for r in [cols]+rows)

def generate_markdown_report(findings, target="", output_path=None):
    findings=_sort(findings)
    lines=[
        "# Security OSINT Assessment Report",
        "",
        f"**Target:** {target or 'Multiple'}  ",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Findings:** {len(findings)}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This report summarizes publicly indexed security signals for **{target or 'the specified targets'}**. All findings are derived from passive, publicly accessible sources. No private data was accessed, downloaded, or validated. No authentication or exploitation was performed.",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]
    for i,f in enumerate(findings,1):
        sev=f.get("severity","INFO"); lbl=LABEL.get(sev,"[INFO]")
        lines+=[
            f"### {i}. {lbl} {f.get('finding_type',f.get('type','finding')).replace('_',' ').title()}",
            "",
            f"**Target:** {f.get('target','')}  ",
            f"**Severity:** {sev}  ",
            f"**Confidence:** {f.get('confidence',0):.0%}  ",
            f"**Exposure Class:** {f.get('exposure_class','').replace('_',' ').title()}  ",
            f"**Evidence URL:** {safe_fingerprint(f.get('evidence',''),250)}  ",
            f"**Search Query:** {safe_fingerprint(f.get('query',''),250)}  ",
            f"**Fingerprint:** {safe_fingerprint(f.get('fingerprint',''),300)}  ",
            f"**Timestamp:** {f.get('timestamp',datetime.utcnow().isoformat()+'Z')}  ",
            "",
            "#### Technical Explanation",
            f"A publicly indexed signal was identified via search query **`{safe_fingerprint(f.get('query',''))}`** indicating **{f.get('exposure_class','').replace('_',' ')}** at **{f.get('target','')}**.",
            "",
            "#### Business Risk",
            f"Exposure class **{f.get('exposure_class','')}** may allow unauthorized access to {f.get('exposure_class','').replace('_',' ')}. Confidence: **{f.get('confidence',0):.0%}**.",
            "",
            "#### Recommended Remediation",
            f"{f.get('remediation','Review and restrict the exposed resource.')}",
            "",
            "#### Validation Steps",
            f"1. Verify the evidence URL: {safe_fingerprint(f.get('evidence',''),250)}  ",
            f"2. Confirm the finding type matches {f.get('exposure_class','')}  ",
            f"3. Apply remediation per above  ",
            "",
            "---",
            "",
        ]
    lines+=["## Responsible Disclosure","", "If you are the affected organization, please contact your security team or use your official disclosure channel (security.txt, security@, bug bounty platform). We have intentionally not accessed, downloaded, or validated any private data. We recommend reviewing the affected resources and performing an authorized security assessment.", "", "---", "", "## Evidence Handling Notes", "", "- All evidence URLs are publicly indexed and were not authenticated. - Secret values are redacted as `[REDACTED_SECRET]`. - No credentials, tokens, PII, or private documents were collected or stored. - Findings are deduplicated by (target, fingerprint, URL) hash."]
    md="\n".join(lines)
    if output_path:
        Path(output_path).write_text(md,encoding="utf-8")
        return f"✅ Markdown report: {output_path}"
    return md

def batch_dedup(findings):
    """Group by (exposure_class, technology, fingerprint) for multi-company mode."""
    groups={}
    for f in findings:
        key=(f.get("exposure_class",""), f.get("technology",""), f.get("fingerprint","")[:80])
        groups.setdefault(key,[]).append(f)
    return groups

def batch_summary(groups):
    lines=[]
    for (exp,tech,fp),items in groups.items():
        sev_counts={}
        for f in items: sev_counts[f.get("severity","INFO")]=sev_counts.get(f.get("severity","INFO"),0)+1
        targets=sorted(set(f.get("target","") for f in items))
        lines.append(f"\n{len(items)} findings | {exp.replace('_',' ').title()} | Tech: {tech or '—'} | Targets: {', '.join(targets[:5])}{'…' if len(targets)>5 else ''}")
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if s in sev_counts: lines.append(f"  {s}: {sev_counts[s]}")
    return "\n".join(lines)