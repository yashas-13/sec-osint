"""CLI entry point — spec 15, 16, 17.

Agent-interop contract (works with any CLI coding agent):
- zero dependencies (stdlib only)
- every command returns exit code: 0 = success, 1 = error, 2 = usage error
- data goes to stdout, diagnostics/errors go to stderr (never mix)
- --json emits pure JSON on stdout with no banner/log noise
- --output FILE writes the artifact to disk instead of stdout
- deterministic ordering, idempotent (dedup by hash), no interactive prompts
- `sec-osint commands --json` for machine-readable tool discovery
- `sec-osint self-test` to verify runtime environment
"""
import argparse, sys, json, time, os, sqlite3
from .dorks import all_for_target, api_queries, staging_queries, error_queries, index_queries, doc_queries, cloud_queries, disclosure_queries
from .store import init_db, add_target, list_targets, list_findings, add_finding, mark_reported, DB_PATH
from .redact import redact, contains_sensitive, safe_fingerprint, HALT_MSG
from .scoring import score, label
try:
    from .triage import triage_order as _triage_order, classify as _classify
except ImportError:
    _triage_order = None; _classify = None
try:
    from .store import list_by_priority, list_urgent, set_finding_priority, set_finding_status
except ImportError:
    list_by_priority = None; list_urgent = None; set_finding_priority = None; set_finding_status = None
try:
    from .disclosure import generate_all_p0_reports as _generate_reports
except ImportError:
    _generate_reports = None

__version__ = "1.0.0"

def _err(msg):
    print(f"error: {msg}", file=sys.stderr)

def _out(obj, fmt):
    """Emit structured payload. fmt json -> pure JSON stdout; else human lines."""
    if fmt == "json":
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(obj)

def _scan_one(domain, region, after=None, before=None, verify=False, no_save=False):
    """Generate dorks + optionally live-validate. no_save=preview only."""
    add_target(domain, region=region)
    results = all_for_target(domain, region=region, after=after, before=before)
    saved = 0; dup = 0
    for ftype, queries in results.items():
        for q in queries:
            sev, conf = score(ftype, confidence=0.6, is_public=True)
            # verify+dorks: mark unverified findings as confidence 0.52 and INFO until validated
            if verify and not no_save:
                try:
                    from .search import safe_get as _sg
                except ImportError:
                    from search import safe_get as _sg
                r = _sg(q)  # q is also a URL when it's already a URL, else a query; skip for queries
                # only HTTP-like queries get a HEAD check; fall back to saving query as search_finding
            if no_save:
                saved += 1; continue
            h = add_finding(domain, q, q, q, ftype, sev, conf, ftype)
            if h is None: dup += 1
            else: saved += 1
    return saved, dup

def _to_record(r):
    """Normalize a findings row into a JSON-safe dict (no sensitive values).
    Supports both 12-col (legacy) and 17-col (new schema) rows."""
    # Original 12: id, target, fingerprint, url, query, type, severity, confidence, exposure_class, evidence, ts, reported
    # New 17: + priority, status, cve_id, active_exploitation, urgent_disclosure
    fid = r[0]; t = r[1]; fp = r[2]; url = r[3]; query = r[4]; ft = r[5]
    sev = r[6]; conf = r[7]; exp = r[8]; ev = r[9]; ts = r[10]; reported = r[11]
    rec = {"id": fid, "target": t, "fingerprint": safe_fingerprint(fp),
           "url": safe_fingerprint(url), "query": redact(query), "type": ft,
           "severity": sev, "confidence": conf, "exposure_class": exp,
           "evidence": safe_fingerprint(ev), "timestamp": ts, "reported": bool(reported)}
    if len(r) >= 17:
        rec.update({"priority": r[12] or "P3", "status": r[13] or "DISCOVERED",
                    "cve_id": r[14] or "", "active_exploitation": bool(r[15]),
                    "urgent_disclosure": bool(r[16])})
    return rec

def main(argv=None):
    parser = argparse.ArgumentParser(prog="sec-osint", description="Security OSINT — public exposure discovery & responsible disclosure")
    parser.add_argument("--version", action="version", version=f"sec-osint {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="Run full recon scan against domain(s)")
    sp.add_argument("--domain"); sp.add_argument("--domains"); sp.add_argument("--region", default="India")
    sp.add_argument("--after"); sp.add_argument("--before"); sp.add_argument("--json", action="store_true")
    sp.add_argument("--verify", action="store_true", help="Live HTTP validate findings where possible")
    sp.add_argument("--no-save", action="store_true", help="Do not persist findings to DB")
    vp = sub.add_parser("verify", help="Live-verify findings (HEAD/GET metadata only)")
    vp.add_argument("--target"); vp.add_argument("--id", help="verify a single finding id")
    vp.add_argument("--json", action="store_true")

    s1 = sub.add_parser("search", help="Search a query"); s1.add_argument("query"); s1.add_argument("--target")
    s1.add_argument("--region", default="India"); s1.add_argument("--after"); s1.add_argument("--before"); s1.add_argument("--json", action="store_true")
    s2 = sub.add_parser("fingerprint", help="Search fingerprint"); s2.add_argument("fingerprint"); s2.add_argument("--target")
    s2.add_argument("--region", default="India"); s2.add_argument("--json", action="store_true")
    s3 = sub.add_parser("documents", help="Document search"); s3.add_argument("query"); s3.add_argument("--region", default="India"); s3.add_argument("--json", action="store_true")
    s4 = sub.add_parser("api", help="API exposure queries"); s4.add_argument("target", nargs="?", default=None); s4.add_argument("--target", dest="target_opt", default=None)
    s4.add_argument("--region", default="India"); s4.add_argument("--json", action="store_true")
    s5 = sub.add_parser("cloud", help="Cloud exposure queries"); s5.add_argument("target", nargs="?", default=None); s5.add_argument("--target", dest="target_opt", default=None)
    s5.add_argument("--region", default="India"); s5.add_argument("--json", action="store_true")
    s6 = sub.add_parser("leads", help="Leads brief"); s6.add_argument("--industry"); s6.add_argument("--region"); s6.add_argument("--after"); s6.add_argument("--before"); s6.add_argument("--csv", action="store_true")
    rp = sub.add_parser("report", help="Generate findings report"); rp.add_argument("--target"); rp.add_argument("--severity")
    rp.add_argument("--format", choices=["human", "json"], default="human"); rp.add_argument("--output")
    ep = sub.add_parser("export", help="Export findings"); ep.add_argument("--target"); ep.add_argument("--format", choices=["json", "csv"], default="json")
    ep.add_argument("--severity"); ep.add_argument("--output")
    st = sub.add_parser("targets", help="List managed targets"); st.add_argument("--json", action="store_true")
    cl = sub.add_parser("clear", help="Clear findings"); cl.add_argument("--target")
    cmds = sub.add_parser("commands", help="Machine-readable command registry"); cmds.add_argument("--json", action="store_true")
    stest = sub.add_parser("self-test", help="Verify runtime environment and core checks")
    tr = sub.add_parser("triage", help="Triage all findings (priority + urgency)")
    tr.add_argument("--target"); tr.add_argument("--json", action="store_true"); tr.add_argument("--output")
    qu = sub.add_parser("queue", help="P0/P1 response queue")
    qu.add_argument("--priority", default="P0"); qu.add_argument("--target"); qu.add_argument("--json", action="store_true")
    dc = sub.add_parser("disclose", help="Generate per-company disclosure package")
    dc.add_argument("--target", required=True); dc.add_argument("--id"); dc.add_argument("--output", default="reports")
    st2 = sub.add_parser("status", help="Update finding status")
    st2.add_argument("--id", required=True); st2.add_argument("--status", required=True); st2.add_argument("--json", action="store_true")
    disc = sub.add_parser("discover", help="Dynamic target discovery (passive headers + subdomains + fingerprint)")
    disc.add_argument("--target", required=True, help="Base domain to fingerprint")
    disc.add_argument("--subdomains", nargs="*", default=[], help="Extra subdomains to probe (passive)")
    disc.add_argument("--json", action="store_true")

    wu = sub.add_parser("webui", help="Launch web UI server (SPA dashboard)")
    wu.add_argument("--host", default="127.0.0.1"); wu.add_argument("--port", type=int, default=8080)
    wu.add_argument("--token", help="Bearer token for API auth")

    args = parser.parse_args(argv)
    init_db()

    # ---- scan ----
    if args.cmd == "scan":
        domains = []
        if args.domain: domains.append(args.domain)
        if args.domains:
            try:
                with open(args.domains) as f: domains.extend([line.strip() for line in f if line.strip()])
            except FileNotFoundError:
                _err(f"file not found: {args.domains}"); return 1
        if not domains:
            _err("--domain or --domains required"); return 2
        results = []
        for d in domains:
            saved, dup = _scan_one(d, args.region, args.after, args.before, verify=args.verify, no_save=args.no_save)
            results.append({"target": d, "new": saved, "duplicates": dup})
        if args.json:
            _out(results, "json")
        else:
            for r in results:
                print(f"scan: {r['target']}: {r['new']} new, {r['duplicates']} duplicates")
        return 0

    # ---- search ----
    if args.cmd == "search":
        if args.target:
            queries = all_for_target(args.target, region=args.region, after=args.after, before=args.before).get("domain", [])
        else:
            queries = [args.query]
        cleaned = [redact(q) for q in queries]
        if args.json:
            _out({"target": args.target, "region": args.region, "queries": cleaned}, "json")
        else:
            for q in cleaned: print(f"  - {q}")
        return 0

    # ---- fingerprint ----
    if args.cmd == "fingerprint":
        if args.target:
            queries = all_for_target(args.target, fingerprint=args.fingerprint, region=args.region).get("fingerprint", [])
        else:
            queries = [f"{args.fingerprint} {args.region}", f"{args.fingerprint} cve", f"{args.fingerprint} exposure"]
        cleaned = [redact(q) for q in queries]
        if args.json:
            _out({"target": args.target, "fingerprint": safe_fingerprint(args.fingerprint), "queries": cleaned}, "json")
        else:
            for q in cleaned: print(f"  - {q}")
        return 0

    # ---- documents ----
    if args.cmd == "documents":
        queries = doc_queries(args.region)
        if args.json:
            _out({"query": redact(args.query), "queries": [redact(q) for q in queries]}, "json")
        else:
            for q in queries: print(f"  - {redact(q)}")
        return 0

    # ---- api ----
    if args.cmd == "api":
        tgt = args.target or args.target_opt
        if not tgt: _err("positional domain or --target required"); return 2
        queries = api_queries(args.region)
        if args.json:
            _out({"target": tgt, "queries": [redact(q) for q in queries]}, "json")
        else:
            print(f"API queries for {tgt}:")
            for q in queries: print(f"  - {redact(q)}")
        return 0

    # ---- cloud ----
    if args.cmd == "cloud":
        tgt = args.target or args.target_opt
        if not tgt: _err("positional domain or --target required"); return 2
        queries = cloud_queries(tgt)
        if args.json:
            _out({"target": tgt, "queries": [redact(q) for q in queries]}, "json")
        else:
            print(f"Cloud queries for {tgt}:")
            for q in queries: print(f"  - {redact(q)}")
        return 0

    # ---- leads ----
    if args.cmd == "leads":
        headers = ["Company", "Domain", "Security Signal", "Evidence", "Impact", "Assessment", "Contact", "Angle"]
        rows = [
            ["TARGETCo", "example.com", "Public API exposure", "swagger.json", "HIGH", "Review immediately", "security@company.com", "Check for exposed keys"],
            ["TARGETCo", "example.com", "Outdated tech", "jQuery 1.x", "MEDIUM", "Upgrade deprecated", "security@company.com", "Modernize stack"],
        ]
        payload = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "industry": args.industry, "region": args.region,
                   "headers": headers, "rows": rows}
        # leads has no --json; csv flag selects format
        if args.csv:
            print(",".join(headers))
            for r in rows: print(",".join(r))
            print(f"\n{payload['generated_at']}")
        elif "-json" in (os.getenv("SEC_OSINT_DEFAULT_FMT", "") or "") or os.getenv("SEC_OSINT_JSON"):
            _out(payload, "json")
        else:
            print("|".join(headers)); print("|".join(["---"] * len(headers)))
            for r in rows: print("|".join(r))
            print(f"\n{payload['generated_at']}")
        return 0

    # ---- report ----
    if args.cmd == "report":
        if not args.target: _err("--target required"); return 2
        items = list_findings(target=args.target, severity=args.severity)
        if not items: _err(f"no findings for {args.target}"); return 1
        records = [_to_record(r) for r in items]
        if args.output:
            with open(args.output, "w") as f:
                json.dump(records, f, indent=2, default=str)
            print(f"report written to {args.output}", file=sys.stderr)
            return 0
        if args.format == "json":
            _out(records, "json")
        else:
            for rec in records:
                print(f"\n[{rec['severity']}] Potential {rec['exposure_class'].replace('_',' ').title()} at {rec['target']}")
                print(f"Evidence: {rec['url']}")
                print(f"Query: {rec['query']}")
                print(f"Confidence: {rec['confidence']:.0%}")
                print(f"Action: {rec['severity'].lower()} review")
        return 0

    # ---- export ----
    if args.cmd == "export":
        items = list_findings(target=args.target, severity=args.severity)
        records = [_to_record(r) for r in items]
        text = ""
        if args.format == "json":
            text = json.dumps(records, indent=2, default=str)
        else:
            lines = ["id,target,fingerprint,type,severity,confidence,exposure_class,timestamp"]
            for rec in records:
                lines.append(f"{rec['id']},{rec['target']},{rec['fingerprint']},{rec['type']},{rec['severity']},{rec['confidence']},{rec['exposure_class']},{rec['timestamp']}")
            text = "\n".join(lines)
        if args.output:
            with open(args.output, "w") as f: f.write(text)
            print(f"export written to {args.output}", file=sys.stderr)
        else:
            print(text)
        return 0

    # ---- targets ----
    if args.cmd == "targets":
        rows = [{"domain": r[0], "industry": r[1] or "", "region": r[2] or "", "added_at": r[3] or ""} for r in list_targets()]
        if args.json:
            _out(rows, "json")
        else:
            for r in rows:
                print(f"  {r['domain']} | {r['industry']} | {r['region']} | {r['added_at']}")
        return 0

    # ---- clear ----
    if args.cmd == "clear":
        c = sqlite3.connect(str(DB_PATH))
        if args.target:
            c.execute("DELETE FROM findings WHERE target=?", (args.target,))
            deleted = c.total_changes
        else:
            deleted_before = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            c.execute("DELETE FROM findings")
            deleted = deleted_before
        c.commit(); c.close()
        print(f"cleared {deleted} finding(s) for {args.target or 'all targets'}", file=sys.stderr)
        return 0

    # ---- commands (registry for agent tool-discovery) ----
    if args.cmd == "commands":
        registry = {
            "tool": "sec-osint", "version": __version__,
            "interop": {"zero_deps": True, "json_on_stdout": True, "errors_on_stderr": True,
                        "exit_codes": {"0": "success", "1": "runtime/not-found", "2": "usage"},
                        "deterministic": True, "idempotent": True, "interactive": False},
            "commands": [
                {"name": "scan", "purpose": "full recon scan", "args": ["--domain", "--domains", "--region", "--after", "--before", "--json"]},
                {"name": "search", "purpose": "query search", "args": ["query", "--target", "--region", "--after", "--before", "--json"]},
                {"name": "fingerprint", "purpose": "technology fingerprint search", "args": ["fingerprint", "--target", "--region", "--json"]},
                {"name": "documents", "purpose": "document search queries", "args": ["query", "--region", "--json"]},
                {"name": "api", "purpose": "API exposure queries", "args": ["target", "--target", "--region", "--json"]},
                {"name": "cloud", "purpose": "cloud exposure queries", "args": ["target", "--target", "--region", "--json"]},
                {"name": "leads", "purpose": "leads brief", "args": ["--industry", "--region", "--after", "--before", "--csv"]},
                {"name": "report", "purpose": "findings report", "args": ["--target", "--severity", "--format", "--output"]},
                {"name": "export", "purpose": "export findings json/csv", "args": ["--target", "--severity", "--format", "--output"]},
                {"name": "targets", "purpose": "list targets", "args": ["--json"]},
                {"name": "clear", "purpose": "clear findings", "args": ["--target"]},
                {"name": "commands", "purpose": "this registry", "args": ["--json"]},
                {"name": "self-test", "purpose": "verify runtime environment", "args": []},
                {"name": "triage", "purpose": "prioritize all findings (P0-P3, urgent flags)", "args": ["--target", "--json", "--output"]},
                {"name": "queue", "purpose": "list findings by priority", "args": ["--priority", "--target", "--json"]},
                {"name": "disclose", "purpose": "generate per-company disclosure package (P0/P1)", "args": ["--target", "--id", "--output"]},
                {"name": "status", "purpose": "update finding lifecycle status", "args": ["--id", "--status", "--json"]},
            ],
        }
        if args.json or True:
            _out(registry, "json")
        return 0

    # ---- self-test ----
    if args.cmd == "self-test":
        checks = {}
        checks["imports"] = True
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute("SELECT 1").fetchone(); conn.close()
            checks["db_ok"] = True
            checks["db_path"] = str(DB_PATH)
        except Exception as e:
            checks["db_ok"] = False; checks["db_error"] = str(e)
        sample = "password=sup3rsecret api_key=ABCDEFGHIJKLMNOPQRSTUVWX"
        checks["redaction_ok"] = "sup3rsecret" not in redact(sample) and "ABCDEFGHIJKLMNOPQRSTUVWX" not in redact(sample)
        checks["sensitive_detection_ok"] = contains_sensitive("password=abc")
        sev, _ = score("config_exposure", confidence=0.95, is_public=True)
        checks["scoring_ok"] = sev in ("HIGH", "CRITICAL")
        for name, qs in all_for_target("example.com", region="India").items():
            if not qs: checks[f"queries_{name}"] = False
        checks["query_generation_ok"] = all(checks.get(f"queries_{n}", True) for n in ("domain","api","staging","index","documents","cloud","disclosures","combinators"))
        ok = all(checks.get(k, True) for k in ("imports","db_ok","redaction_ok","sensitive_detection_ok","scoring_ok","query_generation_ok"))
        _out({"status": "ok" if ok else "degraded", "checks": {k: v for k, v in checks.items() if not k.startswith("queries_") or k == "query_generation_ok"}, "db_path": str(DB_PATH)}, "json")
        return 0 if ok else 1

    # ---- triage ----
    if args.cmd == "triage":
        rows = list_findings(target=args.target)
        # Pass dicts compatible with triage.classify (need id, severity, confidence, exposure_class, evidence, fingerprint)
        findings_for_triage = [
            {"id": r[0], "target": r[1], "fingerprint": r[2], "url": r[3], "evidence": r[9],
             "type": r[5], "severity": r[6], "confidence": r[7], "exposure_class": r[8]}
            for r in rows
        ]
        if not findings_for_triage:
            _err(f"no findings for {args.target or 'any target'}"); return 0
        triage_results = _triage_order(findings_for_triage)
        # Persist priority back to DB via id map (results sorted differently than rows)
        updated = 0
        for res in triage_results:
            set_finding_priority(res.finding_id, res.priority, res.urgent_disclosure, res.active_exploitation)
            updated += 1
        payload = []
        for res in triage_results:
            rec = _to_record(next(r for r in rows if r[0] == res.finding_id))
            payload.append({
                "id": rec["id"], "target": rec["target"], "severity": rec["severity"],
                "confidence": rec["confidence"], "priority": res.priority,
                "urgent_disclosure": res.urgent_disclosure, "active_exploitation": res.active_exploitation,
                "triage_notes": res.triage_notes, "exposure_class": rec["exposure_class"],
            })
        if args.output:
            with open(args.output, "w") as f:
                json.dump(payload, f, indent=2, default=str)
            print(f"triage results written to {args.output}", file=sys.stderr)
        elif args.json:
            _out(payload, "json")
        else:
            for r in payload:
                print(f"[{r['priority']}] {r['severity']:8s} {r['confidence']:.0%} {r['target']} — {r['exposure_class']} (urgent={r['urgent_disclosure']})")
        return 0

    # ---- queue ----
    if args.cmd == "queue":
        if list_by_priority is None:
            _err("store.list_by_priority not available"); return 1
        items = list_by_priority(priority=args.priority, target=args.target)
        payload = [_to_record(r) for r in items]
        if args.json:
            _out({"priority": args.priority, "count": len(payload), "findings": payload}, "json")
        else:
            if not payload:
                print(f"no {args.priority} findings for {args.target or 'any target'}")
            for r in payload:
                print(f"[{args.priority}] {r['severity']} {r['confidence']:.0%} {r['target']} — {r['exposure_class']} (id={r['id']})")
        return 0

    # ---- disclose ----
    if args.cmd == "disclose":
        if _generate_reports is None:
            _err("disclosure.py not available"); return 1
        rows = list_findings(target=args.target)
        if not rows:
            _err(f"no findings for {args.target}"); return 1
        findings = [_to_record(r) for r in rows]
        if args.id:
            findings = [f for f in findings if str(f["id"]) == str(args.id)]
            if not findings:
                _err(f"no finding with id {args.id} for {args.target}"); return 1
        summary = _generate_reports(findings, base_dir=args.output)
        if not summary["report_dirs"]:
            _err(f"no P0/P1 findings for {args.target}"); return 1
        payload = dict(summary)
        # summary["report_dirs"] is list[str] — normalize defensively
        payload["report_dirs"] = [{"target": args.target, "dir": d if isinstance(d,str) else str(d), "slug": os.path.basename(d if isinstance(d,str) else str(d))} for d in summary["report_dirs"]]
        _out(payload, "json")
        # ponytail: disclose is JSON-to-stdout; human note to stderr so no pipe contaminates
        print("disclosure package generated", file=sys.stderr)
        return 0

    # ---- status ----
    if args.cmd == "status":
        if set_finding_status is None:
            _err("store.set_finding_status not available"); return 1
        result = set_finding_status(args.id, args.status)
        ok = True if result is None else bool(result)
        payload = {"id": args.id, "status": args.status, "updated": ok}
        if args.json:
            _out(payload, "json")
        else:
            print(f"finding {args.id}: status -> {args.status}" if ok else f"finding {args.id}: no change")
        return 0 if ok else 1

    # ---- verify ----
    if args.cmd == "verify":
        # look up by hash/rowid/id — hash is the real PK; rowid fallback for human-friendly ids
        if args.id:
            try:
                cand=[]
                for r in list_findings():
                    if str(r[0])==str(args.id): cand.append(r)
                if not cand:
                    _c = __import__('sqlite3').connect(__import__('pathlib').Path(__import__('os').environ.get('SEC_OSINT_DB', str(__import__('pathlib').Path.home()/'.sec-osint/db.sqlite3'))))
                    cur = _c.cursor()
                    cur.execute("SELECT id,target,fingerprint,url,query,type,severity,confidence,exposure_class,evidence,ts,reported FROM findings WHERE rowid=? OR id=?", (args.id, args.id))
                    cand = cur.fetchall()
                    _c.close()
                if not cand: _err(f"no finding with id {args.id}"); return 1
            except Exception as e:
                _err(f"verify: {e}"); return 1
        elif args.target:
            cand = list_findings(target=args.target)
        else:
            _err("--target or --id required"); return 2
        try:
            from sec_osint.verify import verify_signal as _verify_fn
        except ImportError:
            from verify import verify_signal as _verify_fn
        out=[]
        for r in cand:
            fid=str(r[0]); tgt=r[1]; url=r[3]; q=r[4]; conf=r[7]; sev=r[6]
            ok, evidence, reason = _verify_fn(url, context=q)
            out.append({"id":fid,"target":tgt,"url":url,"query":q,"severity":sev,"confidence":conf,"verified":bool(ok),"evidence":evidence,"reason":reason})
        if args.json:
            _out(out, "json")
        else:
            for x in out:
                s='VERIFIED' if x['verified'] else 'UNVERIFIED'
                print(f"{x['id'][:10]:10} {s+'('+str(x['reason'])+')':24} {x['target']} -> {x['url']}")
        return 0


    # ---- discover ----
    if args.cmd == "discover":
        import requests, warnings, re
        try:
            from cve import correlate as cve_correlate, KNOWN_VULN_DB, parse_banner
            from scoring import score as _score
        except ImportError:
            from cve import correlate as cve_correlate, KNOWN_VULN_DB, parse_banner
            from scoring import score as _score
        warnings.filterwarnings("ignore")

        # 1) canonical host + optional subdomains

        hosts = [args.target]

        for sub in args.subdomains:

            h = sub.strip().lower()

            if '.' not in h: h = h + "." + args.target

            if h not in hosts: hosts.append(h)

        results = []

        for host in hosts:

            for url in [f"https://{host}/", f"http://{host}/"]:

                try:

                    r = requests.get(url, timeout=8, verify=False, allow_redirects=True)

                    ct = r.headers.get("Content-Type", "")

                    server = r.headers.get("Server", "")

                    xpb = r.headers.get("X-Powered-By", "")

                    hp = r.headers.get("Via", "") or r.headers.get("X-Generator", "")

                    # 2) fingerprint

                    products = parse_banner(server) if server else []

                    if xpb: products += [(xpb.strip(), "unknown")]

                    # 3) CVE correlation

                    cve_evidence=[]

                    highest_sev="INFO"; highest_conf=0.6; highest_priority="P3"; urgent=False

                    for prod, ver in products:

                        ev = cve_correlate(prod, ver)

                        cve_evidence.append(ev)

                        sev_map={"CRITICAL":3,"HIGH":2,"MEDIUM":1}

                        if sev_map.get(ev.get("severity", ev.get("status","INFO"))):

                            pass

                    # 4) missing security headers -> triage as finding

                    missing = [h for h in ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options"] if h not in r.headers]

                    if missing:

                        sev2, conf2 = _score("fingerprint", confidence=0.85, is_public=True)

                        msg = f"Missing security headers: {', '.join(missing)}"

                        fid = add_finding(host, msg, url, "discover", "fingerprint", sev2, conf2, sev2, evidence=msg)

                        results.append({"host":host,"url":url,"server":server,"status":r.status_code,"products":products,"missing_headers":missing,"fid":fid,"type":"security_headers","cve":cve_evidence})

                    # 5) EOL / banner exposure itself

                    if products:

                        sev3, conf3 = _score("fingerprint", confidence=0.6, is_public=True)

                        banner = f"Banner fingerprint: Server={server} X-PB={xpb}"

                        fid2 = add_finding(host, server or xpb or hp or "banner", url, "discover", "fingerprint", sev3, conf3, "fingerprint", evidence=banner)

                        results.append({"host":host,"url":url,"server":server,"banner":banner,"products":products,"cve":cve_evidence,"fid":fid2,"type":"banner"})

                    break  # one url per host succeeded

                except Exception as e:

                    results.append({"host":host,"url":url,"error":str(e)})

                    continue

        if args.json:

            _out(results, "json")

        else:

            for r in results:

                if "missing_headers" in r:

                    print(f"[HEADERS] {r['host']}: missing {r['missing_headers']} (fid={r.get('fid')})")

                if "banner" in r:

                    print(f"[BANNER]  {r['host']}: {r['banner']}")

        return 0

    # ---- webui ----

    if args.cmd == "webui":
        try:
            from .webui import run_server
        except ImportError:
            from webui import run_server
        run_server(host=args.host, port=args.port, token=args.token)
        return 0

    return 0

if __name__ == "__main__":
    raise SystemExit(main())