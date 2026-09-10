#!/usr/bin/env python3
"""
sec-osint Web UI — stdlib HTTP server + SPA.
Zero deps. Serves index.html + /api/* JSON endpoints.
"""
import argparse, json, os, sys, sqlite3, threading, time
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ---- integrate core modules ----
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT.parent))
try:
    from sec_osint.store import (
        init_db, add_target, list_targets, list_findings, add_finding,
        mark_reported, set_finding_priority, set_finding_status,
        list_by_priority, list_urgent, DB_PATH, fingerprint_hash
    )
    from sec_osint.triage import triage_order, TriageResult
    from sec_osint.disclosure import generate_all_p0_reports, company_slug
    from sec_osint.cli import _scan_one, _to_record
    from sec_osint.scoring import score, priority
    from sec_osint.redact import safe_fingerprint, redact, contains_sensitive
except ModuleNotFoundError:
    from store import (
        init_db, add_target, list_targets, list_findings, add_finding,
        mark_reported, set_finding_priority, set_finding_status,
        list_by_priority, list_urgent, DB_PATH, fingerprint_hash
    )
    from triage import triage_order, TriageResult
    from disclosure import generate_all_p0_reports, company_slug
    from cli import _scan_one, _to_record
    from scoring import score, priority
    from redact import safe_fingerprint, redact, contains_sensitive

WEBUI_DIR = ROOT / "webui"
REPORTS_BASE = Path(os.path.expanduser("~/sec-osint/reports"))

TOKEN = None  # set from CLI


def require_auth(headers):
    if TOKEN is None:
        return True
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth[7:] == TOKEN


class APIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEBUI_DIR), **kwargs)

    def _send(self, status, data=None, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if data is not None:
            self.wfile.write(json.dumps(data, default=str).encode("utf-8"))

    def _bad(self, msg="bad request", code=400):
        self._send(code, {"error": msg})

    def _unauthorized(self):
        self._send(401, {"error": "unauthorized"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()

    def do_GET(self):
        if not require_auth(self.headers):
            return self._unauthorized()
        u = urlparse(self.path)
        if u.path == "/api/version":
            return self._send(200, {"version": "1.0.0", "service": "sec-osint webui"})

        if u.path == "/api/stats":
            return self._api_stats()

        if u.path == "/api/targets":
            return self._api_targets()

        if u.path == "/api/findings":
            q = parse_qs(u.query)
            t = q.get("target", [None])[0]
            sev = q.get("severity", [None])[0]
            pri = q.get("priority", [None])[0]
            lim = int(q.get("limit", [500])[0])
            rows = list_findings(target=t, severity=sev)
            if pri:
                rows = [r for r in rows if (r[12] or "P3").upper() == pri.upper()]
            return self._send(200, {"findings": [_to_record(r) for r in rows[:lim]]})

        if u.path == "/api/queue":
            q = parse_qs(u.query)
            pri = q.get("priority", ["P0"])[0]
            t = q.get("target", [None])[0]
            items = list_by_priority(priority=pri, target=t)
            return self._send(200, {"priority": pri, "count": len(items), "findings": [_to_record(r) for r in items]})

        if u.path == "/api/reports":
            q = parse_qs(u.query)
            t = q.get("target", [None])[0]
            return self._api_reports(t)

        if u.path.startswith("/api/reports/file"):
            q = parse_qs(u.query)
            p = q.get("path", [None])[0]
            return self._api_report_file(p)

        if u.path == "/api/export":
            q = parse_qs(u.query)
            fmt = q.get("format", ["json"])[0]
            t = q.get("target", [None])[0]
            rows = list_findings(target=t)
            data = [_to_record(r) for r in rows]
            if fmt == "csv":
                import io
                out = io.StringIO()
                out.write("id,target,fingerprint,type,severity,confidence,exposure_class,timestamp,priority,status,cve_id,active_exploitation,urgent_disclosure\n")
                for r in data:
                    out.write(f"{r['id']},{r['target']},{r['fingerprint']},{r['type']},{r['severity']},{r['confidence']},{r['exposure_class']},{r['timestamp']},{r.get('priority','P3')},{r.get('status','DISCOVERED')},{r.get('cve_id','')},{r.get('active_exploitation',False)},{r.get('urgent_disclosure',False)}\n")
                return self._send(200, out.getvalue(), "text/csv")
            return self._send(200, data)

        # static fallback
        super().do_GET()

    def do_POST(self):
        if not require_auth(self.headers):
            return self._unauthorized()
        u = urlparse(self.path)
        clen = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(clen).decode("utf-8") if clen else "{}"
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return self._bad("invalid json")

        if u.path == "/api/targets":
            domain = payload.get("domain")
            region = payload.get("region", "")
            industry = payload.get("industry", "")
            if not domain:
                return self._bad("domain required")
            add_target(domain, industry=industry, region=region)
            return self._send(201, {"domain": domain, "region": region, "industry": industry})

        if u.path == "/api/scan":
            domain = payload.get("target") or payload.get("domain")
            region = payload.get("region", "")
            after = payload.get("after")
            before = payload.get("before")
            if not domain:
                return self._bad("target required")
            res = _scan_one(domain, region=region, after=after, before=before)
            return self._send(200, {"target": domain, "new": res[0], "duplicates": res[1]})

        if u.path == "/api/triage":
            target = payload.get("target")
            rows = list_findings(target=target)
            findings_for_triage = [
                {"id": r[0], "target": r[1], "fingerprint": r[2], "url": r[3], "evidence": r[9],
                 "type": r[5], "severity": r[6], "confidence": r[7], "exposure_class": r[8]}
                for r in rows
            ]
            if not findings_for_triage:
                return self._send(200, {"results": [], "message": "no findings for target"})
            results = triage_order(findings_for_triage)
            for res in results:
                set_finding_priority(res.finding_id, res.priority, res.urgent_disclosure, res.active_exploitation)
            return self._send(200, {"results": [
                {"id": r.finding_id, "severity": r.severity, "confidence": r.confidence,
                 "priority": r.priority, "urgent_disclosure": r.urgent_disclosure,
                 "active_exploitation": r.active_exploitation, "triage_notes": r.triage_notes,
                 "exposure_class": r.exposure_class, "cve_matched": r.cve_matched}
                for r in results
            ]})

        if u.path == "/api/status":
            fid = payload.get("id")
            status = payload.get("status")
            if not fid or not status:
                return self._bad("id and status required")
            ok = set_finding_status(fid, status)
            return self._send(200, {"id": fid, "status": status, "updated": ok})

        if u.path == "/api/disclose":
            target = payload.get("target")
            fid = payload.get("id")
            rows = list_findings(target=target)
            if not rows:
                return self._bad("no findings for target")
            findings = [_to_record(r) for r in rows]
            if fid:
                findings = [f for f in findings if str(f["id"]) == str(fid)]
                if not findings:
                    return self._bad(f"no finding with id {fid}")
            summary = generate_all_p0_reports(findings, base_dir=str(REPORTS_BASE))
            return self._send(200, summary)

        if u.path == "/api/mark_reported":
            fid = payload.get("id")
            if not fid:
                return self._bad("id required")
            mark_reported(fid)
            return self._send(200, {"id": fid, "reported": True})

        return self._bad(f"unknown endpoint {u.path}")

    def do_DELETE(self):
        if not require_auth(self.headers):
            return self._unauthorized()
        u = urlparse(self.path)
        if u.path == "/api/findings":
            q = parse_qs(u.query)
            t = q.get("target", [None])[0]
            import sqlite3
            c = sqlite3.connect(str(DB_PATH))
            if t:
                c.execute("DELETE FROM findings WHERE target=?", (t,))
            else:
                c.execute("DELETE FROM findings")
            c.commit(); c.close()
            return self._send(200, {"cleared": True, "target": t})
        if u.path == "/api/targets":
            q = parse_qs(u.query)
            d = q.get("domain", [None])[0]
            if not d:
                return self._bad("domain required")
            c = sqlite3.connect(str(DB_PATH))
            c.execute("DELETE FROM targets WHERE domain=?", (d,))
            c.commit(); c.close()
            return self._send(200, {"deleted": True})
        return self._bad(f"unknown endpoint {u.path}")

    # --- helpers ---
    def _api_stats(self):
        c = sqlite3.connect(str(DB_PATH))
        targets = c.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        findings = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        by_sev = dict(c.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall())
        by_pri = dict(c.execute("SELECT COALESCE(priority,'P3'), COUNT(*) FROM findings GROUP BY priority").fetchall())
        urgent = c.execute("SELECT COUNT(*) FROM findings WHERE urgent_disclosure=1").fetchone()[0]
        p0 = c.execute("SELECT COUNT(*) FROM findings WHERE priority='P0'").fetchone()[0]
        reported = c.execute("SELECT COUNT(*) FROM findings WHERE reported=1").fetchone()[0]
        c.close()
        return self._send(200, {
            "targets": targets, "findings": findings, "by_severity": by_sev,
            "by_priority": by_pri, "urgent": urgent, "p0": p0, "reported": reported
        })

    def _api_targets(self):
        rows = list_targets()
        return self._send(200, {"targets": [{"domain": r[0], "industry": r[1] or "", "region": r[2] or "", "added_at": r[3] or ""} for r in rows]})

    def _api_reports(self, target):
        dirs = []
        if target:
            slug = company_slug(target)
            d = REPORTS_BASE / slug
            if d.is_dir():
                dirs = [d]
        else:
            if REPORTS_BASE.is_dir():
                dirs = [p for p in REPORTS_BASE.iterdir() if p.is_dir()]
        out = []
        for d in dirs:
            files = [f.name for f in d.iterdir() if f.is_file()]
            out.append({"target": d.name, "dir": str(d), "files": files})
        return self._send(200, {"reports": out})

    def _api_report_file(self, path_str):
        if not path_str:
            return self._bad("path required")
        p = Path(path_str)
        try:
            p.resolve().relative_to(REPORTS_BASE.resolve())
        except (ValueError, OSError):
            return self._bad("path outside reports dir")
        if not p.is_file():
            return self._bad("not a file")
        try:
            return self._send(200, {"path": str(p), "content": p.read_text(encoding="utf-8")})
        except Exception as e:
            return self._bad(f"read error: {e}")

    def log_message(self, fmt, *args):
        print(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} - {fmt % args}", file=sys.stderr)


def run_server(host="127.0.0.1", port=8080, token=None):
    global TOKEN
    TOKEN = token
    init_db()
    server = ThreadingHTTPServer((host, port), APIHandler)
    print(f"sec-osint webui listening on http://{host}:{port}")
    if token:
        print(f"  Auth token: {token}  (header: Authorization: Bearer {token})")
    print(f"  Static files: {WEBUI_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.server_close()


def main():
    ap = argparse.ArgumentParser(prog="sec-osint webui")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--token", help="Bearer token for API auth")
    args = ap.parse_args()
    run_server(args.host, args.port, args.token)


if __name__ == "__main__":
    main()