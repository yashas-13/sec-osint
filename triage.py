"""Triage engine — spec 24-39. Stdlib only. CRITICAL-first.
Classifies findings by severity/confidence -> priority, urgent flag, KEV check."""
import re
from dataclasses import dataclass, field

try:
    from .cve import ACTIVE_EXPLOITED  # stdlib-only correlate lives in cve.py
except Exception:
    try:
        from cve import ACTIVE_EXPLOITED
    except Exception:
        import sys
        print("triage: warning: cve.ACTIVE_EXPLOITED unavailable", file=sys.stderr)
        ACTIVE_EXPLOITED = frozenset()

@dataclass
class TriageResult:
    finding_id: int
    severity: str
    confidence: float
    priority: str
    urgent_disclosure: bool
    active_exploitation: bool
    exposure_class: str = ""
    triage_notes: str = ""
    cve_matched: str = ""  # comma-joined CVE ids if any

# Simple product/version extractor (ponytail: upgrade to semver/CPE when available)
_PROD_VERSION_RE = re.compile(
    r"(?P<product>Apache|nginx|OpenSSL|jQuery|WordPress|Drupal|Spring|Tomcat|IIS|Node\.?js|React|Angular|Log4j|Confluence|GitLab|Ivanti|TeamCity)"
    r"[\s/]+(?P<version>\d+\.\d+(?:\.\d+)?(?:[^\s,;)]*)?)",
    re.I,
)

def extract_tech(evidence: str, fingerprint: str = "") -> dict:
    text = " ".join([evidence or "", fingerprint or ""])
    m = _PROD_VERSION_RE.search(text)
    if m:
        prod = m.group("product").strip()
        ver = m.group("version").strip().rstrip(",;)")
        return {"product": prod, "version": ver, "hints": [prod]}
    return {"product": "", "version": "", "hints": []}

def _priority(sev: str, conf: float) -> str:
    try:
        from .scoring import priority as _pri
        return _pri(sev, conf)
    except Exception:
        s = sev.upper()
        if s == "CRITICAL" and conf >= 0.8:
            return "P0"
        if s == "HIGH" and conf >= 0.8:
            return "P1"
        if s in ("LOW", "INFO"):
            return "P3"
        return "P2"

def _urgent(sev: str, conf: float, active: bool, hint: str) -> bool:
    try:
        from .scoring import urgent as _urg
        return _urg(sev, conf, active_exploitation=active, exposure_hint=hint)
    except Exception:
        return active or (sev.upper() == "CRITICAL" and conf >= 0.6 and any(
            h in (hint or "").lower() for h in ("credential", "database", "rce", "auth_bypass")))

def _detect_kev(evidence: str, fingerprint: str) -> tuple[bool, list[str]]:
    blob = " ".join([evidence or "", fingerprint or ""])
    found = []
    upper = blob.upper()
    for cve in ACTIVE_EXPLOITED:
        if cve.upper() in upper:
            found.append(cve)
    return (len(found) > 0, found)

def classify(finding: dict) -> TriageResult:
    raw_id = finding.get("id", finding.get("finding_id", 0))
    try: fid = int(raw_id)
    except: fid = hash(str(raw_id)) & 0xfffffff
    sev = (finding.get("severity") or "INFO").upper()
    conf = float(finding.get("confidence", 0.6) or 0.6)
    exp = (finding.get("exposure_class") or finding.get("type") or "").strip()
    kev, cves = _detect_kev(finding.get("evidence", ""), finding.get("fingerprint", ""))
    pri = _priority(sev, conf)
    if kev:
        pri = "P0"
    urg = _urgent(sev, conf, kev, exp)
    if kev:
        urg = True
    notes = ""
    if kev:
        notes = f"KEV match {', '.join(cves)} -> URGENT_DISCLOSURE P0"
    elif urg:
        notes = f"CRITICAL {exp or 'exposure'} conf {conf:.2f} -> URGENT"
    else:
        notes = f"{sev} conf {conf:.2f} -> {pri}"
    return TriageResult(
        finding_id=fid, severity=sev, confidence=conf, priority=pri,
        urgent_disclosure=urg, active_exploitation=kev,
        exposure_class=exp, triage_notes=notes,
        cve_matched=",".join(cves),
    )

def triage_order(findings: list[dict]) -> list[TriageResult]:
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    scored = [classify(f) for f in findings]
    scored.sort(key=lambda r: (order.get(r.priority, 4), -r.confidence, r.finding_id))
    return scored

def batch_triage(findings: list[dict], cve_correlator=None) -> dict:
    scored = triage_order(findings)
    # Optional per-product CVE correlation
    cve_matches: dict[str, dict] = {}
    if cve_correlator is not None:
        seen: set[tuple[str, str]] = set()
        for f in findings:
            tech = extract_tech(f.get("evidence", ""), f.get("fingerprint", ""))
            key = (tech["product"], tech["version"])
            if not tech["product"] or key in seen:
                continue
            seen.add(key)
            try:
                cve_matches[f"{key[0]}@{key[1]}" or key[0]] = cve_correlator(
                    tech["product"], tech["version"], tech["hints"]
                )
            except Exception as e:
                cve_matches[f"{key[0]}@{key[1]}"] = {"error": str(e)}
    # Fallback correlation via cve.correlate if caller didn't supply one
    elif not cve_matches:
        try:
            from .cve import correlate as _corr
            seen = set()
            for f in findings:
                tech = extract_tech(f.get("evidence", ""), f.get("fingerprint", ""))
                key = (tech["product"], tech["version"])
                if not tech["product"] or key in seen:
                    continue
                seen.add(key)
                cve_matches[f"{key[0]}@{key[1]}" or key[0]] = _corr(
                    tech["product"], tech["version"], tech["hints"]
                )
        except Exception:
            pass
    return {
        "triage_results": scored,
        "cve_matches": cve_matches,
        "urgent_count": sum(1 for r in scored if r.urgent_disclosure),
        "p0_count": sum(1 for r in scored if r.priority == "P0"),
        "p1_count": sum(1 for r in scored if r.priority == "P1"),
    }
