"""Passive verification helpers — spec 7, 10, 14. Never authenticate or exploit."""
import re, time
from .redact import contains_sensitive, redact, HALT_MSG
from .search import safe_get

_SEVERITY_LABEL=["CRITICAL","HIGH","MEDIUM","LOW","INFO"]

def verify_signal(url, context=""):
    """Verify by HEAD/GET metadata only. Returns (ok, evidence, reason)."""
    if not url or not url.startswith("http"): return False,"","not-url"
    r=safe_get(url, timeout=10)
    if not r: return False,"","unreachable"
    if r.status_code>=400: return False,r.status_code,"http-error"
    if contains_sensitive((context or "")[:500]): return False,"","sensitive-context"
    return True, {"status":r.status_code, "ct":r.headers.get("Content-Type",""), "len":len(r.text)}, r.status_code

def safe_fingerprint(text, max_len=200):
    t=redact(text or "")
    if len(t)>max_len: t=t[:max_len]+"…"
    return t

def evidence_entry(timestamp, target, url, query, ftype, fingerprint, confidence, severity, remediation=""):
    """Build a redacted, non-sensitive evidence dict (spec 10)."""
    return {
        "timestamp":timestamp,
        "target":target,
        "evidence_url":safe_fingerprint(url,250),
        "search_query":safe_fingerprint(query,200),
        "finding_type":ftype,
        "fingerprint":safe_fingerprint(fingerprint,250),
        "confidence":confidence,
        "severity":severity,
        "remediation":remediation or _DEFAULT_REMEDIATION.get(ftype,"Review exposure."),
        "screenshot":None,
    }

_DEFAULT_REMEDIATION={
    "config_exposure":"Review and restrict exposed configuration.",
    "api_exposure":"Review API exposure and scopes.",
    "staging_exposed":"Restrict staging/UAT access.",
    "index_exposure":"Disable directory listing.",
    "cloud_reference":"Review public cloud references.",
    "document_exposure":"Restrict or remove public documents.",
    "security_signal":"Investigate disclosed security signals.",
    "cve_match":"Patch affected software/version.",
    "fingerprint_match":"Verify fingerprint; update if needed.",
    "error_leak":"Mitigate verbose error output.",
    "no_security_contact":"Adopt security.txt / disclosure channel.",
}

def should_fetch(target, is_authorized, collecting_sensitive=False, authenticating=False, exploiting=False, private=False):
    """7-question passive gate — spec 18. Returns (bool, reason)."""
    q1=is_authorized or target.strip()==""  # authorized?
    q2=True  # passive/public recon
    q3=collecting_sensitive
    q4=authenticating
    q5=exploiting
    q6=private
    q7=True  # metadata only
    if not q1: return False, "Target not authorized."
    if q3 or q4 or q5 or q6:
        return False, HALT_MSG
    if not q2 or not q7: return False, "Non-passive operation blocked."
    return True, "ok"

def halt_and_log(findings, target, reason):
    findings.append({
        "target":target,"finding":"safe_failure_halt","severity":"INFO","confidence":1.0,
        "evidence":HALT_MSG,"exposure_class":"info","reason":reason
    })
    print(HALT_MSG)
    return findings