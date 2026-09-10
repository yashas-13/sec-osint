"""Critical-disclosure report package — spec sections 16, 17, 36.

Redaction guarantee: evidence dicts are metadata-only. No sensitive values
are written to any report file. Values sourced from findings pass through
safe_fingerprint()/redact() so credentials, PII and tokens never reach disk.
"""
import hashlib, json, os, re
from datetime import datetime
from pathlib import Path
try:
    from sec_osint.redact import safe_fingerprint
    from sec_osint.scoring import priority
except ImportError:
    from redact import safe_fingerprint
    from scoring import priority

DEFAULT_BASE_DIR = "~/sec-osint/reports"

# Tailored remediation: (immediate, long-term) per exposure class.
_REMEDIATION = {
    "credential_exposure": ("Rotate exposed credentials immediately; revoke the leaked key/token and audit its use.",
                            "Adopt a secrets manager, rotate keys on a schedule, and scan public sources for leaks."),
    "database_exposure": ("Take the database off public access now; require auth and restrict to private networks.",
                          "Run repeated authenticated checks for open instances and enforce network policy."),
    "rce_indicator": ("Patch or isolate the affected asset immediately; take it offline if internet-facing and unpatched.",
                      "Maintain a patching SLA, add WAF rules and runtime detection."),
    "auth_bypass": ("Suspend affected sessions and revoke tokens; enforce multi-factor authentication.",
                    "Application security review plus anomaly detection for bypass patterns."),
    "cloud_credential": ("Revoke the cloud credential and rotate linked keys; check cloud logs for abuse.",
                         "Cloud-native secret management, short-lived credentials, continuous monitoring."),
    "api_authz_failure": ("Fix server-side authorization checks; reject requests lacking scope.",
                          "Automated API security testing and schema-driven authz enforcement."),
    "config_exposure": ("Remove the exposed file/endpoint from public access and restrict it server-side.",
                        "Add a public-exposure scanning pipeline to CI/CD."),
    "api_exposure": ("Require authentication and rate limiting on the API; remove public docs if internal.",
                     "Adopt API gateway policy and review public routes regularly."),
    "staging_exposed": ("Remove staging/UAT/dev instances from public access; use VPN or IP allow-listing.",
                        "Standardize non-prod behind a jump host and monitor for exposure."),
    "index_exposure": ("Disable directory indexing on the web server.",
                       "Harden server config and audit for open directory listings."),
    "document_exposure": ("Remove the sensitive document from public hosting and enforce access control.",
                          "Implement document classification and DLP review for public storage."),
    "cve_match": ("Patch the matched CVE immediately; if unpatched and internet-facing, isolate the asset.",
                  "Maintain a patching SLA and subscribe to CVE/advisory feeds."),
}
_DEFAULT_REMEDIATION = ("Remove or restrict the exposed resource from public access.",
                        "Institutionalize a review process for publicly reachable assets and re-run scans.")


def company_slug(target):
    """domain -> filesystem-safe slug, e.g. https://Login.Example.com -> login-example-com."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(target or "").strip().lower()).strip("-")
    return slug or "unknown"


def _remediation(exposure_class):
    return _REMEDIATION.get((exposure_class or "").lower(), _DEFAULT_REMEDIATION)


def _norm(f):
    """Normalize (and redact) a finding dict to the fixed internal shape."""
    sev = str(f.get("severity") or "INFO").upper()
    conf = float(f.get("confidence") or 0.0)
    return {
        "id": f.get("id"),
        "target": f.get("target") or "",
        "severity": sev,
        "confidence": conf,
        "priority": f.get("priority") or priority(sev, conf),
        "exposure_class": f.get("exposure_class") or "",
        "evidence": safe_fingerprint(f.get("evidence") or "", 250),
        "fingerprint": safe_fingerprint(f.get("fingerprint") or "", 300),
        "url": safe_fingerprint(f.get("url") or f.get("evidence") or "", 250),
        "query": safe_fingerprint(f.get("query") or "", 250),
        "timestamp": f.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cve_matched": f.get("cve_matched") or "",
        "active_exploitation": bool(f.get("active_exploitation")),
        "urgent_disclosure": bool(f.get("urgent_disclosure")),
        "triage_notes": f.get("triage_notes") or "",
    }


def generate_critical_report(finding, out_dir):
    """Write a per-company P0/P1 disclosure package. Returns file summary dict."""
    f = _norm(finding)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    exp = f["exposure_class"].replace("_", " ").title() or "Exposure"
    h = hashlib.sha256(f"{f['target']}|{f['fingerprint']}|{f['url']}".encode()).hexdigest()[:16]

    # evidence.json — redacted metadata only; no sensitive values ever written.
    (out / "evidence.json").write_text(
        json.dumps({"hash": h, "url": f["url"], "confidence": f["confidence"],
                    "timestamp": f["timestamp"], "severity": f["severity"],
                    "priority": f["priority"], "exposure_class": f["exposure_class"],
                    "cve_matched": f["cve_matched"]}, indent=2) + "\n", encoding="utf-8")

    # executive-summary.md — section 36 format.
    urgent = f["active_exploitation"] or f["urgent_disclosure"]
    (out / "executive-summary.md").write_text(
        "\n".join([
            "# Critical Disclosure — Executive Summary", "",
            f"**Severity:** {f['severity']}  ", f"**Confidence:** {f['confidence']:.0%}  ",
            f"**Priority:** {f['priority']}  ", f"**Organization:** {f['target']}  ",
            f"**Asset:** {f['url']}  ", f"**Discovery timestamp:** {f['timestamp']}  ",
            f"**Vulnerability / Exposure:** {exp}  ",
            f"**Attack surface:** {exp} reachable at {f['url']}  ",
            f"**Evidence:** {f['evidence']}  ",
            "**Observed impact:** publicly indexed indicator of exposure; no access gained, no data modified.",
            "**Business impact:** this exposure class can lead to data theft, abuse, or regulatory liability.",
            f"**Urgent attention reason:** {'actively exploited — immediate action required. ' if f['active_exploitation'] else ''}"
            f"{'priority ' + f['priority'] + ' disclosure required.' if urgent else 'routine triage.'}",
            "**Safe validation:** passive check of public search-indexed signals only.",
            "**NOT tested:** no exploitation, no authentication, no destructive testing performed.",
            "**Remediation:** see remediation.md (immediate and long-term actions).",
            "**References:** see technical-finding.md (CVE/advisory references).",
            "**Disclosure contact:** locate the organization's security contact via security.txt / security@ address.",
            "", "---", "",
            "No credentials used. No private records collected. No unauthorized auth attempted. No destructive testing.",
        ]) + "\n", encoding="utf-8")

    # technical-finding.md — raw technical details.
    cve = f["cve_matched"]
    cve_ref = f"NVD: https://nvd.nist.gov/vuln/detail/{cve}" if cve else \
        f"NVD search: https://nvd.nist.gov/vuln/search/results?query={f['target'].replace(' ', '+')}"
    adv_ref = f"CERT-In search: https://www.cert-in.org.in/Directions.aspx?q={f['target'].replace(' ', '+')}"
    (out / "technical-finding.md").write_text(
        "\n".join([
            "# Technical Finding", "",
            f"**Finding ID:** {f['id']}  ", f"**Target:** {f['target']}  ",
            f"**Exposure class:** {f['exposure_class']}  ",
            f"**Severity / Priority:** {f['severity']} / {f['priority']}  ",
            f"**Confidence:** {f['confidence']:.0%}  ",
            f"**CVSS:** {'not assessed offline; passive OSA scoring only. CVE match: ' + cve if cve else 'not assessed offline (passive OSA scoring only).'}",
            f"**Timestamp:** {f['timestamp']}  ", f"**Evidence URL:** {f['url']}  ",
            f"**Fingerprint:** {f['fingerprint']}  ", f"**Search query:** {f['query']}  ",
            f"**CVE references:** {cve or 'none'}  ", f"**Advisory references:** {adv_ref}  ",
            f"**Triage notes:** {f['triage_notes'] or 'none'}  ",
        ]) + "\n", encoding="utf-8")

    # disclosure-email.md — section 17.
    (out / "disclosure-email.md").write_text(
        "\n".join([
            "# Disclosure Email Draft", "",
            f"**To:** SECURITY / security@ / {f['target']}",
            f"**Subject:** [Security] {exp} exposure at {f['target']} — {f['severity']}", "",
            "Dear Security Team,",
            f"During passive public-source review of **{f['target']}** we observed a **{f['severity']}** exposure: **{exp}**.",
            f"**What observed:** publicly indexed indicator of {exp} (metadata only; no data read).",
            f"**Where:** {f['url']}", f"**Category:** {f['exposure_class']}",
            "**Safe validation method:** passive review of public search-engine index entries; no credentials, no private records, no authorization attempted.",
            f"**Scope:** {f['target']}", f"**Severity:** {f['severity']} (confidence {f['confidence']:.0%}, priority {f['priority']})",
            "**Recommended immediate actions:** see remediation.md — rotate / restrict / revoke per exposure class.",
            "**Secure channel:** please reply via your official disclosure channel (security.txt, bug-bounty program, or this address).",
            "", "Regards,", "Passive Security Researcher (metadata-only).",
        ]) + "\n", encoding="utf-8")

    # remediation.md — tailored by exposure class.
    imm, long = _remediation(f["exposure_class"])
    (out / "remediation.md").write_text(
        "\n".join([
            "# Remediation Recommendations", "",
            f"**Finding:** {f['id']} — {exp} at {f['target']} ({f['severity']} / {f['priority']})", "",
            "## Immediate", f"- {imm}", "", "## Long-term", f"- {long}", "",
            "Post-remediation validation must be performed by the organization under an authorized engagement.",
        ]) + "\n", encoding="utf-8")

    return {"id": f["id"], "target": f["target"], "report_dir": str(out),
            "files": sorted(p.name for p in out.iterdir())}


def generate_all_p0_reports(findings, base_dir=DEFAULT_BASE_DIR):
    """Generate disclosure packages for every P0/P1 finding. Returns summary dict."""
    base = Path(os.path.expanduser(str(base_dir)))
    total_p0 = total_p1 = 0
    dirs = []
    for f in findings:
        sev = str(f.get("severity") or "INFO").upper()
        conf = float(f.get("confidence") or 0.0)
        pri = f.get("priority") or priority(sev, conf)
        if pri not in ("P0", "P1"):
            continue
        if pri == "P0":
            total_p0 += 1
        else:
            total_p1 += 1
        d = base / company_slug(f.get("target") or "unknown")
        generate_critical_report(f, str(d))
        if str(d) not in dirs:
            dirs.append(str(d))
    return {"total_p0": total_p0, "total_p1": total_p1, "report_dirs": dirs}