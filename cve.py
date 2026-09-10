"""CVE correlation engine — spec 23-39. stdlib only, metadata-only, no network."""
from __future__ import annotations

ACTIVE_EXPLOITED = frozenset({
    "CVE-2023-44487",   # HTTP/2 rapid reset
    "CVE-2024-3400",    # Palo Alto PAN-OS
    "CVE-2024-27198",   # JetBrains TeamCity
    "CVE-2024-21762",   # Ivanti Connect Secure
    "CVE-2023-22515",   # Atlassian Confluence
})

_STATUSES = ["LIKELY_AFFECTED", "POTENTIALLY_AFFECTED", "INSUFFICIENT_EVIDENCE"]


def nvd_url(product: str, version: str = "") -> str:
    q = f"{product} {version}".strip()
    return f"https://nvd.nist.gov/vuln/search/results?query={q.replace(' ', '+')}&form_type=Basic" if q else ""


def certin_url(product: str = "", keyword: str = "") -> str:
    q = (product + " " + keyword).strip()
    return f"https://www.cert-in.org.in/Directions.aspx?q={q.replace(' ', '+')}" if q else ""


def is_known_exploited(cve_id: str) -> bool:
    return cve_id.upper() in ACTIVE_EXPLOITED


# ponytail: naive prefix/range compare only; upgrade to semver/libvuln when available.
def version_affected(version: str, affected_prefix: str) -> bool:
    if not version or not affected_prefix:
        return False
    return version.startswith(affected_prefix)


def correlate(product: str, version: str = "", fingerprints: list[str] | None = None) -> dict:
    if not product:
        return {
            "product": "", "version": version, "status": "INSUFFICIENT_EVIDENCE",
            "confidence": 0.0, "cve_refs": [], "advisory_refs": [], "notes": "missing product"
        }

    cve_refs, advisory_refs = [], []
    if version:
        cve_refs.append(nvd_url(product, version))
        advisory_refs.append(certin_url(product, "vulnerability"))

    if not version:
        status = "POTENTIALLY_AFFECTED"
        confidence = min(0.6, 0.4 + 0.1 * min(len(fingerprints or []), 3))
        notes = "no version supplied; highest confidence is POTENTIALLY_AFFECTED"
    else:
        # Do not claim CONFIRMED_VULNERABLE without explicit version-to-range match.
        status = "POTENTIALLY_AFFECTED"
        confidence = 0.55
        notes = "offline placeholder; no matched CVE record here"

    return {
        "product": product,
        "version": version,
        "status": status,
        "confidence": round(confidence, 2),
        "cve_refs": cve_refs,
        "advisory_refs": advisory_refs,
        "notes": notes,
    }


def exposure_base(exposure_class: str):
    from .scoring import EXPOSURE_CLASS_BASE
    return EXPOSURE_CLASS_BASE.get(exposure_class, ("MEDIUM", 0.6))
