"""Risk scoring — spec 9 + 23-39 triage. CRITICAL/HIGH/MEDIUM/LOW/INFO"""
LEVELS=["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
WEIGHTS={
  "config_exposure": ("HIGH",0.9),
  "api_exposure": ("MEDIUM",0.7),
  "staging_exposed": ("HIGH",0.85),
  "index_exposure": ("MEDIUM",0.6),
  "cloud_reference": ("MEDIUM",0.6),
  "document_exposure": ("LOW",0.5),
  "security_signal": ("MEDIUM",0.6),
  "cve_match": ("CRITICAL",0.8),
  "fingerprint_match": ("HIGH",0.75),
  "error_leak": ("MEDIUM",0.65),
  "no_security_contact": ("LOW",0.4),
}

# Exposure classes from section 23 (Agent-B/C emit these). Base severity per class.
EXPOSURE_CLASS_BASE={
  "credential_exposure": ("HIGH",0.85),
  "database_exposure": ("CRITICAL",0.88),
  "rce_indicator": ("CRITICAL",0.9),
  "auth_bypass": ("CRITICAL",0.88),
  "cloud_credential": ("CRITICAL",0.9),
  "api_authz_failure": ("HIGH",0.82),
}

def score(exposure_class, confidence=0.6, is_public=True):
    base, w = EXPOSURE_CLASS_BASE.get(exposure_class, WEIGHTS.get(exposure_class, ("MEDIUM",0.6)))
    # confidence adjusts but never inflates just because keyword appears
    idx=LEVELS.index(base)
    if confidence>0.85 and idx<len(LEVELS)-1 and is_public:
        idx+=1
    elif confidence<0.4 and idx>0:
        idx-=1
    return LEVELS[idx], confidence

def label(sev): return f"[{sev}]"

# ---- Spec 23-39 triage: priority + urgent disclosure ----

def priority(severity, confidence):
    """P0 = critical+high conf, P1 = high+high conf, P3 = LOW/INFO, else P2."""
    sev=severity.upper()
    if sev=="CRITICAL" and confidence>=0.8: return "P0"
    if sev=="HIGH" and confidence>=0.8: return "P1"
    if sev in ("LOW","INFO"): return "P3"
    return "P2"

def urgent(severity, confidence, active_exploitation=False, exposure_hint=""):
    """URGENT_DISCLOSURE: actively exploited, or critical-tier exposure hint with conf>=0.6."""
    if active_exploitation: return True
    sev=severity.upper()
    hints={"credential","database","rce","auth_bypass"}
    if sev=="CRITICAL" and exposure_hint and any(h in exposure_hint.lower() for h in hints) and confidence>=0.6:
        return True
    return False