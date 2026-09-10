"""Passive technology fingerprinting from public HTML, headers, and JS."""
import re
from .scoring import score

TECH_PATTERNS={
    "WordPress": [r"wp-content",r"wp-includes",r"wp-json",r"wordpress"],
    "Drupal": [r"drupal\.js",r"sites/default",r"Drupal\.settings"],
    "Laravel": [r"laravel_session",r"XSRF-TOKEN",r"_token"],
    "Django": [r"csrftoken",r"django\.language",r"__admin__"],
    "React": [r"__REACT_DEVTOOLS__",r"react\.production",r"react\.development"],
    "Vue": [r"vue\.js",r"__VUE__",r"data-v-"],
    "Angular": [r"ng-version",r"angular\.js",r"ng-app"],
    "jQuery": [r"jquery\.js",r"jquery/"],
    "Bootstrap": [r"bootstrap\.css",r"bootstrap\.js"],
    "Nginx": [r"nginx/",r"X-Accel"],
    "Apache": [r"Apache/"],
    "Cloudflare": [r"cloudflare",r"cf-ray"],
    "GitHub Pages": [r"cdn\.jsdelivr\.net/npm/gh-pages"],
}

def _detect(patterns, text, headers=""):
    blob=text+" "+headers
    return sum(bool(re.search(p,blob,re.I)) for p in patterns)

def fingerprint_tech_stack(html="", headers=None):
    headers=headers or {}
    header_blob=" ".join(f"{k}: {v}" for k,v in headers.items())
    found=[]
    for tech,patterns in TECH_PATTERNS.items():
        n=_detect(patterns,html,header_blob)
        if n: found.append({"technology":tech,"confidence":min(0.99,0.55+0.15*n),"matches":n})
    return found

def detect_server(headers):
    return headers.get("Server","") or headers.get("server","")

def fingerprint_finding(target, html="", headers=None):
    tech=fingerprint_tech_stack(html,headers)
    if not tech: return None
    best=max(tech,key=lambda x:x["confidence"])
    sev,conf=score("fingerprint_match",best["confidence"],True)
    return {"target":target,"finding":"public_technology_fingerprint","severity":sev,"confidence":conf,"evidence":f"{best['technology']} ({best['matches']} signatures)","exposure_class":"fingerprint_match","technology":best["technology"],"stack":tech}
