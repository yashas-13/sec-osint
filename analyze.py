"""Analysis: JS, API, cloud, documents. Spec 5, 6, 7. Passive only."""
import re, os, sys, json, hashlib
from urllib.parse import urlparse, urljoin
from pathlib import Path

H={"User-Agent":"Mozilla/5.0"}
_JSW_RE=re.compile(r'["\'](/[^"\']*(?:api|graphql|swagger|webhook|token|secret|key|password|auth|login|v[0-9])[^"\']*)["\']')
_JSURL_RE=re.compile(r'["\'](https?://[^"\']+)["\']')
_ENDPOINT_RE=re.compile(r'(?:POST|GET|PUT|DELETE|PATCH|fetch|axios|ajax)\s*[\(]?\s*["\'](/[^"\']+)')
_DEBUG_RE=re.compile(r'(?:console\.log|debug\s*:|__DEV__|process\.env\.NODE_ENV|webpack_require)',re.I)
_SOURCEMAP_RE=re.compile(r'//[#@]\s*sourceMappingURL')
_OAUTH_RE=re.compile(r'https://(?:accounts\.)?google\.com/oauth|github\.com/login/oauth|openid\.connect')
_WEBHOOK_RE=re.compile(r'/webhook|/hooks/',re.I)

# cloud patterns
_S3_RE=re.compile(r'https?://[a-zA-Z0-9_-]+\.s3[.\-]?amazonaws\.com',re.I)
_GCS_RE=re.compile(r'https?://storage\.googleapis\.com/[a-zA-Z0-9_-]+',re.I)
_AZURE_RE=re.compile(r'https?://[a-zA-Z0-9_-]+\.blob\.core\.windows\.net',re.I)
_GOOGLEDRV_RE=re.compile(r'drive\.google\.com|docs\.google\.com',re.I)
_SP_RE=re.compile(r'sharepoint\.com',re.I)
_ODRV_RE=re.compile(r'onedrive\.(?:live\.com|microsoft\.com)',re.I)

_DOC_RE=re.compile(r'filetype:(pdf|docx?|xlsx?|pptx?|csv|txt)',re.I)

def _safe_get(url, timeout=12):
    try:
        import requests
        r=requests.get(url, headers=H, timeout=timeout, allow_redirects=True, verify=False)
        if r.status_code==200: return r.text[:100000]
    except: pass
    return None

def _redact(text):
    from .redact import redact
    return redact(text or "")

def analyze_javascript(url, content=None):
    """Fetch and analyze a JS file for endpoints, secrets, debug flags."""
    if content is None: content=_safe_get(url)
    if not content: return []
    findings=[]
    hits=[]
    hits.extend(_JSW_RE.findall(content)[:25])
    hits.extend(_ENDPOINT_RE.findall(content)[:15])
    for src in _JSURL_RE.findall(content)[:20]:
        if any(k in src.lower() for k in ("/api/","/graphql","/swagger","/webhook","oauth","token")):
            hits.append(src)
    if hits:
        seen=set()
        uniq=[]
        for h in hits:
            nh=hashlib.md5(h.encode()).hexdigest()[:12]
            if nh not in seen: seen.add(nh); uniq.append(h)
        findings.append({"target":urlparse(url).netloc,"finding":"javascript_endpoints","severity":"MEDIUM","confidence":0.65,"evidence":f"JS: {url[:80]}\nEndpoints: {chr(10).join(uniq[:10])}","exposure_class":"api_exposure","data_source":"javascript","url":url,"fingerprint":f"js:{urlparse(url).netloc}"})
    if _DEBUG_RE.search(content):
        findings.append({"target":urlparse(url).netloc,"finding":"javascript_debug_flag","severity":"LOW","confidence":0.5,"evidence":f"Debug indicators in {url[:80]}","exposure_class":"config_exposure","data_source":"javascript","url":url})
    if _SOURCEMAP_RE.search(content):
        findings.append({"target":urlparse(url).netloc,"finding":"javascript_sourcemap","severity":"INFO","confidence":0.8,"evidence":f"Source map in {url[:80]}","exposure_class":"document_exposure","data_source":"javascript","url":url})
    return findings

def analyze_api(search_results, domain=""):
    findings=[]
    api_paths=["/api","/api/v1","/api/v2","/graphql","/swagger","/swagger-ui","/openapi","/openapi.json","/api-docs","/actuator","/env","/.env","/health","/status"]
    for r in search_results[:5]:
        url=r.get("url","")
        if any(k in url.lower() for k in ["api","graphql","swagger","openapi","admin","dashboard"]):
            findings.append({"target":domain or urlparse(url).netloc,"finding":"api_endpoint_discovered","severity":"MEDIUM","confidence":0.55,"evidence":url,"exposure_class":"api_exposure","data_source":"dork","url":url})
            break
    return findings

def analyze_cloud(search_results, domain=""):
    findings=[]
    clouds={"s3_aws":_S3_RE,"gcs":_GCS_RE,"azure":_AZURE_RE,"gdrive":_GOOGLEDRV_RE,"sharepoint":_SP_RE,"onedrive":_ODRV_RE}
    for cloud_name,pat in clouds.items():
        for r in search_results[:8]:
            url=r.get("url","")
            if pat.search(url):
                t=urlparse(url).netloc
                findings.append({"target":domain or t,"finding":f"cloud_{cloud_name}_reference","severity":"MEDIUM","confidence":0.6,"evidence":url,"exposure_class":"cloud_reference","data_source":"dork","url":url})
    return findings

def analyze_documents(search_results, domain="", fetch=True):
    """Extract metadata from public docs. Passive only — HEAD only, skip private docs."""
    findings=[]
    doc_rows=[r for r in search_results if _DOC_RE.search(r.get("url","").lower())]
    for r in doc_rows[:8]:
        url=r["url"]; title=r.get("title","")
        if fetch:
            info=head_info(url)
            ct=info.get("ct",""); sz=info.get("length",0)
            if sz>50000 and any(k in title.lower() for k in ["confidential","internal","private","customer"]):
                continue  # skip docs with private-indicating titles
            findings.append({"target":domain or urlparse(url).netloc,"finding":"document_exposure","severity":"LOW","confidence":0.5,"evidence":f"{title[:100]} @ {url[:100]} ({ct}, {sz} bytes)","exposure_class":"document_exposure","data_source":"dork","url":url})
        else:
            findings.append({"target":domain or urlparse(url).netloc,"finding":"document_exposure","severity":"LOW","confidence":0.4,"evidence":f"{title[:100]} @ {url[:100]}","exposure_class":"document_exposure","data_source":"dork","url":url})
    return findings

def analyze_disclosure(search_results, domain=""):
    findings=[]
    for r in search_results[:5]:
        url=r.get("url",""); title=r.get("title","") or r.get("snippet","")
        low=(title+" "+url).lower()
        if any(k in low for k in ["vulnerability","breach","incident","cve","security advisory","responsible disclosure"]):
            if "data breach" in low or "hacked" in low or "ransomware" in low:
                sev="HIGH"; conf=0.7
            elif "vulnerability" in low or "cve" in low:
                sev="MEDIUM"; conf=0.6
            else:
                sev="LOW"; conf=0.5
            findings.append({"target":domain or urlparse(url).netloc,"finding":"security_disclosure_signal","severity":sev,"confidence":conf,"evidence":f"{title[:120]} @ {url[:100]}","exposure_class":"security_signal","data_source":"dork","url":url})
    return findings
