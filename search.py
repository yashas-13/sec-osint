"""Search execution — fetch results via engine rotation. Spec 7, 18."""
import os, re, sys, time, random, hashlib, urllib.parse as _up
from pathlib import Path

H={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

try:
    import requests
except ImportError:
    requests=None

SEARXNG_INSTANCES=[
    "https://search.bus-hit.me","https://searx.be","https://search.privacyguides.net",
]
ENGINE_DELAYS={"ddg-lite":1,"brave":3,"searxng":2,"mojeek":2,"yandex":5,"bing":10}

def safe_get(url, **kw):
    if not requests: return None
    kw.setdefault("timeout",12)
    kw.setdefault("headers",H)
    try:
        r=requests.get(url,**kw)
        # ponytail: add retry with backoff, proper TLS CAs when available
        return r
    except requests.exceptions.SSLError:
        try: return requests.get(url, verify=False, **kw)
        except: return None
    except: return None

def normalize_url(url:str)->str:
    try:
        p=_up.urlparse(url.strip())
        qs=_up.parse_qs(p.query)
        qs={k:v for k,v in qs.items() if k not in ("utm_source","utm_medium","utm_campaign","fbclid","gclid")}
        qs_str="&".join(f"{k}={v[0]}" for k,v in sorted(qs.items()))
        return _up.urlunparse((p.scheme.lower(),p.netloc.lower().rstrip("/"),p.path.rstrip("/") or "/","","",qs_str[:200]))
    except: return url.strip().lower()[:300]

def dedup(rows):
    seen={}; out=[]
    for r in rows:
        h=hashlib.md5(normalize_url(r["url"]).encode()).hexdigest()
        if h not in seen:
            seen[h]=True; r2=dict(r); r2["url"]=normalize_url(r["url"]); out.append(r2)
    return out

def brave_urls(html_text, q=""):
    try:
        from bs4 import BeautifulSoup
        soup=BeautifulSoup(html_text,"html.parser")
        out=[]
        for a in soup.select("a[href]"):
            href=a.get("href",""); title=a.get_text(strip=True)
            if href.startswith("http") and "search.brave.com" not in href and "cdn.search.brave" not in href:
                out.append({"url":href,"title":title[:200],"snippet":href[:300],"engine":"brave"})
            if len(out)>=10: break
        return out
    except: return []

def ddg_lite_search(q, n):
    rows=[]
    try:
        r=safe_get("https://lite.duckduckgo.com/lite/", params={"q":q})
        if not r or r.status_code!=200: return []
        from bs4 import BeautifulSoup
        soup=BeautifulSoup(r.text,"html.parser")
        for a in soup.select("a[href]"):
            href=a.get("href","")
            if "uddg=" in href:
                href=_up.unquote(_up.parse_qs(_up.urlparse("//"+href).query).get("uddg",[""])[0])
            if href.startswith("http") and len(href)>20:
                rows.append({"url":href,"title":a.get_text(strip=True)[:200],"snippet":href[:400],"engine":"ddg-lite"})
            if len(rows)>=n: break
    except Exception as e: print(f"  ddg-lite: {e}", file=sys.stderr)
    return rows

def brave_search(q, n):
    # Brave via web scrape (no API key). API path if BRAVE_API_KEY set.
    api_key=os.getenv("BRAVE_API_KEY")
    if api_key:
        try:
            r=safe_get("https://api.search.brave.com/res/v1/web/search", headers={"X-Subscription-Token":api_key,"Accept":"application/json"}, params={"q":q,"count":n})
            if not r or r.status_code==429: raise RuntimeError("429")
            for hit in r.json().get("web",{}).get("results",[]):
                return [{"url":h.get("url",""),"title":h.get("title",""),"snippet":h.get("description","")[:400],"engine":"brave-api"} for h in r.json()["web"]["results"][:n]]
        except RuntimeError: raise
        except Exception as e: print(f"  brave-api: {e}", file=sys.stderr)
    # fallback scrape
    try:
        r=safe_get(f"https://search.brave.com/search?q={_up.quote_plus(q)}&count={n}")
        if not r or r.status_code==429: raise RuntimeError("429 brave 429")
        if r and r.status_code==200: return brave_urls(r.text)[:n]
    except RuntimeError: raise
    except Exception as e: print(f"  brave: {e}", file=sys.stderr)
    return []

def searxng_search(q, n):
    inst=random.choice(SEARXNG_INSTANCES)
    try:
        r=safe_get(f"{inst}/search", params={"q":q,"format":"json","categories":"general"})
        if not r or r.status_code==429: raise RuntimeError("429 searxng 429")
        if not r or r.status_code!=200: return []
        return [{"url":h.get("url",""),"title":h.get("title",""),"snippet":h.get("content","")[:400],"engine":f"searxng:{inst}"} for h in r.json().get("results",[])[:n]]
    except RuntimeError: raise
    except Exception as e: print(f"  searxng-{inst}: {e}", file=sys.stderr)
    return []

def mojeek_search(q, n):
    try:
        r=safe_get("https://www.mojeek.com/search", params={"q":q})
        if not r or r.status_code==429: raise RuntimeError("429")
        if not r or r.status_code!=200: return []
        from bs4 import BeautifulSoup
        soup=BeautifulSoup(r.text,"html.parser")
        out=[]
        for el in soup.select(".ob, .result")[:n]:
            a=el.select_one("a[href]") if el else None
            if a and a.get("href","").startswith("http"):
                out.append({"url":a["href"],"title":a.get_text(strip=True)[:200],"snippet":el.get_text(strip=True)[:400],"engine":"mojeek"})
        return out
    except RuntimeError: raise
    except Exception as e: print(f"  mojeek: {e}", file=sys.stderr)
    return []

def yandex_search(q, n):
    try:
        r=safe_get("https://yandex.com/search/", params={"text":q})
        if not r or r.status_code==429: raise RuntimeError("429")
        if not r or r.status_code!=200: return []
        from bs4 import BeautifulSoup
        soup=BeautifulSoup(r.text,"html.parser")
        out=[]
        for a in soup.select("a.link, .organic__url")[:n]:
            href=a.get("href","")
            if href.startswith("http"):
                out.append({"url":href,"title":a.get_text(strip=True)[:200],"snippet":href[:400],"engine":"yandex"})
        return out
    except RuntimeError: raise
    except Exception as e: print(f"  yandex: {e}", file=sys.stderr)
    return []

def bing_search(q, n):
    key=os.getenv("BING_API_KEY")
    if not key: return []
    try:
        r=safe_get("https://api.bing.microsoft.com/v7.0/search", headers={"Ocp-Apim-Subscription-Key":key}, params={"q":q,"count":n})
        if not r or r.status_code==429: raise RuntimeError("429")
        if not r or r.status_code!=200: return []
        return [{"url":h.get("url",""),"title":h.get("name",""),"snippet":h.get("snippet","")[:400],"engine":"bing"} for h in r.json().get("webPages",{}).get("value",[])[:n]]
    except RuntimeError: raise
    except Exception as e: print(f"  bing: {e}", file=sys.stderr)
    return []

ENGINES=[
    {"name":"ddg-lite","fn":ddg_lite_search,"delay":1},
    {"name":"brave","fn":brave_search,"delay":2},
    {"name":"searxng","fn":searxng_search,"delay":2},
    {"name":"mojeek","fn":mojeek_search,"delay":2},
    {"name":"yandex","fn":yandex_search,"delay":3},
    {"name":"bing","fn":bing_search,"delay":3, "requires_key":True},
]

def multi_search(queries, per_query=5, engines=None, max_total=30, verbose=True):
    """Execute each dork through engine rotation. Returns deduped rows."""
    if engines is None: engines=ENGINES
    # if no API keys, skip keyed engines
    active=[e for e in engines if not e.get("requires_key") or os.getenv("BING_API_KEY")]
    all_rows=[]
    for qi,q in enumerate(queries):
        if verbose: print(f"[Query {qi+1}/{len(queries)}] {q[:70]}", file=sys.stderr)
        got=False
        for e in active:
            if verbose: print(f"  -> {e['name']}...", file=sys.stderr)
            t0=time.time()
            try:
                rows=e["fn"](q, per_query)
                if rows:
                    all_rows.extend(rows)
                    got=True
                    if verbose: print(f"     {len(rows)} hits ({e['name']})", file=sys.stderr)
                    break
                else:
                    if verbose: print(f"     0 hits", file=sys.stderr)
            except RuntimeError as err:
                msg=str(err)
                if "429" in msg or "429"==msg:
                    if verbose: print(f"     rate-limited, switching engine", file=sys.stderr)
                    time.sleep(e["delay"]+random.uniform(0.5,1.5))
                    continue
                if verbose: print(f"     failed: {msg}", file=sys.stderr)
            except Exception as err:
                if verbose: print(f"     err: {err}", file=sys.stderr)
            # jitter between engines
            time.sleep(e["delay"]+random.uniform(0.3,1.0))
        if not got and verbose: print(f"  (no results for: {q[:50]})", file=sys.stderr)
        if len(all_rows)>=max_total: break
    return dedup(all_rows)

def head_info(url, timeout=10):
    """Lightweight HEAD for document tech hints. Passive only."""
    try:
        r=safe_get(url, timeout=timeout)
        if not r: return {}
        return {"status":r.status_code, "headers":dict(r.headers), "length":len(r.text), "ct":r.headers.get("Content-Type","")}
    except: return {}
