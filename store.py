"""SQLite memory — spec 16. No secrets, no PII. Avoid repeat reports."""
import sqlite3, json, os, hashlib, time
from pathlib import Path

DB_PATH=Path(os.path.expanduser("~/.sec-osint/db.sqlite3"))

def _con():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c=sqlite3.connect(str(DB_PATH))
    c.execute("PRAGMA journal_mode=WAL")
    return c

def migrate_schema():
    """Add new columns idempotently. Call after init_db()."""
    c=_con()
    cols={row[1] for row in c.execute("PRAGMA table_info(findings)").fetchall()}
    adds=[("priority","TEXT","'P3'"),("status","TEXT","'DISCOVERED'"),("cve_id","TEXT","NULL"),("active_exploitation","INTEGER","0"),("urgent_disclosure","INTEGER","0")]
    for name,dtype,default in adds:
        if name not in cols:
            c.execute(f"ALTER TABLE findings ADD COLUMN {name} {dtype} DEFAULT {default}")
    c.commit(); c.close()

def init_db():
    c=_con()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS targets(domain TEXT PRIMARY KEY, added_at TEXT, industry TEXT, region TEXT);
    CREATE TABLE IF NOT EXISTS findings(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT, fingerprint TEXT, url TEXT, query TEXT, type TEXT,
      severity TEXT, confidence REAL, exposure_class TEXT, evidence TEXT, ts TEXT,
      hash TEXT UNIQUE, reported INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS knowledge(
      key TEXT PRIMARY KEY, value TEXT, updated TEXT
    );
    """)
    c.commit(); c.close()
    migrate_schema()

def add_target(domain, industry="", region=""):
    c=_con()
    c.execute("INSERT OR IGNORE INTO targets(domain,added_at,industry,region) VALUES(?,?,?,?)", (domain, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), industry, region))
    c.commit(); c.close()

def list_targets():
    c=_con(); rows=c.execute("SELECT domain,industry,region,added_at FROM targets ORDER BY added_at").fetchall(); c.close(); return rows

def fingerprint_hash(target, fingerprint, url):
    return hashlib.sha256(f"{target}|{fingerprint}|{url}".encode()).hexdigest()[:16]

def add_finding(target, fingerprint, url, query, ftype, severity, confidence, exposure_class, evidence=""):
    h=fingerprint_hash(target, fingerprint, url)
    c=_con()
    try:
        c.execute("INSERT INTO findings(target,fingerprint,url,query,type,severity,confidence,exposure_class,evidence,ts,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (target,fingerprint,url,query,ftype,severity,confidence,exposure_class,evidence,time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),h))
        c.commit()
        return h
    except sqlite3.IntegrityError:
        return None
    finally: c.close()

def list_findings(target=None, severity=None):
    c=_con()
    q="SELECT id,target,fingerprint,url,query,type,severity,confidence,exposure_class,evidence,ts,reported FROM findings WHERE 1=1"
    p=[]
    if target: q+=" AND target=?"; p.append(target)
    if severity: q+=" AND severity=?"; p.append(severity.upper())
    q+=" ORDER BY ts DESC"
    rows=c.execute(q,p).fetchall(); c.close(); return rows

def mark_reported(fid):
    c=_con(); c.execute("UPDATE findings SET reported=1 WHERE id=?",(fid,)); c.commit(); c.close()

def dedup_fingerprints():
    c=_con(); rows=c.execute("SELECT fingerprint, url, COUNT(*) c FROM findings GROUP BY fingerprint,url HAVING c>1").fetchall(); c.close(); return rows

def is_duplicate(target,fingerprint,url):
    c=_con(); r=c.execute("SELECT 1 FROM findings WHERE hash=?",(fingerprint_hash(target,fingerprint,url),)).fetchone(); c.close(); return r is not None

def set_finding_priority(fid: int, priority: str, urgent_disclosure: bool=False, active_exploitation: bool=False):
    c=_con(); c.execute("UPDATE findings SET priority=?, urgent_disclosure=?, active_exploitation=? WHERE id=?", (priority, 1 if urgent_disclosure else 0, 1 if active_exploitation else 0, fid)); c.commit(); c.close()

def set_finding_status(fid: int, status: str):
    c=_con(); c.execute("UPDATE findings SET status=? WHERE id=?", (status, fid)); c.commit(); c.close()

def list_by_priority(priority=None, target=None, status=None, urgent_only=False):
    q="SELECT id,target,fingerprint,url,query,type,severity,confidence,exposure_class,evidence,ts,reported,priority,status,cve_id,active_exploitation,urgent_disclosure FROM findings WHERE 1=1"
    p=[]
    if priority: q+=" AND priority=?"; p.append(priority.upper())
    if target: q+=" AND target=?"; p.append(target)
    if status: q+=" AND status=?"; p.append(status.upper())
    if urgent_only: q+=" AND urgent_disclosure=1"
    q+=" ORDER BY CASE priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END, confidence DESC, id ASC"
    c=_con(); rows=c.execute(q,p).fetchall(); c.close(); return rows

def list_urgent():
    return list_by_priority(urgent_only=True)

init_db()
