"""Redaction — never output secret values. Spec sections 5,10,14."""
import re
_PATTERNS=[
    (re.compile(r'(?i)(api[_-]?key\s*[:=]\s*)["\']?([A-Za-z0-9_\-]{16,})["\']?',re.I), r'\1[REDACTED_SECRET]'),
    (re.compile(r'(?i)(secret\s*[:=]\s*)["\']?([A-Za-z0-9_\-]{16,})["\']?',re.I), r'\1[REDACTED_SECRET]'),
    (re.compile(r'(?i)(password\s*[:=]\s*)["\']?([^\s"\']{6,})["\']?',re.I), r'\1[REDACTED_SECRET]'),
    (re.compile(r'(?i)(access[_-]?token\s*[:=]\s*)["\']?([A-Za-z0-9_\-\.]{16,})["\']?',re.I), r'\1[REDACTED_SECRET]'),
    (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----',re.S), '[REDACTED_PRIVATE_KEY]'),
    (re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{16,})["\']?',re.I), r'\1=[REDACTED_SECRET]'),
    (re.compile(r'sk-[A-Za-z0-9]{20,}'), '[REDACTED_SECRET]'),
    (re.compile(r'ghp_[A-Za-z0-9]{30,}'), '[REDACTED_SECRET]'),
]
_SENSITIVE_HINTS=["password","api_key","apikey","secret","credential","private key","session","cookie","personal data","database dump"]

def redact(text:str)->str:
    if not text: return text
    for pat,repl in _PATTERNS:
        text=pat.sub(repl, text)
    return text

def contains_sensitive(text:str)->bool:
    low=text.lower()
    return any(h in low for h in _SENSITIVE_HINTS)

def safe_fingerprint(text:str, max_len=200)->str:
    t=redact(text)
    if len(t)>max_len: t=t[:max_len]+"…"
    return t

# spec 14: halt message
HALT_MSG="Sensitive material detected. Collection halted. Value redacted. No authentication or exploitation performed."
