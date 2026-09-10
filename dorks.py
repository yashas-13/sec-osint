"""Dork query generation — dynamic, not fixed list. Covers spec sections 1-13."""
import datetime

def _after_before(after, before):
    s = ""
    if after: s += f' after:{after}'
    if before: s += f' before:{before}'
    return s

def domain_queries(target, after=None, before=None):
    s=_after_before(after, before)
    return [
        f'site:{target}',
        f'site:{target} "security"',
        f'site:{target} "security.txt"',
        f'site:{target} "responsible disclosure"',
        f'site:{target} "bug bounty"',
        f'"{target}" India',
        f'"{target}" cybersecurity',
        f'"{target}" vulnerability{s}',
        f'"{target}" "security advisory"{s}',
    ]

def tech_queries(product, version="", extra="India", after=None, before=None):
    s=_after_before(after, before)
    q=[]
    base=f'"{product}"'
    if version: base=f'"{product} {version}"'
    q += [f'{base} {extra}{s}', f'{base} "version" {extra}{s}', f'{base} "powered by" {extra}{s}', f'{base} "login" {extra}{s}']
    return q

def api_queries(region="India"):
    return [f'inurl:"/api/" {region}', f'inurl:"/api/v1/" {region}', f'inurl:"/api/v2/" {region}', f'inurl:"/graphql" {region}', f'inurl:"/swagger" {region}', f'inurl:"/swagger-ui" {region}', f'inurl:"/openapi" {region}', f'inurl:"/admin/" {region}', f'inurl:"/administrator/" {region}', f'inurl:"/dashboard/" {region}']

def staging_queries(target, region="India"):
    return [f'inurl:"staging" {region}', f'inurl:"uat" {region}', f'inurl:"preprod" {region}', f'inurl:"dev" {region}', f'inurl:"test" {region}', f'"staging" "{target}"', f'"UAT" "{target}"', f'"pre-production" "{target}"']

def error_queries(fingerprint, region="India"):
    return [f'"{fingerprint}" {region}', f'"stack trace" {region}', f'"internal server error" {region}', f'"database error" {region}']

def index_queries(region="India"):
    return [f'"Index of" "backup" {region}', f'"Index of" "uploads" {region}', f'"Index of" "archive" {region}', f'"Index of" "documents" {region}']

def doc_queries(region="India"):
    return [f'filetype:pdf "security audit" {region}', f'filetype:pdf "VAPT" {region}', f'filetype:pdf "penetration testing" {region}', f'filetype:pdf "risk assessment" {region}', f'filetype:xlsx "security" {region}']

def cloud_queries(target):
    return [f'"{target}" "drive.google.com"', f'"{target}" "docs.google.com"', f'"{target}" "sharepoint.com"', f'"{target}" "onedrive"']

def disclosure_queries(target, after=None, before=None):
    s=_after_before(after, before)
    return [f'"{target}" vulnerability{s}', f'"{target}" security incident{s}', f'"{target}" data breach{s}', f'"{target}" CVE{s}', f'"{target}" security advisory{s}']

def vuln_hunt_queries(fingerprint, tech="", region="India"):
    q=[f'"{fingerprint}" {region}', f'"{fingerprint}" "login"', f'"{fingerprint}" "api"', f'"{fingerprint}" -github.com -stackoverflow.com']
    if tech: q.append(f'"{tech}" {region}')
    return q

def combinator_queries(target):
    return [f'site:{target} filetype:pdf', f'site:{target} inurl:api', f'site:{target} inurl:admin', f'site:{target} inurl:swagger', f'site:{target} inurl:staging']

def all_for_target(target, tech="", fingerprint="", cve="", after=None, before=None, region="India"):
    out={}
    out["domain"]=domain_queries(target, after, before)
    if tech: out["technology"]=tech_queries(tech, extra=region, after=after, before=before)
    out["api"]=api_queries(region)
    out["staging"]=staging_queries(target, region)
    out["index"]=index_queries(region)
    out["documents"]=doc_queries(region)
    out["cloud"]=cloud_queries(target)
    out["disclosures"]=disclosure_queries(target, after, before)
    if fingerprint: out["fingerprint"]=vuln_hunt_queries(fingerprint, tech, region)
    if cve: out["cve"]=[f'"{cve}" {region}{_after_before(after,before)}', f'"{cve}" "{target}"']
    out["combinators"]=combinator_queries(target)
    return out
