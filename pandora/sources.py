"""Data sources for the breach hunt.

Each source is a small function that takes the config dict and returns a list of
Finding objects. A source declares:
  - modes:  which run modes it applies to ("surface" and/or "dark")
  - key_of: which config value it needs (None = no API key needed / free)

Sources with a missing/empty required key are skipped gracefully with a log
line, so the tool runs out of the box and lights up more sources as you add
keys. Every network call has a timeout; be polite and stay within each
provider's ToS and rate limits.

IMPORTANT: point these only at your OWN organisation's name / domain / keywords.
"""
from __future__ import annotations

import logging
import time
from typing import Callable

import requests

from .model import Finding

log = logging.getLogger("pandora.sources")

# ---- registry ---------------------------------------------------------------

REGISTRY: dict[str, dict] = {}


def source(name: str, modes: tuple[str, ...], key_of: str | None = None):
    def deco(fn: Callable):
        REGISTRY[name] = {"fn": fn, "modes": modes, "key_of": key_of}
        return fn
    return deco


def _terms(cfg: dict) -> list[str]:
    """All the strings we're hunting for."""
    t = []
    if cfg.get("org_name"):
        t.append(cfg["org_name"])
    t += cfg.get("domains", [])
    t += cfg.get("keywords", [])
    return [x for x in t if x]


def _http() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "pandora/1.0 (org self-monitoring)"})
    return s


UA_TIMEOUT = 20


# ---- SURFACE WEB sources ----------------------------------------------------

@source("crtsh", modes=("surface",), key_of=None)
def crtsh(cfg: dict) -> list[Finding]:
    """Certificate Transparency logs -> subdomains / hosts using your domain.

    Asset discovery: shows the public footprint an attacker also sees. Free.
    """
    out: list[Finding] = []
    sess = _http()
    for dom in cfg.get("domains", []):
        try:
            r = sess.get("https://crt.sh/", params={"q": f"%.{dom}", "output": "json"},
                         timeout=UA_TIMEOUT)
            r.raise_for_status()
            names = set()
            for row in r.json():
                for n in str(row.get("name_value", "")).splitlines():
                    n = n.strip().lower()
                    if n and not n.startswith("*."):
                        names.add(n)
            for host in sorted(names):
                out.append(Finding(
                    source="crtsh", mode="surface",
                    title=f"Certificate host: {host}",
                    url=f"https://crt.sh/?q={host}",
                    snippet="Public TLS certificate references this host.",
                    matched_terms=[dom], severity="info",
                    raw={"host": host, "domain": dom}))
        except Exception as e:  # noqa: BLE001
            log.warning("crtsh failed for %s: %s", dom, e)
        time.sleep(1.0)  # be polite
    return out


@source("search_dorks", modes=("surface",), key_of="serpapi_key")
def search_dorks(cfg: dict) -> list[Finding]:
    """Run leak-focused search queries via SerpAPI (google engine).

    Swap the provider block below if you prefer Brave Search API or Google CSE.
    Dorks target paste sites, public buckets, doc-sharing, and code hosts.
    """
    key = cfg.get("serpapi_key")
    if not key:
        return []
    out: list[Finding] = []
    sess = _http()
    org = cfg.get("org_name", "")
    domains = cfg.get("domains", [])
    dork_targets = cfg.get("dork_sites", [
        "pastebin.com", "ghostbin.com", "throwbin.io", "controlc.com",
        "trello.com", "s3.amazonaws.com", "blob.core.windows.net",
        "storage.googleapis.com", "docs.google.com", "scribd.com",
        "anonfiles.com", "mega.nz",
    ])
    queries: list[str] = []
    if org:
        queries.append(f'"{org}"')
        for site in dork_targets:
            queries.append(f'site:{site} "{org}"')
    for dom in domains:
        queries.append(f'"{dom}"')
        queries.append(f'"@{dom}" (password OR passwd OR login OR credentials)')
        queries.append(f'intext:"{dom}" (filetype:xlsx OR filetype:csv OR filetype:sql)')

    for q in queries:
        try:
            r = sess.get("https://serpapi.com/search.json",
                         params={"engine": "google", "q": q, "num": 20, "api_key": key},
                         timeout=UA_TIMEOUT)
            r.raise_for_status()
            for res in r.json().get("organic_results", []):
                url = res.get("link", "")
                out.append(Finding(
                    source="search_dorks", mode="surface",
                    title=res.get("title", url)[:200],
                    url=url,
                    snippet=res.get("snippet", "")[:400],
                    matched_terms=[t for t in _terms(cfg) if t.lower() in
                                   (res.get("title", "") + res.get("snippet", "") + url).lower()],
                    severity="medium",
                    raw={"query": q}))
        except Exception as e:  # noqa: BLE001
            log.warning("search dork failed (%s): %s", q, e)
        time.sleep(1.5)
    return out


@source("github", modes=("surface",), key_of="github_token")
def github(cfg: dict) -> list[Finding]:
    """GitHub code search for your domain/keywords (leaked configs, creds, dumps)."""
    token = cfg.get("github_token")
    if not token:
        return []
    out: list[Finding] = []
    sess = _http()
    sess.headers.update({"Authorization": f"Bearer {token}",
                         "Accept": "application/vnd.github+json"})
    for term in _terms(cfg):
        try:
            r = sess.get("https://api.github.com/search/code",
                         params={"q": f'"{term}"', "per_page": 30},
                         timeout=UA_TIMEOUT)
            if r.status_code == 403:
                log.warning("github rate-limited; backing off")
                time.sleep(30)
                continue
            r.raise_for_status()
            for item in r.json().get("items", []):
                repo = item.get("repository", {}).get("full_name", "")
                out.append(Finding(
                    source="github", mode="surface",
                    title=f"{repo}/{item.get('path','')}",
                    url=item.get("html_url", ""),
                    snippet=f"'{term}' referenced in public code.",
                    matched_terms=[term], severity="high",
                    raw={"repo": repo, "path": item.get("path")}))
        except Exception as e:  # noqa: BLE001
            log.warning("github search failed (%s): %s", term, e)
        time.sleep(3)  # GitHub code search is heavily rate-limited
    return out


@source("hibp", modes=("surface",), key_of="hibp_key")
def hibp(cfg: dict) -> list[Finding]:
    """Have I Been Pwned — breaches affecting your DOMAIN (requires verified domain + key)."""
    key = cfg.get("hibp_key")
    if not key:
        return []
    out: list[Finding] = []
    sess = _http()
    sess.headers.update({"hibp-api-key": key})
    for dom in cfg.get("domains", []):
        try:
            r = sess.get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{dom}",
                         timeout=UA_TIMEOUT)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            for local_part, breaches in r.json().items():
                out.append(Finding(
                    source="hibp", mode="surface",
                    title=f"Breached account: {local_part}@{dom}",
                    snippet=f"Appears in: {', '.join(breaches)}",
                    matched_terms=[dom], severity="high",
                    raw={"account": f"{local_part}@{dom}", "breaches": breaches}))
        except Exception as e:  # noqa: BLE001
            log.warning("hibp failed for %s: %s", dom, e)
        time.sleep(2)
    return out


@source("leakcheck", modes=("surface",), key_of="leakcheck_key")
def leakcheck(cfg: dict) -> list[Finding]:
    """LeakCheck.io — credential leaks by domain (requires key). DeHashed is a drop-in swap."""
    key = cfg.get("leakcheck_key")
    if not key:
        return []
    out: list[Finding] = []
    sess = _http()
    for dom in cfg.get("domains", []):
        try:
            r = sess.get("https://leakcheck.io/api/v2/query/" + dom,
                         params={"type": "domain"},
                         headers={"X-API-Key": key}, timeout=UA_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            for rec in data.get("result", []):
                out.append(Finding(
                    source="leakcheck", mode="surface",
                    title=f"Credential leak: {rec.get('email','(record)')}",
                    snippet=f"source={rec.get('source',{}).get('name','?')}",
                    matched_terms=[dom], severity="high",
                    raw=rec))
        except Exception as e:  # noqa: BLE001
            log.warning("leakcheck failed for %s: %s", dom, e)
        time.sleep(2)
    return out


# ---- DARK WEB sources -------------------------------------------------------

@source("ahmia", modes=("dark",), key_of=None)
def ahmia(cfg: dict) -> list[Finding]:
    """Ahmia — clearnet-searchable index of Tor (.onion) services. Free.

    This queries an INDEX of the dark web; it does not open .onion sites for you.
    Treat any onion URL it returns as untrusted — do not visit casually.
    """
    import re
    out: list[Finding] = []
    sess = _http()
    for term in _terms(cfg):
        try:
            r = sess.get("https://ahmia.fi/search/", params={"q": term},
                         timeout=UA_TIMEOUT)
            r.raise_for_status()
            # Ahmia returns HTML; pull onion links + surrounding titles simply.
            for m in re.finditer(
                r'href="/search/redirect\?[^"]*redirect_url=([^"&]+)"[^>]*>(.*?)</a>',
                r.text, re.S):
                url = requests.utils.unquote(m.group(1))
                title = re.sub("<[^>]+>", "", m.group(2)).strip()[:200]
                out.append(Finding(
                    source="ahmia", mode="dark",
                    title=title or url,
                    url=url,
                    snippet=f"Onion service indexed by Ahmia mentioning '{term}'.",
                    matched_terms=[term], severity="high",
                    raw={"query": term}))
        except Exception as e:  # noqa: BLE001
            log.warning("ahmia failed (%s): %s", term, e)
        time.sleep(2)
    return out


@source("intelx", modes=("surface", "dark"), key_of="intelx_key")
def intelx(cfg: dict) -> list[Finding]:
    """Intelligence X — leaks, pastes, dark-web and breach data (requires key).

    Runs in BOTH modes: surface run captures pastes/leaks, dark run captures
    tor/breach material. This is the closest thing to a real dark-web feed for
    an individual buyer; commercial feeds (SpyCloud/Flare/Cybersixgill) plug in
    the same way if your hospital procures one.
    """
    key = cfg.get("intelx_key")
    if not key:
        return []
    base = cfg.get("intelx_base", "https://2.intelx.io")
    out: list[Finding] = []
    sess = _http()
    sess.headers.update({"x-key": key})
    for term in _terms(cfg):
        try:
            start = sess.post(f"{base}/intelligent/search",
                              json={"term": term, "maxresults": 50, "media": 0,
                                    "sort": 4, "terminate": []},
                              timeout=UA_TIMEOUT)
            start.raise_for_status()
            sid = start.json().get("id")
            if not sid:
                continue
            time.sleep(2)
            res = sess.get(f"{base}/intelligent/search/result",
                           params={"id": sid, "limit": 50}, timeout=UA_TIMEOUT)
            res.raise_for_status()
            for rec in res.json().get("records", []):
                out.append(Finding(
                    source="intelx",
                    mode="dark" if cfg.get("_mode") == "dark" else "surface",
                    title=rec.get("name", "(record)")[:200],
                    url=f"{base}/file/view?f={rec.get('systemid','')}",
                    snippet=f"bucket={rec.get('bucket','')}",
                    matched_terms=[term], severity="high",
                    raw={"systemid": rec.get("systemid"), "bucket": rec.get("bucket")}))
        except Exception as e:  # noqa: BLE001
            log.warning("intelx failed (%s): %s", term, e)
        time.sleep(2)
    return out


# ---- EXPOSURE / ASSET DISCOVERY sources -------------------------------------

# Ports that shouldn't usually be exposed to the public internet. Any of these
# turning up in a Shodan hit is bumped to "high".
_RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}


@source("shodan", modes=("surface",), key_of="shodan_key")
def shodan(cfg: dict) -> list[Finding]:
    """Shodan — internet-exposed hosts/services tied to your org or domain.

    This is the source that surfaces "shadow IT" like a forgotten panel, an open
    database, or an app someone stood up outside your sanctioned infrastructure.
    Requires a Shodan API key; the search endpoint needs a (cheap) membership.
    """
    key = cfg.get("shodan_key")
    if not key:
        return []
    out: list[Finding] = []
    sess = _http()

    queries: list[str] = []
    if cfg.get("org_name"):
        queries.append(f'org:"{cfg["org_name"]}"')
        queries.append(f'ssl:"{cfg["org_name"]}"')
    for dom in cfg.get("domains", []):
        queries.append(f"hostname:{dom}")
        queries.append(f"ssl.cert.subject.cn:{dom}")

    for q in queries:
        try:
            r = sess.get("https://api.shodan.io/shodan/host/search",
                         params={"key": key, "query": q}, timeout=UA_TIMEOUT)
            if r.status_code == 401:
                log.warning("shodan: invalid API key")
                return out
            r.raise_for_status()
            for m in r.json().get("matches", []):
                port = m.get("port")
                risky = _RISKY_PORTS.get(port)
                hostnames = ", ".join(m.get("hostnames", [])) or m.get("ip_str", "")
                out.append(Finding(
                    source="shodan", mode="surface",
                    title=f"Exposed service {m.get('ip_str','')}:{port}"
                          + (f" ({risky})" if risky else ""),
                    url=f"https://www.shodan.io/host/{m.get('ip_str','')}",
                    snippet=f"host={hostnames} product={m.get('product','?')} "
                            f"org={m.get('org','?')}",
                    matched_terms=[t for t in _terms(cfg)
                                   if t.lower() in str(m).lower()] or [q],
                    severity="high" if risky else "medium",
                    raw={"ip": m.get("ip_str"), "port": port,
                         "product": m.get("product"), "hostnames": m.get("hostnames"),
                         "risky_service": risky}))
        except Exception as e:  # noqa: BLE001
            log.warning("shodan failed (%s): %s", q, e)
        time.sleep(1.5)
    return out


@source("dnstwist", modes=("surface",), key_of=None)
def dnstwist(cfg: dict) -> list[Finding]:
    """dnstwist — registered look-alike / typosquat domains impersonating you.

    High value for a hospital brand (phishing / fake patient portals). Free, but
    needs the dnstwist CLI installed:  pip install dnstwist   (or, on Kali/Debian,
    apt install dnstwist). Skips gracefully if it isn't present.
    """
    import json as _json
    import shutil
    import subprocess

    if shutil.which("dnstwist") is None:
        log.info("dnstwist not installed; skip (pip install dnstwist / apt install dnstwist)")
        return []

    out: list[Finding] = []
    for dom in cfg.get("domains", []):
        try:
            proc = subprocess.run(
                ["dnstwist", "--registered", "--format", "json", dom],
                capture_output=True, text=True, timeout=600)
            records = _json.loads(proc.stdout or "[]")
            for rec in records:
                d = rec.get("domain", "")
                if not d or d == dom:
                    continue
                a = ", ".join(rec.get("dns_a", []) or [])
                out.append(Finding(
                    source="dnstwist", mode="surface",
                    title=f"Look-alike domain registered: {d}",
                    url=f"http://{d}",
                    snippet=f"technique={rec.get('fuzzer','?')} resolves_to={a or 'n/a'}",
                    matched_terms=[dom], severity="high",
                    raw=rec))
        except Exception as e:  # noqa: BLE001
            log.warning("dnstwist failed for %s: %s", dom, e)
    return out
