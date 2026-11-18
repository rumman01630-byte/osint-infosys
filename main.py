"""
OSINT Infosys v0.18.1 — multi-source email intelligence (memory-safe)
Fixes: Sherlock targets 3->1, verify limit 15->10, frontend JSON guard
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

import dns.asyncresolver
import dns.resolver
import httpx
import phonenumbers
import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet, InvalidToken
from email_validator import EmailNotValidError, validate_email
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from phonenumbers import carrier as pn_carrier
from phonenumbers import geocoder as pn_geocoder
from pydantic import BaseModel, Field

VERSION = "0.18.1"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
API_TOKEN = os.environ.get("OSINT_API_TOKEN", "").strip()
DATA_ENCRYPTION_KEY = os.environ.get("DATA_ENCRYPTION_KEY", "").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL required")
if len(API_TOKEN) < 32:
    raise RuntimeError("OSINT_API_TOKEN must be 32+ chars")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("osint")

if DATA_ENCRYPTION_KEY:
    try:
        cipher = Fernet(DATA_ENCRYPTION_KEY.encode())
    except Exception:
        _DK = hashlib.pbkdf2_hmac("sha256", DATA_ENCRYPTION_KEY.encode(),
                                   b"osint-infosys-v0161-salt", 100_000, dklen=32)
        cipher = Fernet(base64.urlsafe_b64encode(_DK))
    _HMAC = hashlib.pbkdf2_hmac("sha256", DATA_ENCRYPTION_KEY.encode(),
                                 b"osint-infosys-v0161-hmac", 100_000, dklen=32)
else:
    _DK = hashlib.pbkdf2_hmac("sha256", API_TOKEN.encode(),
                               b"osint-infosys-v0151-key-derivation", 100_000, dklen=32)
    cipher = Fernet(base64.urlsafe_b64encode(_DK))
    _HMAC = _DK

_LEGACY = Fernet(base64.urlsafe_b64encode(
    hashlib.pbkdf2_hmac("sha256", API_TOKEN.encode(),
                        b"osint-infosys-v0151-key-derivation", 100_000, dklen=32)))


def keyed_hash(s: str) -> str:
    return hmac.new(_HMAC, s.lower().encode(), hashlib.sha256).hexdigest()


def decrypt_fallback(ct: str) -> str:
    try:
        return cipher.decrypt(ct.encode()).decode()
    except InvalidToken:
        return _LEGACY.decrypt(ct.encode()).decode()


app = FastAPI(title="OSINT Infosys", version=VERSION)
SEM = asyncio.Semaphore(2)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_sherlock = False

BD_PREFIX = {"013": "Grameenphone", "017": "Grameenphone", "014": "Banglalink",
             "019": "Banglalink", "015": "Teletalk", "016": "Airtel", "018": "Robi"}

NF_MARKERS = ["user not found", "page not found", "couldn't find", "could not find",
              "doesn't exist", "does not exist", "no user", "account not found",
              "profile not found", "404 not found", "this page isn't available",
              "this account doesn't exist", "this account is not available",
              "no longer available", "page doesn't exist", "we can't find",
              "we couldn't find", "sorry, this page"]


@contextmanager
def db():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require", connect_timeout=10)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS jobs_v0151 (
                    job_id UUID PRIMARY KEY,
                    job_type TEXT NOT NULL DEFAULT 'email',
                    status TEXT NOT NULL,
                    email_ciphertext TEXT NOT NULL,
                    email_sha256 TEXT NOT NULL,
                    result_ciphertext TEXT,
                    error TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    started_at TIMESTAMPTZ,
                    last_heartbeat_at TIMESTAMPTZ,
                    completed_at TIMESTAMPTZ
                )
            """)


async def reaper():
    while True:
        try:
            await asyncio.sleep(120)
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE jobs_v0151 SET status='interrupted',
                        error='Job interrupted — heartbeat stale.',
                        completed_at=NOW(), updated_at=NOW()
                        WHERE status='running'
                        AND (last_heartbeat_at IS NULL
                             OR last_heartbeat_at < NOW() - INTERVAL '10 minutes')
                    """)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.error("Reaper: %s", e)


@app.on_event("startup")
async def on_start():
    global _sherlock
    init_db()
    for cmd in [["sherlock", "--version"],
                [sys.executable, "-m", "sherlock_project", "--version"]]:
        try:
            p = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(p.wait(), timeout=10)
            _sherlock = True
            log.info("Sherlock: available via %s", " ".join(cmd[:2]))
            break
        except Exception:
            continue
    if not _sherlock:
        log.warning("Sherlock: not available — username auto-pivot disabled")
    asyncio.create_task(reaper())
    log.info("OSINT Infosys %s initialized", VERSION)


@app.head("/")
async def head():
    return {}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "version": VERSION, "sherlock": _sherlock}


def auth(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer required")
    if not secrets.compare_digest(authorization[7:].strip(), API_TOKEN):
        raise HTTPException(401, "Invalid token")


def norm_email(v: str):
    try:
        c = validate_email(v.strip(), check_deliverability=False)
        l, d = c.normalized.rsplit("@", 1)
        return f"{l}@{d.lower()}", d.lower()
    except EmailNotValidError as e:
        raise HTTPException(422, str(e))


def norm_domain(v: str):
    d = v.strip().lower()
    if d.startswith(("http://", "https://")):
        d = urlparse(d).hostname or ""
    d = d.split("/")[0].rstrip(".")
    if not DOMAIN_RE.match(d):
        raise HTTPException(422, f"Invalid domain: {v}")
    return d


def parse_phone(raw: str):
    try:
        n = phonenumbers.parse(raw.strip(), None)
    except Exception as e:
        raise HTTPException(422, f"Invalid phone: {e}")
    if not phonenumbers.is_possible_number(n):
        raise HTTPException(422, "Invalid phone length")
    return {
        "valid": phonenumbers.is_valid_number(n),
        "e164": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164),
        "national": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL),
        "country": phonenumbers.region_code_for_number(n) or "Unknown",
        "carrier": pn_carrier.name_for_number(n, "en") or "Unknown",
        "location": pn_geocoder.description_for_number(n, "en") or "Unknown",
        "line_type": {0: "mobile", 1: "fixed_line", 2: "fixed_or_mobile", 3: "toll_free",
                      4: "premium", 5: "shared", 6: "voip", 7: "personal", 8: "pager",
                      9: "uan", 10: "voicemail", -1: "unknown"}.get(
                      phonenumbers.number_type(n), "unknown"),
    }


def derive_usernames(email: str, limit: int = 6) -> list[str]:
    local = email.split("@")[0].split("+")[0].lower().strip()
    if not local:
        return []
    out = []
    def add(v):
        if v and v not in out and USERNAME_RE.match(v):
            out.append(v)
    add(local)
    add(local.replace(".", ""))
    add(local.replace(".", "_"))
    add(local.replace(".", "-"))
    if "." in local:
        add(local.split(".")[0])
        add(local.split(".")[-1])
    return out[:limit]


def srec(source, status, method, **kw):
    return {"source": source, "status": status, "method": method,
            "observed_at": datetime.now(timezone.utc).isoformat(), **kw}


def clean(v: str):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", " ", v))).strip()


def safe_url(u: str):
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


async def dns_check(domain):
    r = dns.asyncresolver.Resolver()
    r.lifetime = 5.0
    out = {}
    for label, qtype, qname in [
        ("MX", "MX", domain), ("A", "A", domain), ("AAAA", "AAAA", domain),
        ("NS", "NS", domain), ("TXT", "TXT", domain),
        ("SPF", "TXT", domain), ("DMARC", "TXT", f"_dmarc.{domain}")]:
        try:
            a = await r.resolve(qname, qtype, raise_on_no_answer=False)
            vals = []
            if a.rrset:
                for it in a:
                    if qtype == "MX":
                        vals.append(str(it.exchange).rstrip("."))
                    elif qtype in ("A", "AAAA"):
                        vals.append(str(it))
                    elif qtype == "NS":
                        vals.append(str(it).rstrip("."))
                    else:
                        vals.append("".join(p.decode("utf-8", "replace") for p in it.strings))
            if label == "SPF":
                vals = [v for v in vals if v.lower().startswith("v=spf1")]
            if label == "DMARC":
                vals = [v for v in vals if v.lower().startswith("v=dmarc1")]
            out[label] = srec("DNS", "found" if vals else "not_found",
                              f"DNS {qtype}", query=qname, values=vals)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            out[label] = srec("DNS", "not_found", f"DNS {qtype}", query=qname, values=[])
        except Exception as e:
            out[label] = srec("DNS", "error", f"DNS {qtype}", query=qname, error=type(e).__name__)
    return out


async def rdap_check(domain):
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True,
                                     headers={"User-Agent": "OSINT-Infosys/0.18"}) as c:
            r = await c.get(f"https://rdap.org/domain/{domain}")
        if r.status_code == 404:
            return srec("RDAP", "not_found", "registration")
        if r.status_code != 200:
            return srec("RDAP", "unavailable", "registration", http_status=r.status_code)
        d = r.json()
        reg = "Unknown"
        for e in d.get("entities", []) or []:
            if "registrar" in (e.get("roles") or []):
                v = e.get("vcardArray", [None, []])
                for it in (v[1] if len(v) > 1 else []):
                    if it[0] == "fn":
                        reg = it[3] or "Unknown"
                        break
                break
        ev = {x.get("eventAction"): x.get("eventDate")
              for x in d.get("events", []) or [] if x.get("eventDate")}
        ns = [n.get("ldhName") for n in d.get("nameservers", []) or [] if n.get("ldhName")]
        return srec("RDAP", "found", "registration", registrar=reg, events=ev,
                    nameservers=ns, status_flags=d.get("status", []))
    except httpx.TimeoutException:
        return srec("RDAP", "unavailable", "registration", error="timeout")
    except Exception as e:
        return srec("RDAP", "error", "registration", error=type(e).__name__)


async def crtsh_check(domain):
    try:
        async with httpx.AsyncClient(timeout=25,
                                     headers={"User-Agent": "OSINT-Infosys/0.18"}) as c:
            r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if r.status_code == 429:
            return srec("crt.sh", "rate_limited", "CT")
        if r.status_code != 200:
            return srec("crt.sh", "unavailable", "CT", http_status=r.status_code)
        d = r.json()
        if not isinstance(d, list):
            return srec("crt.sh", "error", "CT", error="unexpected")
        hosts = set()
        for row in d:
            for n in str(row.get("name_value", "")).split("\n"):
                n = n.strip().lower().replace("*.", "")
                if n and (n == domain or n.endswith("." + domain)):
                    hosts.add(n)
        lst = sorted(hosts)[:100]
        return srec("crt.sh", "found" if lst else "not_found", "CT",
                    hosts=lst, total=len(hosts))
    except Exception as e:
        return srec("crt.sh", "error", "CT", error=type(e).__name__)


def unwrap_ddg(h):
    try:
        p = urlparse(h)
        if "duckduckgo.com" in (p.hostname or ""):
            t = parse_qs(p.query).get("uddg", [])
            if t:
                return unquote(t[0])
        return h
    except Exception:
        return h


async def search(provider, q, limit=12):
    h = {"User-Agent": "OSINT-Infosys/0.18"}
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                     max_redirects=5, headers=h) as c:
            if provider == "DuckDuckGo":
                r = await c.post("https://html.duckduckgo.com/html/", data={"q": q})
            else:
                r = await c.get("https://www.bing.com/search", params={"q": q})
        if r.status_code == 429:
            return srec(provider, "rate_limited", "search", results=[])
        if r.status_code in (401, 403, 407):
            return srec(provider, "blocked", "search", results=[], http_status=r.status_code)
        if r.status_code != 200:
            return srec(provider, "unavailable", "search", results=[], http_status=r.status_code)
        pg = r.text
        low = pg.lower()
        if any(m in low for m in ("captcha", "unusual traffic", "verify you are human",
                                   "consent required", "robot check")):
            return srec(provider, "blocked", "challenge", results=[])
        res = []
        if provider == "DuckDuckGo":
            for href, title in re.findall(
                r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                pg, re.I | re.S)[:limit]:
                u = unwrap_ddg(html.unescape(href))
                if safe_url(u):
                    res.append({"title": clean(title)[:200], "url": u[:1000], "snippet": ""})
        else:
            for href, title, body in re.findall(
                r'<li[^>]+class="[^"]*b_algo[^"]*"[^>]*>.*?<h2[^>]*>.*?<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?</h2>(.*?)(?=<li[^>]+class="[^"]*b_algo|$)',
                pg, re.I | re.S)[:limit]:
                u = html.unescape(href)
                if safe_url(u):
                    sm = re.search(r"<p[^>]*>(.*?)</p>", body, re.I | re.S)
                    snip = clean(sm.group(1))[:400] if sm else ""
                    res.append({"title": clean(title)[:200], "url": u[:1000], "snippet": snip})
        if res:
            return srec(provider, "found", "search", results=res)
        nrm = ("no results found", "there are no results for", "no results for")
        return srec(provider, "not_found" if any(m in low for m in nrm) else "unavailable",
                    "search", results=[])
    except httpx.TimeoutException:
        return srec(provider, "unavailable", "search", results=[], error="timeout")
    except Exception as e:
        return srec(provider, "error", "search", results=[], error=type(e).__name__)


async def holehe(email):
    for cmd in [["holehe", email, "--no-color"],
                [sys.executable, "-m", "holehe", email, "--no-color"]]:
        try:
            p = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                so, se = await asyncio.wait_for(p.communicate(), timeout=150)
            except asyncio.TimeoutError:
                p.kill()
                await p.wait()
                return srec("Holehe", "error", "CLI", found=[], not_found=[],
                            rate_limited=[], error="timeout")
            out = so.decode("utf-8", "replace")
            f, nf, rl, bl = [], [], [], []
            rec = 0
            for ln in out.splitlines():
                ln = ln.strip()
                if not ln or "Email used" in ln or "Email not used" in ln or "Rate limit" in ln:
                    continue
                if ln.startswith("[+]"):
                    s = ln[3:].strip()
                    if s:
                        f.append(s)
                        rec += 1
                elif ln.startswith("[-]"):
                    s = ln[3:].strip()
                    if s:
                        nf.append(s)
                        rec += 1
                elif ln.startswith("[x]"):
                    s = ln[3:].strip()
                    if s:
                        rl.append(s)
                        rec += 1
                elif "blocked" in ln.lower():
                    bl.append(ln[:180])
            if rec == 0:
                return srec("Holehe", "error", "CLI", found=[], not_found=[],
                            rate_limited=[], parser="unrecognized", error="No lines")
            st = "found" if f else ("rate_limited" if rl else ("blocked" if bl else ("not_found" if nf else "unavailable")))
            return srec("Holehe", st, "CLI",
                        found=list(dict.fromkeys(f)),
                        not_found=list(dict.fromkeys(nf)),
                        rate_limited=list(dict.fromkeys(rl)),
                        blocked=bl, parser="recognized",
                        limitation="Association signals only.")
        except FileNotFoundError:
            continue
        except Exception as e:
            log.warning("Holehe: %s", e)
    return srec("Holehe", "unavailable", "CLI", found=[], not_found=[],
                rate_limited=[], error="not installed")


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)


async def verify_url(url):
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, max_redirects=3,
                                     headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-Infosys/0.18)"}) as c:
            r = await c.get(url)
        if r.status_code == 404:
            return False, "HTTP 404"
        if r.status_code >= 400:
            return None, f"HTTP {r.status_code}"
        low = r.text.lower()[:50000]
        for m in NF_MARKERS:
            if m in low:
                return False, f"contains '{m}'"
        return True, "content check"
    except httpx.TimeoutException:
        return None, "timeout"
    except Exception as e:
        return None, type(e).__name__


async def sherlock(username, timeout=240.0):
    for cmd in [
        ["sherlock", username, "--print-found", "--no-color", "--timeout", "8"],
        [sys.executable, "-m", "sherlock_project", username, "--print-found", "--no-color", "--timeout", "8"]]:
        try:
            p = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                so, se = await asyncio.wait_for(p.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                p.kill()
                await p.wait()
                return {"username": username, "status": "timeout", "found": [], "error": "timeout"}
            out = strip_ansi(so.decode("utf-8", "replace"))
            err = se.decode("utf-8", "replace")
            f = []
            for ln in out.splitlines():
                ln = ln.strip()
                if not ln.startswith("[+]"):
                    continue
                m = re.search(r'\[\+\]\s*(.+?)\s*[:\-]\s*(https?://\S+)', ln)
                if m and safe_url(m.group(2)):
                    f.append({"platform": m.group(1).strip().rstrip(":").strip(),
                              "url": m.group(2).strip()})
            seen = set()
            uq = []
            for x in f:
                if x["url"] not in seen:
                    seen.add(x["url"])
                    uq.append(x)
            if not uq:
                if any(k in err.lower() for k in ("captcha", "forbidden", "blocked", "429")):
                    return {"username": username, "status": "blocked", "found": [], "error": "blocked"}
                return {"username": username, "status": "not_found", "found": [], "total_found": 0}
            return {"username": username, "status": "found", "found": uq, "total_found": len(uq)}
        except FileNotFoundError:
            continue
        except Exception as e:
            log.warning("Sherlock: %s", e)
    return {"username": username, "status": "unavailable", "found": [], "error": "not installed"}


async def verify_sherlock(found, limit=10):
    if not found:
        return []
    sem = asyncio.Semaphore(5)
    top = found[:limit]
    rest = found[limit:]

    async def one(item):
        async with sem:
            ok, note = await verify_url(item["url"])
            st = "found" if ok is True else ("not_verified" if ok is False else "unverified")
            return {**item, "verified": ok, "verification_note": note, "final_status": st}

    results = await asyncio.gather(*[one(i) for i in top], return_exceptions=True)
    out = []
    for item, r in zip(top, results):
        if isinstance(r, Exception):
            out.append({**item, "verified": None,
                        "verification_note": "error", "final_status": "unverified"})
        else:
            out.append(r)
    for item in rest:
        out.append({**item, "verified": None,
                    "verification_note": "limit reached", "final_status": "unverified"})
    return out


async def gravatar_profile(email):
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True,
                                     headers={"User-Agent": "OSINT-Infosys/0.18"}) as c:
            r = await c.get(f"https://www.gravatar.com/{md5}.json")
        if r.status_code == 404:
            return srec("Gravatar Profile", "not_found", "profile JSON")
        if r.status_code != 200:
            return srec("Gravatar Profile", "unavailable", "profile JSON", http_status=r.status_code)
        try:
            data = r.json()
        except Exception:
            return srec("Gravatar Profile", "not_found", "profile JSON (empty)")
        entry = (data.get("entry") or [{}])[0]
        if not entry:
            return srec("Gravatar Profile", "not_found", "profile JSON")
        accounts = entry.get("accounts", []) or []
        urls = entry.get("urls", []) or []
        return srec("Gravatar Profile", "found", "profile JSON",
                    display_name=entry.get("displayName"),
                    about=entry.get("aboutMe"),
                    location=entry.get("currentLocation"),
                    thumbnail=entry.get("thumbnailUrl"),
                    accounts=[{"domain": a.get("domain"), "username": a.get("username"),
                               "url": a.get("url"), "verified": a.get("verified")}
                              for a in accounts],
                    urls=[{"title": u.get("title"), "value": u.get("value")} for u in urls],
                    limitation="Gravatar profile is self-declared by the account owner.")
    except Exception as e:
        return srec("Gravatar Profile", "error", "profile JSON", error=type(e).__name__)


async def keybase_lookup(email):
    try:
        async with httpx.AsyncClient(timeout=10,
                                     headers={"User-Agent": "OSINT-Infosys/0.18"}) as c:
            r = await c.get(f"https://keybase.io/_/api/1.0/user/lookup.json?email={quote(email)}")
        if r.status_code != 200:
            return srec("Keybase", "unavailable", "user lookup", http_status=r.status_code)
        data = r.json()
        if (data.get("status") or {}).get("code") != 0:
            return srec("Keybase", "not_found", "user lookup")
        them = data.get("them")
        if not them:
            return srec("Keybase", "not_found", "user lookup")
        user = them[0] if isinstance(them, list) else them
        basics = user.get("basics", {}) or {}
        profile = user.get("profile", {}) or {}
        proofs = ((user.get("proofs_summary") or {}).get("all") or [])
        if not basics.get("username"):
            return srec("Keybase", "not_found", "user lookup")
        return srec("Keybase", "found", "user lookup",
                    username=basics.get("username"),
                    full_name=profile.get("full_name"),
                    location=profile.get("location"),
                    bio=profile.get("bio"),
                    proofs=[{"platform": p.get("proof_type"), "username": p.get("nametag"),
                             "url": p.get("service_url")} for p in proofs],
                    limitation="Keybase proofs are self-declared and cryptographically verifiable.")
    except Exception as e:
        return srec("Keybase", "error", "user lookup", error=type(e).__name__)


async def hackernews_search(email):
    try:
        async with httpx.AsyncClient(timeout=12,
                                     headers={"User-Agent": "OSINT-Infosys/0.18"}) as c:
            r = await c.get("https://hn.algolia.com/api/v1/search",
                            params={"query": email, "tags": "comment", "hitsPerPage": 20})
        if r.status_code != 200:
            return srec("HackerNews", "unavailable", "Algolia", http_status=r.status_code)
        data = r.json()
        hits = data.get("hits", [])
        if not hits:
            return srec("HackerNews", "not_found", "Algolia")
        results = []
        for h in hits[:15]:
            results.append({
                "author": h.get("author"),
                "story_title": h.get("story_title") or h.get("title"),
                "comment_excerpt": (h.get("comment_text") or "")[:200],
                "created_at": h.get("created_at"),
                "url": f"https://news.ycombinator.com/item?id={h.get('objectID')}",
            })
        return srec("HackerNews", "found", "Algolia", results=results, total=len(hits),
                    limitation="Public HN comments only.")
    except Exception as e:
        return srec("HackerNews", "error", "Algolia", error=type(e).__name__)


async def pgp_check(email):
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True,
                                     headers={"User-Agent": "OSINT-Infosys/0.18"}) as c:
            r = await c.get(f"https://keys.openpgp.org/vks/v1/by-email/{quote(email)}")
        if r.status_code == 200 and "BEGIN PGP" in r.text:
            return srec("PGP Keyserver", "found", "keys.openpgp.org",
                        key_type="OpenPGP",
                        key_id=r.headers.get("x-keyid") or "present",
                        limitation="Public PGP key exists for this email.")
        if r.status_code == 404:
            return srec("PGP Keyserver", "not_found", "keys.openpgp.org")
        return srec("PGP Keyserver", "unavailable", "keys.openpgp.org", http_status=r.status_code)
    except Exception as e:
        return srec("PGP Keyserver", "error", "keys.openpgp.org", error=type(e).__name__)


async def phone_check(phone):
    info = parse_phone(phone)
    e164 = info["e164"]
    bd = None
    if e164.startswith("+880"):
        bd = BD_PREFIX.get(e164[4:7])
    queries = [
        {"tool": "Google · exact", "url": f"https://www.google.com/search?q={quote(e164)}"},
        {"tool": "Bing · exact", "url": f"https://www.bing.com/search?q={quote(e164)}"},
        {"tool": "Truecaller (manual)", "url": f"https://www.truecaller.com/search/bd/{quote(e164.replace('+',''))}"},
        {"tool": "WhatsApp (manual)", "url": f"https://wa.me/{quote(e164.replace('+','').replace(' ',''))}"},
        {"tool": "Sync.me (manual)", "url": "https://sync.me/"},
    ]
    return {"parsed": info, "bd_prefix_carrier": bd, "manual_queries": queries,
            "assessment": {"conclusion": "unresolved",
                           "note": "Numbering metadata inferred from E.164. Carrier may be inaccurate (MNP, VoIP)."}}


async def domain_check(domain):
    dns_r, rdap_r, ct_r = await asyncio.gather(
        dns_check(domain), rdap_check(domain), crtsh_check(domain),
        return_exceptions=True)

    def u(r, d):
        return d if isinstance(r, Exception) else r

    return {"domain": domain,
            "dns": u(dns_r, {}),
            "rdap": u(rdap_r, srec("RDAP", "error", "lookup", error="exc")),
            "crtsh": u(ct_r, srec("crt.sh", "error", "lookup", error="exc")),
            "assessment": {"conclusion": "unresolved",
                           "note": "DNS, RDAP, CT are public records. Do not establish ownership."}}


async def heartbeat(job_id, stop):
    while not stop.is_set():
        try:
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE jobs_v0151 SET last_heartbeat_at=NOW(), "
                                "updated_at=NOW() WHERE job_id=%s AND status='running'",
                                (job_id,))
        except Exception:
            pass
        try:
            await asyncio.wait_for(stop.wait(), timeout=20)
        except asyncio.TimeoutError:
            pass


async def run_job(job_id, kind, payload):
    async with SEM:
        stop = asyncio.Event()
        hb = asyncio.create_task(heartbeat(job_id, stop))
        try:
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE jobs_v0151 SET status='running', started_at=NOW(), "
                                "last_heartbeat_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                                (job_id,))
            result = None
            if kind == "email":
                result = await _email(payload)
            elif kind == "username":
                result = await _username(payload)
            elif kind == "phone":
                result = await _phone(payload)
            elif kind == "domain":
                result = await _domain(payload)
            ct = cipher.encrypt(json.dumps(result).encode()).decode()
            with db() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE jobs_v0151 SET status='done', result_ciphertext=%s, "
                                "error=NULL, completed_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                                (ct, job_id))
        except Exception as e:
            log.exception("Job %s failed", job_id)
            try:
                with db() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE jobs_v0151 SET status='failed', error=%s, "
                                    "completed_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                                    (type(e).__name__, job_id))
            except Exception:
                pass
        finally:
            stop.set()
            hb.cancel()
            try:
                await hb
            except Exception:
                pass


async def _email(email):
    domain = email.split("@")[1]
    derived = derive_usernames(email, 6)
    sherlock_targets = derived[:1] if _sherlock else []

    tasks = {
        "holehe": holehe(email),
        "dns": dns_check(domain),
        "duckduckgo": search("DuckDuckGo", f'"{email}"'),
        "bing": search("Bing", f'"{email}"'),
        "gravatar": gravatar_profile(email),
        "keybase": keybase_lookup(email),
        "hackernews": hackernews_search(email),
        "pgp": pgp_check(email),
    }
    sherlock_tasks = {f"sherlock:{u}": sherlock(u, 240) for u in sherlock_targets}

    combined = await asyncio.gather(
        *tasks.values(), *sherlock_tasks.values(), return_exceptions=True)
    results = dict(zip(list(tasks.keys()) + list(sherlock_tasks.keys()), combined))

    def u(k, default):
        r = results.get(k, default)
        return default if isinstance(r, Exception) else r

    sherlock_results = []
    for target in sherlock_targets:
        r = results.get(f"sherlock:{target}",
                        {"username": target, "status": "error",
                         "found": [], "error": "exc"})
        if isinstance(r, Exception):
            sherlock_results.append({"username": target, "status": "error",
                                     "found": [], "error": "exc"})
        else:
            verified = await verify_sherlock(r.get("found", []), limit=10)
            sherlock_results.append({**r, "found": verified})

    ddg = u("duckduckgo", srec("DuckDuckGo", "error", "search", results=[]))
    bing = u("bing", srec("Bing", "error", "search", results=[]))
    refs = []
    seen = set()
    for pr in (ddg, bing):
        for item in pr.get("results", []):
            if item["url"] in seen:
                continue
            seen.add(item["url"])
            refs.append({**item, "discovery_source": pr["source"]})

    return {
        "schema_version": "0.18",
        "job_type": "email",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "derived_usernames": derived,
        "sherlock_auto_investigated": sherlock_targets,
        "sherlock": sherlock_results,
        "sources": {
            "dns": u("dns", {}),
            "holehe": u("holehe", srec("Holehe", "error", "CLI",
                                        found=[], not_found=[], rate_limited=[])),
            "duckduckgo": ddg,
            "bing": bing,
            "gravatar_profile": u("gravatar",
                                   srec("Gravatar Profile", "error", "profile")),
            "keybase": u("keybase", srec("Keybase", "error", "lookup")),
            "hackernews": u("hackernews", srec("HackerNews", "error", "Algolia")),
            "pgp": u("pgp", srec("PGP Keyserver", "error", "lookup")),
        },
        "public_references": refs,
        "assessment": {"conclusion": "unresolved",
                       "note": "Observations are leads only. No result establishes account ownership."},
    }


async def _username(username):
    r = await sherlock(username, 280)
    if r.get("found"):
        r["found"] = await verify_sherlock(r["found"], limit=20)
    return {"schema_version": "0.18", "job_type": "username",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "username": username, "sherlock": r,
            "assessment": {"conclusion": "unresolved",
                           "note": "Public profile URLs are candidates. Verify each manually."}}


async def _phone(p):
    return {"schema_version": "0.18", "job_type": "phone",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            **(await phone_check(p))}


async def _domain(d):
    return {"schema_version": "0.18", "job_type": "domain",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            **(await domain_check(d))}


class EReq(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class UReq(BaseModel):
    username: str = Field(min_length=2, max_length=64)


class PReq(BaseModel):
    phone: str = Field(min_length=5, max_length=30)


class DReq(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


def new_job(kind, payload):
    jid = str(uuid.uuid4())
    enc = cipher.encrypt(payload.encode()).decode()
    dig = keyed_hash(payload)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO jobs_v0151 "
                        "(job_id,job_type,status,email_ciphertext,email_sha256) "
                        "VALUES (%s,%s,'pending',%s,%s)", (jid, kind, enc, dig))
    return jid


@app.post("/api/check", dependencies=[Depends(auth)])
async def api_email(req: EReq, bg: BackgroundTasks):
    em, _ = norm_email(req.email)
    jid = new_job("email", em)
    bg.add_task(run_job, jid, "email", em)
    return {"jobId": jid}


@app.post("/api/check-username", dependencies=[Depends(auth)])
async def api_username(req: UReq, bg: BackgroundTasks):
    u = req.username.strip()
    if not USERNAME_RE.match(u):
        raise HTTPException(400, "Invalid username")
    jid = new_job("username", f"username:{u}")
    bg.add_task(run_job, jid, "username", u)
    return {"jobId": jid}


@app.post("/api/check-phone", dependencies=[Depends(auth)])
async def api_phone(req: PReq, bg: BackgroundTasks):
    info = parse_phone(req.phone)
    jid = new_job("phone", f"phone:{info['e164']}")
    bg.add_task(run_job, jid, "phone", req.phone)
    return {"jobId": jid}


@app.post("/api/check-domain", dependencies=[Depends(auth)])
async def api_domain(req: DReq, bg: BackgroundTasks):
    d = norm_domain(req.domain)
    jid = new_job("domain", f"domain:{d}")
    bg.add_task(run_job, jid, "domain", d)
    return {"jobId": jid}


@app.get("/api/job/{job_id}", dependencies=[Depends(auth)])
async def get_job(job_id: str):
    try:
        uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(400, "Invalid job ID")
    with db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT job_id,job_type,status,result_ciphertext,error,"
                        "created_at,updated_at,started_at,completed_at,last_heartbeat_at "
                        "FROM jobs_v0151 WHERE job_id=%s", (job_id,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Not found")
    p = dict(row)
    ct = p.pop("result_ciphertext", None)
    if ct:
        try:
            p["result"] = json.loads(decrypt_fallback(ct))
        except Exception:
            p["result"] = None
            p["error"] = "Decryption failed"
    return p


HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Infosys v0.18.1</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:16px;background:#090d12;color:#e5e7eb;font:15px -apple-system,BlinkMacSystemFont,system-ui,sans-serif}
main{max-width:850px;margin:auto}
header{text-align:center;padding:20px 0}
h1{color:#34d399;margin:0;font-size:24px}
.sub{color:#9ca3af;font-size:12px;margin:4px 0}
.panel{background:#111923;border:1px solid #263342;border-radius:12px;padding:16px;margin:12px 0}
input{width:100%;padding:12px;background:#080d13;border:1px solid #374151;border-radius:8px;color:#fff;margin:6px 0;font-size:15px}
button{width:100%;padding:14px;border:0;border-radius:8px;background:#34d399;color:#000;font-weight:700;margin-top:8px;cursor:pointer;font-size:15px}
button:disabled{opacity:.5;cursor:not-allowed}
button.link{background:transparent;color:#9ca3af;font-weight:400;font-size:12px;margin:0;padding:4px 0;text-align:right;width:auto}
.tabs{display:flex;gap:4px;margin:12px 0;flex-wrap:wrap}
.tabs button{flex:1;background:#172230;color:#9ca3af;border:1px solid #263342;padding:10px 4px;font-weight:600;font-size:12px;min-width:70px}
.tabs button.active{background:#34d399;color:#000;border-color:#34d399}
label{font-size:13px;color:#d1d5db}
.warn{color:#fbbf24;font-size:11px}
.muted{color:#9ca3af;font-size:12px}
.status{padding:12px;border-radius:8px;background:#172b42;margin:12px 0;font-size:13px}
.error{background:#3b1d1d;color:#fca5a5}
.item{border-bottom:1px solid #263342;padding:10px 0;word-wrap:break-word;overflow-wrap:anywhere}
.item:last-child{border:0}
.pill{font-size:10px;padding:2px 7px;border-radius:10px;background:#1f2937;color:#d1d5db;margin-left:6px}
.pill.found{background:#065f46;color:#6ee7b7}
.pill.rate{background:#78350f;color:#fbbf24}
.pill.error{background:#7f1d1d;color:#fca5a5}
.pill.verified{background:#065f46;color:#6ee7b7}
.pill.unverified{background:#78350f;color:#fbbf24}
.pill.highlight{background:#1e40af;color:#93c5fd}
a{color:#6ee7b7;word-break:break-all}
.bad{color:#fca5a5}
details{margin-top:8px}
summary{cursor:pointer;color:#fbbf24;font-weight:600;font-size:13px}
.suggestion{display:inline-block;margin:4px 4px 0 0;padding:6px 12px;background:#1f2937;color:#6ee7b7;border:1px solid #374151;border-radius:6px;font-size:13px;cursor:pointer;width:auto;font-weight:500}
.profile{padding:8px 0;border-bottom:1px solid #263342}
.profile:last-child{border:0}
.profile-name{font-weight:600;font-size:13px;color:#f3f4f6}
.profile-url{font-size:11px;color:#6ee7b7;word-break:break-all}
</style>
</head>
<body>
<main>
<header>
  <h1>OSINT Infosys</h1>
  <p class="sub">Email · Username · Phone · Domain · v0.18.1</p>
  <p class="warn">Authorized investigations only · findings are leads, not identity proof</p>
</header>

<section class="panel" id="auth" style="display:none">
  <label>API token</label>
  <input id="tok" type="password" autocomplete="off">
  <button onclick="saveTok()">Save &amp; Continue</button>
</section>

<section class="panel" id="search" style="display:none">
  <div class="tabs">
    <button id="t-email" class="active" onclick="tab('email')">Email</button>
    <button id="t-username" onclick="tab('username')">Username</button>
    <button id="t-phone" onclick="tab('phone')">Phone</button>
    <button id="t-domain" onclick="tab('domain')">Domain</button>
  </div>
  <div id="p-email">
    <label>Email</label>
    <input id="in-email" type="email" autocomplete="off" placeholder="name@example.com">
    <button id="r-email" onclick="runEmail()">Investigate Email</button>
    <p class="muted">DNS + Holehe + Bing + DDG + Gravatar + Keybase + HN + PGP + Sherlock (1 username). ~2–4 min.</p>
  </div>
  <div id="p-username" style="display:none">
    <label>Username</label>
    <input id="in-username" type="text" autocomplete="off" placeholder="handle">
    <button id="r-username" onclick="runUsername()">Investigate Username</button>
  </div>
  <div id="p-phone" style="display:none">
    <label>Phone (E.164 preferred)</label>
    <input id="in-phone" type="tel" autocomplete="off" placeholder="+8801712345678">
    <button id="r-phone" onclick="runPhone()">Investigate Phone</button>
  </div>
  <div id="p-domain" style="display:none">
    <label>Domain</label>
    <input id="in-domain" type="text" autocomplete="off" placeholder="example.com">
    <button id="r-domain" onclick="runDomain()">Investigate Domain</button>
  </div>
  <button class="link" onclick="forget()">Forget token</button>
</section>

<div id="stat"></div>
<div id="out"></div>
</main>
<script>
const K="osint_api_token_v0151";
let P=null;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function tk(){return localStorage.getItem(K)||''}
function H(){return {'Authorization':'Bearer '+tk(),'Content-Type':'application/json'}}
function saveTok(){const t=document.getElementById('tok').value.trim();if(t.length<32){alert('Too short');return}localStorage.setItem(K,t);show()}
function forget(){localStorage.removeItem(K);document.getElementById('auth').style.display='block';document.getElementById('search').style.display='none'}
function show(){document.getElementById('auth').style.display='none';document.getElementById('search').style.display='block'}
function tab(t){['email','username','phone','domain'].forEach(x=>{document.getElementById('t-'+x).classList.toggle('active',x===t);document.getElementById('p-'+x).style.display=x===t?'block':'none'});document.getElementById('out').innerHTML='';document.getElementById('stat').innerHTML=''}
function resetBtns(){const m={email:'Investigate Email',username:'Investigate Username',phone:'Investigate Phone',domain:'Investigate Domain'};for(const[k,v] of Object.entries(m)){const b=document.getElementById('r-'+k);if(b){b.disabled=false;b.textContent=v}}}
async function readJson(r){const ct=r.headers.get('content-type')||'';if(!ct.includes('application/json')){throw Error('Server HTTP '+r.status+' non-JSON (retry in 60s)')}return await r.json()}
function poll(id,type){let n=0;clearInterval(P);P=setInterval(async()=>{n++;if(n>200){clearInterval(P);resetBtns();err('Polling limit — check later');return}try{const r=await fetch('/api/job/'+encodeURIComponent(id),{headers:H()});if(!r.ok&&r.status>=500){document.getElementById('stat').innerHTML='<div class="status">Server restarting ('+r.status+'). Retrying…</div>';return}const j=await readJson(r);if(j.status==='done'){clearInterval(P);resetBtns();if(type==='email')showEmail(j.result);else if(type==='username')showUser(j.result);else if(type==='phone')showPhone(j.result);else showDomain(j.result)}else if(j.status==='failed'||j.status==='interrupted'){clearInterval(P);resetBtns();err('Job '+j.status+': '+(j.error||''))}else document.getElementById('stat').innerHTML='<div class="status">'+esc(j.status)+'… ('+(n*3)+'s)</div>'}catch(e){clearInterval(P);resetBtns();err(e.message)}},3000)}
function err(m){document.getElementById('stat').innerHTML='<div class="status error">'+esc(m)+'</div>'}
async function go(url,body,type,btn){const b=document.getElementById(btn);b.disabled=true;b.textContent='Investigating…';document.getElementById('out').innerHTML='';document.getElementById('stat').innerHTML='<div class="status">Starting '+type+' investigation…</div>';try{const r=await fetch(url,{method:'POST',headers:H(),body:JSON.stringify(body)});const d=await readJson(r);poll(d.jobId,type)}catch(e){resetBtns();err(e.message)}}
function runEmail(){const v=document.getElementById('in-email').value.trim();if(!v)return;go('/api/check',{email:v},'email','r-email')}
function runUsername(){const v=document.getElementById('in-username').value.trim();if(!v)return;go('/api/check-username',{username:v},'username','r-username')}
function runPhone(){const v=document.getElementById('in-phone').value.trim();if(!v)return;go('/api/check-phone',{phone:v},'phone','r-phone')}
function runDomain(){const v=document.getElementById('in-domain').value.trim();if(!v)return;go('/api/check-domain',{domain:v},'domain','r-domain')}
function sUrl(u){try{const p=new URL(u);return ['http:','https:'].includes(p.protocol)}catch{return false}}
function sec(name,v){const st=v?.status||'?';const pc=st==='found'?'verified':st==='rate_limited'?'rate':st==='error'?'error':'';let b='';if(v?.found?.length)b+='<p>Found: '+esc(v.found.join(', '))+'</p>';if(v?.rate_limited?.length){const t=(v.found?.length||0)+(v.not_found?.length||0)+(v.rate_limited?.length||0);const pct=t?Math.round(100*v.rate_limited.length/t):0;b+='<details><summary>'+v.rate_limited.length+' rate-limited ('+pct+'%)</summary><p>'+esc(v.rate_limited.join(', '))+'</p></details>'}if(v?.not_found?.length)b+='<p class="muted">Not found: '+esc(v.not_found.join(', '))+'</p>';if(v?.values?.length)b+='<p>'+esc(v.values.join(', '))+'</p>';if(v?.results?.length)b+='<p>'+v.results.length+' reference(s)</p>';if(v?.hosts?.length)b+='<details><summary>'+v.hosts.length+' hostnames</summary><p>'+esc(v.hosts.slice(0,40).join(', '))+'</p></details>';if(v?.error)b+='<p class="bad">Error: '+esc(v.error)+'</p>';if(v?.limitation)b+='<p class="muted">'+esc(v.limitation)+'</p>';return '<section class="panel"><h3>'+esc(name)+' <span class="pill '+pc+'">'+esc(st)+'</span></h3>'+b+'</section>'}
function sher(found,user){if(!found?.length)return '<p class="muted">No profiles for @'+esc(user)+'</p>';let h='';for(const p of found){const fs=p.final_status||'found';const pc=fs==='found'?'verified':fs==='not_verified'?'unverified':'';h+='<div class="profile"><div class="profile-name">'+esc(p.platform)+' <span class="pill '+pc+'">'+esc(fs)+'</span></div>';if(p.verification_note)h+='<div class="muted" style="font-size:10px">'+esc(p.verification_note)+'</div>';if(sUrl(p.url))h+='<a class="profile-url" href="'+esc(p.url)+'" target="_blank" rel="noopener">'+esc(p.url)+'</a>';h+='</div>'}return h}
function showEmail(r){document.getElementById('stat').innerHTML='<div class="status">Completed. Empty = not proof of absence.</div>';let h='';
if(r.derived_usernames?.length){h+='<section class="panel"><h3>Derived usernames <span class="pill highlight">pivot</span></h3>';for(const u of r.derived_usernames)h+='<button class="suggestion" onclick="pivot(\''+esc(u)+'\')">'+esc(u)+'</button>';h+='</section>'}
const gp=r.sources?.gravatar_profile;if(gp?.status==='found'){h+='<section class="panel"><h3>Gravatar Profile <span class="pill verified">found</span></h3>';if(gp.display_name)h+='<div class="item"><b>Name:</b> '+esc(gp.display_name)+'</div>';if(gp.about)h+='<div class="item"><b>About:</b> '+esc(gp.about)+'</div>';if(gp.location)h+='<div class="item"><b>Location:</b> '+esc(gp.location)+'</div>';if(gp.accounts?.length){h+='<div class="item"><b>Linked accounts:</b><br>';for(const a of gp.accounts)h+='<span class="pill highlight">'+esc(a.domain||'?')+'</span> '+esc(a.username||'')+'<br>'}h+='</section>'}
const kb=r.sources?.keybase;if(kb?.status==='found'){h+='<section class="panel"><h3>Keybase <span class="pill verified">found</span></h3><div class="item"><b>Username:</b> '+esc(kb.username)+'</div>';if(kb.full_name)h+='<div class="item"><b>Full name:</b> '+esc(kb.full_name)+'</div>';if(kb.proofs?.length){h+='<div class="item"><b>Proofs:</b><br>';for(const p of kb.proofs)h+='<span class="pill highlight">'+esc(p.platform||'?')+'</span> '+esc(p.username||'')+'<br>'}h+='</section>'}
const hn=r.sources?.hackernews;if(hn?.status==='found'&&hn.results?.length){h+='<section class="panel"><h3>HackerNews <span class="pill found">'+hn.total+'</span></h3>';for(const x of hn.results.slice(0,10)){h+='<div class="item"><b>'+esc(x.author||'?')+'</b> · '+esc(x.created_at||'')+'<br>';if(x.story_title)h+='<i>'+esc(x.story_title)+'</i><br>';h+='<span class="muted">'+esc(x.comment_excerpt||'')+'</span><br>';if(sUrl(x.url))h+='<a href="'+esc(x.url)+'" target="_blank" rel="noopener">'+esc(x.url)+'</a>';h+='</div>'}h+='</section>'}
const pgp=r.sources?.pgp;if(pgp?.status==='found'){h+='<section class="panel"><h3>PGP Key <span class="pill verified">found</span></h3><div class="item">'+esc(pgp.key_type||'')+' '+esc(pgp.key_id||'')+'</div></section>'}
const sh=r.sherlock||[];if(sh.length){h+='<section class="panel"><h3>Sherlock</h3>';for(const s of sh){const found=s.found||[];const v=found.filter(x=>x.final_status==='found').length;h+='<details open><summary>@'+esc(s.username)+' · '+v+' verified / '+found.length+' candidates</summary>'+sher(found,s.username)+'</details>'}h+='</section>'}
for(const [k,v] of Object.entries(r.sources||{})){if(['gravatar_profile','keybase','hackernews','pgp'].includes(k))continue;if(k==='dns'){for(const [dk,dv] of Object.entries(v||{}))h+=sec('DNS · '+dk,dv)}else h+=sec(k,v)}
if(r.public_references?.length){h+='<section class="panel"><h3>Public references ('+r.public_references.length+')</h3>';for(const x of r.public_references){h+='<div class="item"><b>'+esc(x.title||'')+'</b> · '+esc(x.discovery_source||'')+'<br>';if(sUrl(x.url))h+='<a href="'+esc(x.url)+'" target="_blank" rel="noopener">'+esc(x.url)+'</a>';if(x.snippet)h+='<p class="muted">'+esc(x.snippet)+'</p>';h+='</div>'}h+='</section>'}
document.getElementById('out').innerHTML=h}
function showUser(r){document.getElementById('stat').innerHTML='<div class="status">Sherlock @'+esc(r.username)+'</div>';const s=r.sherlock||{};const found=s.found||[];const v=found.filter(x=>x.final_status==='found').length;let h='<section class="panel"><h3>Sherlock <span class="pill verified">'+v+' verified</span> <span class="pill">'+found.length+' total</span></h3>'+sher(found,r.username)+'</section>';document.getElementById('out').innerHTML=h}
function showPhone(r){document.getElementById('stat').innerHTML='<div class="status">Phone ready.</div>';const p=r.parsed||{};let h='<section class="panel"><h3>Parsed</h3><div class="item"><b>E.164:</b> '+esc(p.e164)+'</div><div class="item"><b>National:</b> '+esc(p.national)+'</div><div class="item"><b>Country:</b> '+esc(p.country)+'</div><div class="item"><b>Carrier:</b> '+esc(p.carrier)+'</div><div class="item"><b>Location:</b> '+esc(p.location)+'</div><div class="item"><b>Line type:</b> '+esc(p.line_type)+'</div><div class="item"><b>Valid:</b> '+String(!!p.valid)+'</div>';if(r.bd_prefix_carrier)h+='<div class="item"><b>BD:</b> '+esc(r.bd_prefix_carrier)+'</div>';h+='</section>';if(r.manual_queries?.length){h+='<section class="panel"><h3>Manual</h3>';for(const q of r.manual_queries)h+='<div class="item"><b>'+esc(q.tool)+'</b><br>'+(sUrl(q.url)?'<a href="'+esc(q.url)+'" target="_blank" rel="noopener">'+esc(q.url)+'</a>':'')+'</div>';h+='</section>'}document.getElementById('out').innerHTML=h}
function showDomain(r){document.getElementById('stat').innerHTML='<div class="status">Domain ready.</div>';let h='';for(const [k,v] of Object.entries(r.dns||{}))h+=sec('DNS · '+k,v);const rdap=r.rdap||{};if(rdap.status==='found'){h+='<section class="panel"><h3>RDAP <span class="pill verified">found</span></h3><div class="item"><b>Registrar:</b> '+esc(rdap.registrar)+'</div>';for(const [e,d] of Object.entries(rdap.events||{}))h+='<div class="item"><b>'+esc(e)+':</b> '+esc(d)+'</div>';if(rdap.nameservers?.length)h+='<div class="item"><b>NS:</b> '+esc(rdap.nameservers.join(', '))+'</div>';h+='</section>'}else h+=sec('RDAP',rdap);h+=sec('crt.sh',r.crtsh||{});document.getElementById('out').innerHTML=h}
function pivot(u){tab('username');document.getElementById('in-username').value=u;runUsername()}
if(tk())show();else document.getElementById('auth').style.display='block';
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML
