"""
OSINT Infosys v0.16.0
- Email: DNS (MX/SPF/DMARC) + Holehe + DuckDuckGo + Bing
- Username: Sherlock (400+ sites)
- Bearer token auth, browser-remembered
- Fernet encryption at rest
- Heartbeat-based job recovery
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
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
from urllib.parse import parse_qs, unquote, urlparse

import dns.asyncresolver
import dns.resolver
import httpx
import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet, InvalidToken
from email_validator import EmailNotValidError, validate_email
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

VERSION = "0.16.0"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
API_TOKEN = os.environ.get("OSINT_API_TOKEN", "").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")
if len(API_TOKEN) < 32:
    raise RuntimeError("OSINT_API_TOKEN must be at least 32 characters")

_SALT = b"osint-infosys-v0151-key-derivation"
_DK = hashlib.pbkdf2_hmac("sha256", API_TOKEN.encode(), _SALT, 100_000, dklen=32)
cipher = Fernet(base64.urlsafe_b64encode(_DK))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("osint")
app = FastAPI(title="OSINT Infosys", version=VERSION)
job_semaphore = asyncio.Semaphore(2)

USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{2,64}$')


@contextmanager
def db_connection():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require", connect_timeout=10)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db_connection() as conn:
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
            cur.execute("""
                ALTER TABLE jobs_v0151 ADD COLUMN IF NOT EXISTS job_type TEXT NOT NULL DEFAULT 'email'
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_jobs_v0151_status
                ON jobs_v0151(status, created_at DESC)
            """)
            cur.execute("""
                UPDATE jobs_v0151
                SET status='interrupted',
                    error='Job interrupted (no heartbeat for 10+ minutes).',
                    completed_at=NOW(), updated_at=NOW()
                WHERE status='running'
                  AND (last_heartbeat_at IS NULL OR last_heartbeat_at < NOW() - INTERVAL '10 minutes')
            """)
            cur.execute("""
                UPDATE jobs_v0151
                SET status='interrupted',
                    error='Job was queued but never started.',
                    completed_at=NOW(), updated_at=NOW()
                WHERE status='pending'
                  AND created_at < NOW() - INTERVAL '15 minutes'
            """)


def require_auth(authorization: str | None = Header(default=None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    supplied = authorization[7:].strip()
    if not secrets.compare_digest(supplied, API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid bearer token")


@app.on_event("startup")
async def startup_event():
    init_db()
    log.info("OSINT Infosys %s initialized", VERSION)


@app.head("/")
async def root_head():
    return {}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "version": VERSION}


# ---------------- Email helpers ----------------
def normalize_email(value: str) -> tuple[str, str]:
    try:
        checked = validate_email(value.strip(), check_deliverability=False)
        normalized = checked.normalized
        local, domain = normalized.rsplit("@", 1)
        return f"{local}@{domain.lower()}", domain.lower()
    except EmailNotValidError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def derive_usernames(email: str) -> list[str]:
    local, _, _ = email.rpartition("@")
    if not local:
        return []
    base = local.split("+")[0].lower()
    variants = []
    if base:
        variants.append(base)
    if "." in base:
        nodot = base.replace(".", "")
        if nodot and nodot not in variants:
            variants.append(nodot)
        underscore = base.replace(".", "_")
        if underscore not in variants:
            variants.append(underscore)
        hyphen = base.replace(".", "-")
        if hyphen not in variants:
            variants.append(hyphen)
        first = base.split(".")[0]
        if first and len(first) >= 3 and first not in variants:
            variants.append(first)
    out = []
    for v in variants:
        if USERNAME_RE.match(v):
            out.append(v)
        if len(out) >= 4:
            break
    return out


def source_record(source: str, status: str, method: str, **kwargs) -> dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "method": method,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        **kwargs,
    }


# ---------------- DNS ----------------
async def dns_lookup(domain: str) -> dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    records: dict[str, Any] = {}
    checks = [("MX", "MX"), ("SPF", "TXT"), ("DMARC", "TXT")]
    for label, qtype in checks:
        qname = f"_dmarc.{domain}" if label == "DMARC" else domain
        try:
            answer = await resolver.resolve(qname, qtype, raise_on_no_answer=False)
            values = []
            if answer.rrset:
                for item in answer:
                    if qtype == "MX":
                        values.append(str(item.exchange).rstrip("."))
                    else:
                        values.append("".join(p.decode("utf-8", "replace") for p in item.strings))
            if label == "SPF":
                values = [v for v in values if v.lower().startswith("v=spf1")]
            if label == "DMARC":
                values = [v for v in values if v.lower().startswith("v=dmarc1")]
            records[label] = source_record(
                "DNS", "found" if values else "not_found",
                f"DNS {qtype} lookup", query=qname, values=values,
                limitation="DNS presence does not verify mailbox existence or ownership."
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            records[label] = source_record("DNS", "not_found", f"DNS {qtype} lookup", query=qname, values=[])
        except Exception as exc:
            records[label] = source_record("DNS", "error", f"DNS {qtype} lookup",
                                           query=qname, error=type(exc).__name__, values=[])
    return records


# ---------------- Public search ----------------
def clean_text(value: str) -> str:
    value = re.sub(r"<[^>]*>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def safe_http_url(value: str) -> bool:
    try:
        p = urlparse(value)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def unwrap_ddg_url(href: str) -> str:
    try:
        p = urlparse(href)
        if "duckduckgo.com" in (p.hostname or ""):
            t = parse_qs(p.query).get("uddg", [])
            if t:
                return unquote(t[0])
        return href
    except Exception:
        return href


async def public_search(provider: str, email: str, limit: int = 12) -> dict[str, Any]:
    headers = {"User-Agent": "OSINT-Infosys/0.16 (+authorized public-source research)"}
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True,
                                     max_redirects=5, headers=headers) as client:
            if provider == "DuckDuckGo":
                response = await client.post("https://html.duckduckgo.com/html/",
                                             data={"q": f'"{email}"'})
            else:
                response = await client.get("https://www.bing.com/search",
                                            params={"q": f'"{email}"'})
        if response.status_code == 429:
            return source_record(provider, "rate_limited", "exact-email public search",
                                 results=[], http_status=429)
        if response.status_code in (401, 403, 407):
            return source_record(provider, "blocked", "exact-email public search",
                                 results=[], http_status=response.status_code)
        if response.status_code != 200:
            return source_record(provider, "unavailable", "exact-email public search",
                                 results=[], http_status=response.status_code)

        page = response.text
        low = page.lower()
        if any(m in low for m in ("captcha", "unusual traffic", "verify you are human",
                                   "consent required", "robot check")):
            return source_record(provider, "blocked", "HTML challenge detection",
                                 results=[], limitation="Provider returned a challenge page.")
        results = []
        if provider == "DuckDuckGo":
            blocks = re.findall(
                r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                page, re.I | re.S)
            for href, title in blocks[:limit]:
                url = unwrap_ddg_url(html.unescape(href))
                if safe_http_url(url):
                    results.append({"title": clean_text(title)[:200], "url": url[:1000], "snippet": ""})
        else:
            blocks = re.findall(
                r'<li[^>]+class="[^"]*b_algo[^"]*"[^>]*>.*?<h2[^>]*>.*?<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?</h2>(.*?)(?=<li[^>]+class="[^"]*b_algo|$)',
                page, re.I | re.S)
            for href, title, body in blocks[:limit]:
                url = html.unescape(href)
                if safe_http_url(url):
                    sm = re.search(r"<p[^>]*>(.*?)</p>", body, re.I | re.S)
                    snippet = clean_text(sm.group(1))[:400] if sm else ""
                    results.append({"title": clean_text(title)[:200], "url": url[:1000], "snippet": snippet})
        if results:
            status = "found"
        else:
            nrm = ("no results found", "there are no results for", "no results for")
            status = "not_found" if any(m in low for m in nrm) else "unavailable"
        return source_record(provider, status, "exact-email public search",
                             results=results,
                             limitation="HTML parsing is best-effort; empty pages may not mean no results.")
    except httpx.TimeoutException:
        return source_record(provider, "unavailable", "exact-email public search",
                             results=[], error="timeout")
    except Exception as exc:
        return source_record(provider, "error", "exact-email public search",
                             results=[], error=type(exc).__name__)


# ---------------- Holehe ----------------
async def run_holehe(email: str) -> dict[str, Any]:
    commands = [
        ["holehe", email, "--no-color"],
        [sys.executable, "-m", "holehe", email, "--no-color"],
    ]
    last_err = "Holehe not found"
    for cmd in commands:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=150)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return source_record("Holehe", "error", "CLI execution",
                                     found=[], not_found=[], rate_limited=[], error="timeout")
            output = stdout.decode("utf-8", "replace")
            found, not_found, rate_limited, blocked = [], [], [], []
            recognized = 0
            for raw in output.splitlines():
                line = raw.strip()
                if not line:
                    continue
                if "Email used" in line or "Email not used" in line or "Rate limit" in line:
                    continue
                if line.startswith("[+]"):
                    s = line[3:].strip()
                    if s: found.append(s); recognized += 1
                elif line.startswith("[-]"):
                    s = line[3:].strip()
                    if s: not_found.append(s); recognized += 1
                elif line.startswith("[x]"):
                    s = line[3:].strip()
                    if s: rate_limited.append(s); recognized += 1
                elif "blocked" in line.lower():
                    blocked.append(line[:180])
            if recognized == 0:
                return source_record("Holehe", "error", "CLI output parsing",
                                     found=[], not_found=[], rate_limited=[], blocked=blocked,
                                     parser_status="unrecognized",
                                     error="No recognized [±x] lines in Holehe output")
            overall = "found" if found else ("rate_limited" if rate_limited else ("blocked" if blocked else ("not_found" if not_found else "unavailable")))
            return source_record("Holehe", overall, "CLI output parsing",
                                 found=list(dict.fromkeys(found)),
                                 not_found=list(dict.fromkeys(not_found)),
                                 rate_limited=list(dict.fromkeys(rate_limited)),
                                 blocked=blocked, parser_status="recognized",
                                 parsed_count=recognized,
                                 limitation="Holehe results are association signals only.")
        except FileNotFoundError:
            continue
        except Exception as exc:
            last_err = type(exc).__name__
    return source_record("Holehe", "unavailable", "CLI execution",
                         found=[], not_found=[], rate_limited=[], error=last_err)


# ---------------- Sherlock (NEW) ----------------
def strip_ansi(s: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', s)


async def run_sherlock(username: str) -> dict[str, Any]:
    commands = [
        ["sherlock", username, "--print-found", "--no-color", "--timeout", "10"],
        [sys.executable, "-m", "sherlock_project", username, "--print-found", "--no-color", "--timeout", "10"],
        ["python3", "-m", "sherlock_project", username, "--print-found", "--no-color", "--timeout", "10"],
    ]
    last_err = "Sherlock not installed"
    for cmd in commands:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=280)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {"status": "timeout", "found": [],
                        "error": "Sherlock exceeded 280s timeout"}
            output = strip_ansi(stdout.decode("utf-8", "replace"))
            found = []
            for line in output.splitlines():
                line = line.strip()
                if not line.startswith("[+]"):
                    continue
                m = re.search(r'\[\+\]\s*(.+?)\s*[:\-]\s*(https?://\S+)', line)
                if m:
                    platform = m.group(1).strip().rstrip(":").strip()
                    url = m.group(2).strip()
                    if platform and safe_http_url(url):
                        found.append({"platform": platform, "url": url})
            # Deduplicate by URL
            seen = set()
            unique = []
            for item in found:
                if item["url"] in seen:
                    continue
                seen.add(item["url"])
                unique.append(item)
            return {
                "status": "found" if unique else "not_found",
                "found": unique,
                "total_found": len(unique),
            }
        except FileNotFoundError:
            continue
        except Exception as exc:
            last_err = type(exc).__name__
            continue
    return {"status": "error", "found": [], "error": last_err}


# ---------------- Heartbeat ----------------
async def heartbeat_loop(job_id: str, stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE jobs_v0151 SET last_heartbeat_at=NOW(), updated_at=NOW() "
                        "WHERE job_id=%s AND status='running'", (job_id,))
        except Exception:
            pass
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=20)
        except asyncio.TimeoutError:
            continue


# ---------------- Email investigation ----------------
async def execute_email_investigation(job_id: str, email: str, domain: str):
    async with job_semaphore:
        stop = asyncio.Event()
        hb = asyncio.create_task(heartbeat_loop(job_id, stop))
        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE jobs_v0151 SET status='running', started_at=NOW(), "
                        "last_heartbeat_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                        (job_id,))
            holehe, dns_r, ddg, bing = await asyncio.gather(
                run_holehe(email), dns_lookup(domain),
                public_search("DuckDuckGo", email), public_search("Bing", email))
            refs = []
            seen = set()
            for pr in (ddg, bing):
                for item in pr.get("results", []):
                    if item["url"] in seen:
                        continue
                    seen.add(item["url"])
                    refs.append({**item, "discovery_source": pr["source"]})
            result = {
                "schema_version": "0.16",
                "job_type": "email",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "derived_usernames": derive_usernames(email),
                "sources": {"holehe": holehe, "dns": dns_r,
                            "duckduckgo": ddg, "bing": bing},
                "public_references": refs,
                "assessment": {
                    "conclusion": "unresolved",
                    "note": "Observations are leads only. No result establishes account ownership.",
                },
            }
            ct = cipher.encrypt(json.dumps(result).encode()).decode()
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE jobs_v0151 SET status='done', result_ciphertext=%s, "
                                "error=NULL, completed_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                                (ct, job_id))
        except Exception as exc:
            log.exception("Email job %s failed", job_id)
            try:
                with db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE jobs_v0151 SET status='failed', error=%s, "
                                    "completed_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                                    (type(exc).__name__, job_id))
            except Exception:
                pass
        finally:
            stop.set()
            hb.cancel()
            try:
                await hb
            except Exception:
                pass


# ---------------- Username investigation (NEW) ----------------
async def execute_username_investigation(job_id: str, username: str):
    async with job_semaphore:
        stop = asyncio.Event()
        hb = asyncio.create_task(heartbeat_loop(job_id, stop))
        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE jobs_v0151 SET status='running', started_at=NOW(), "
                        "last_heartbeat_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                        (job_id,))
            sherlock_result = await run_sherlock(username)
            result = {
                "schema_version": "0.16",
                "job_type": "username",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "username": username,
                "sherlock": sherlock_result,
                "assessment": {
                    "conclusion": "unresolved",
                    "note": "Public profile URLs are candidates. Verify each manually before treating as the target's account.",
                },
            }
            ct = cipher.encrypt(json.dumps(result).encode()).decode()
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE jobs_v0151 SET status='done', result_ciphertext=%s, "
                                "error=NULL, completed_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                                (ct, job_id))
        except Exception as exc:
            log.exception("Username job %s failed", job_id)
            try:
                with db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE jobs_v0151 SET status='failed', error=%s, "
                                    "completed_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                                    (type(exc).__name__, job_id))
            except Exception:
                pass
        finally:
            stop.set()
            hb.cancel()
            try:
                await hb
            except Exception:
                pass


# ---------------- API ----------------
class EmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class UsernameRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)


@app.post("/api/check", dependencies=[Depends(require_auth)])
async def start_email_check(req: EmailRequest, bg: BackgroundTasks):
    email, domain = normalize_email(req.email)
    job_id = str(uuid.uuid4())
    encrypted = cipher.encrypt(email.encode()).decode()
    digest = hashlib.sha256(email.encode()).hexdigest()
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO jobs_v0151 (job_id,job_type,status,email_ciphertext,email_sha256)
                VALUES (%s,'email','pending',%s,%s)
            """, (job_id, encrypted, digest))
    bg.add_task(execute_email_investigation, job_id, email, domain)
    return {"jobId": job_id, "status": "pending"}


@app.post("/api/check-username", dependencies=[Depends(require_auth)])
async def start_username_check(req: UsernameRequest, bg: BackgroundTasks):
    username = req.username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(400, detail="Invalid username (2-64 chars, letters/numbers/._-)")
    job_id = str(uuid.uuid4())
    encrypted = cipher.encrypt(f"username:{username}".encode()).decode()
    digest = hashlib.sha256(f"username:{username}".encode()).hexdigest()
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO jobs_v0151 (job_id,job_type,status,email_ciphertext,email_sha256)
                VALUES (%s,'username','pending',%s,%s)
            """, (job_id, encrypted, digest))
    bg.add_task(execute_username_investigation, job_id, username)
    return {"jobId": job_id, "status": "pending"}


@app.get("/api/job/{job_id}", dependencies=[Depends(require_auth)])
async def get_job(job_id: str):
    try:
        uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid job ID")
    with db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT job_id,job_type,status,result_ciphertext,error,created_at,
                       updated_at,started_at,completed_at,last_heartbeat_at
                FROM jobs_v0151 WHERE job_id=%s
            """, (job_id,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(404, detail="Job not found")
    payload = dict(row)
    ct = payload.pop("result_ciphertext", None)
    if ct:
        try:
            payload["result"] = json.loads(cipher.decrypt(ct.encode()).decode())
        except (InvalidToken, ValueError):
            payload["result"] = None
            payload["error"] = "Result could not be decrypted"
    return payload


# ---------------- Frontend ----------------
HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Infosys v0.16</title>
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
.tabs{display:flex;gap:6px;margin:12px 0}
.tabs button{flex:1;background:#172230;color:#9ca3af;border:1px solid #263342;padding:10px;font-weight:600;font-size:13px}
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
a{color:#6ee7b7;word-break:break-all}
.bad{color:#fca5a5}
details{margin-top:8px}
summary{cursor:pointer;color:#fbbf24;font-weight:600;font-size:13px}
.suggestion{display:inline-block;margin:4px 4px 0 0;padding:6px 12px;background:#1f2937;color:#6ee7b7;border:1px solid #374151;border-radius:6px;font-size:13px;cursor:pointer;width:auto;font-weight:500}
.suggestion:hover{background:#374151}
.profile{display:flex;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid #263342;align-items:center}
.profile:last-child{border:0}
.profile-name{font-weight:600;font-size:13px;color:#f3f4f6}
.profile-url{font-size:11px;color:#6ee7b7;word-break:break-all}
</style>
</head>
<body>
<main>
<header>
  <h1>OSINT Infosys</h1>
  <p class="sub">Email · Username intelligence · v0.16.0</p>
  <p class="warn">Authorized investigations only · findings are leads, not identity proof</p>
</header>

<section class="panel" id="auth-panel" style="display:none">
  <label>API token (paste once — saved in this browser)</label>
  <input id="token" type="password" autocomplete="off" placeholder="Paste your OSINT_API_TOKEN">
  <button onclick="saveToken()">Save &amp; Continue</button>
</section>

<section class="panel" id="search-panel" style="display:none">
  <div class="tabs">
    <button id="tab-email-btn" class="active" onclick="switchTab('email')">Email</button>
    <button id="tab-username-btn" onclick="switchTab('username')">Username</button>
  </div>

  <div id="email-panel">
    <label>Email address</label>
    <input id="email-input" type="email" autocomplete="off" inputmode="email" placeholder="name@example.com">
    <button id="email-run" onclick="runEmailCheck()">Investigate Email</button>
    <p class="muted">Sends this email to Holehe and DuckDuckGo/Bing. Authorized use only.</p>
  </div>

  <div id="username-panel" style="display:none">
    <label>Username</label>
    <input id="username-input" type="text" autocomplete="off" placeholder="handle">
    <button id="username-run" onclick="runUsernameCheck()">Investigate Username</button>
    <p class="muted">Sherlock scans 400+ public sites. May take 2–4 minutes.</p>
  </div>

  <button class="link" onclick="forgetToken()">Forget saved token</button>
</section>

<div id="status"></div>
<div id="results"></div>
</main>

<script>
const TOKEN_KEY = "osint_api_token_v0151";
let pollHandle = null;
let activeTab = 'email';

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function getToken(){return localStorage.getItem(TOKEN_KEY)||''}
function authHeaders(){return {'Authorization':'Bearer '+getToken(),'Content-Type':'application/json'}}

function saveToken(){
  const t = document.getElementById('token').value.trim();
  if (t.length < 32) { alert('Token must be at least 32 characters.'); return; }
  localStorage.setItem(TOKEN_KEY, t);
  showSearch();
}

function forgetToken(){
  localStorage.removeItem(TOKEN_KEY);
  document.getElementById('auth-panel').style.display = 'block';
  document.getElementById('search-panel').style.display = 'none';
}

function showSearch(){
  document.getElementById('auth-panel').style.display = 'none';
  document.getElementById('search-panel').style.display = 'block';
}

function switchTab(tab){
  activeTab = tab;
  document.getElementById('tab-email-btn').classList.toggle('active', tab==='email');
  document.getElementById('tab-username-btn').classList.toggle('active', tab==='username');
  document.getElementById('email-panel').style.display = tab==='email' ? 'block' : 'none';
  document.getElementById('username-panel').style.display = tab==='username' ? 'block' : 'none';
  document.getElementById('results').innerHTML = '';
  document.getElementById('status').innerHTML = '';
}

async function runEmailCheck(){
  const email = document.getElementById('email-input').value.trim();
  if (!email) { alert('Enter an email address.'); return; }
  const btn = document.getElementById('email-run');
  btn.disabled = true; btn.textContent = 'Investigating…';
  document.getElementById('results').innerHTML = '';
  document.getElementById('status').innerHTML = '<div class="status">Starting email investigation. First run after idle may take 60–120s.</div>';
  try {
    const r = await fetch('/api/check', {method:'POST', headers:authHeaders(), body:JSON.stringify({email})});
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || ('HTTP '+r.status));
    poll(data.jobId, 'email');
  } catch (e) {
    resetButtons(); showError(e.message);
  }
}

async function runUsernameCheck(){
  const username = document.getElementById('username-input').value.trim();
  if (!username) { alert('Enter a username.'); return; }
  const btn = document.getElementById('username-run');
  btn.disabled = true; btn.textContent = 'Scanning 400+ sites…';
  document.getElementById('results').innerHTML = '';
  document.getElementById('status').innerHTML = '<div class="status">Sherlock is checking 400+ sites. This typically takes 2–4 minutes. Please wait.</div>';
  try {
    const r = await fetch('/api/check-username', {method:'POST', headers:authHeaders(), body:JSON.stringify({username})});
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || ('HTTP '+r.status));
    poll(data.jobId, 'username');
  } catch (e) {
    resetButtons(); showError(e.message);
  }
}

function resetButtons(){
  const eb = document.getElementById('email-run');
  const ub = document.getElementById('username-run');
  eb.disabled = false; eb.textContent = 'Investigate Email';
  ub.disabled = false; ub.textContent = 'Investigate Username';
}

function poll(id, type){
  let attempts = 0;
  clearInterval(pollHandle);
  pollHandle = setInterval(async () => {
    attempts++;
    if (attempts > 140) {
      clearInterval(pollHandle);
      showError('Polling limit reached. Check again later.');
      return;
    }
    try {
      const r = await fetch('/api/job/'+encodeURIComponent(id), {headers:authHeaders()});
      const j = await r.json();
      if (!r.ok) throw new Error(j.detail || ('HTTP '+r.status));
      if (['done','failed','interrupted'].includes(j.status)) {
        clearInterval(pollHandle);
        resetButtons();
        if (j.status === 'done') {
          if (type === 'email') renderEmail(j.result);
          else renderUsername(j.result);
        } else {
          showError('Job '+j.status+': '+(j.error||'unknown'));
        }
      } else {
        const elapsed = Math.floor(attempts * 2.5);
        document.getElementById('status').innerHTML = '<div class="status">Job '+esc(j.status)+'… ('+elapsed+'s)</div>';
      }
    } catch (e) {
      clearInterval(pollHandle);
      resetButtons();
      showError(e.message);
    }
  }, 2500);
}

function showError(msg){
  document.getElementById('status').innerHTML = '<div class="status error">'+esc(msg)+'</div>';
}

function renderEmail(r){
  document.getElementById('status').innerHTML = '<div class="status">Completed. Empty results are not proof of absence — review each source status.</div>';
  let out = '';

  // Derived usernames pivot (NEW)
  if (r.derived_usernames && r.derived_usernames.length) {
    out += '<section class="panel"><h3>Derived usernames <span class="pill">pivot</span></h3>';
    out += '<p class="muted">Possible usernames from the email prefix. Click one to run a Sherlock username scan.</p>';
    for (const u of r.derived_usernames) {
      out += '<button class="suggestion" onclick="pivotToUsername(\''+esc(u)+'\')">'+esc(u)+'</button>';
    }
    out += '</section>';
  }

  // Source results
  for (const [key, val] of Object.entries(r.sources || {})) {
    if (key === 'dns') {
      for (const [k, v] of Object.entries(val || {})) out += section('DNS · '+k, v);
    } else {
      out += section(key, val);
    }
  }

  // Public references
  out += '<section class="panel"><h3>Public references ('+(r.public_references||[]).length+')</h3>';
  for (const x of (r.public_references || [])) {
    const u = String(x.url || '');
    let safe = false;
    try { const p = new URL(u); safe = ['http:','https:'].includes(p.protocol); } catch {}
    out += '<div class="item"><b>'+esc(x.title || '(untitled)')+'</b>';
    out += '<p class="muted">'+esc(x.discovery_source || '')+'</p>';
    if (safe) out += '<a href="'+esc(u)+'" target="_blank" rel="noopener noreferrer">'+esc(u)+'</a>';
    if (x.snippet) out += '<p class="muted">'+esc(x.snippet)+'</p>';
    out += '</div>';
  }
  out += '</section>';

  // Assessment
  out += '<section class="panel"><b>Assessment: '+esc(r.assessment?.conclusion || 'unresolved')+'</b>';
  if (r.assessment?.note) out += '<p class="muted">'+esc(r.assessment.note)+'</p>';
  out += '</section>';

  document.getElementById('results').innerHTML = out;
}

function renderUsername(r){
  document.getElementById('status').innerHTML = '<div class="status">Sherlock scan completed for @'+esc(r.username)+'.</div>';
  const s = r.sherlock || {};
  const found = s.found || [];
  let out = '';

  out += '<section class="panel"><h3>Sherlock results for @'+esc(r.username)+' <span class="pill found">'+found.length+' found</span></h3>';
  if (s.status === 'timeout') {
    out += '<p class="bad">Sherlock timed out. Try a shorter username or retry.</p>';
  } else if (s.status === 'error') {
    out += '<p class="bad">Sherlock error: '+esc(s.error||'unknown')+'</p>';
  } else if (found.length === 0) {
    out += '<p class="muted">No public profiles found on the sites Sherlock checked. Not proof of absence — some sites return false negatives.</p>';
  } else {
    out += '<p class="muted">Public profile URLs are candidates. Verify each manually before treating as the target\'s account.</p>';
    for (const p of found) {
      const safe = safeUrl(p.url);
      out += '<div class="profile">';
      out += '<div><div class="profile-name">'+esc(p.platform)+'</div>';
      if (safe) out += '<a class="profile-url" href="'+esc(p.url)+'" target="_blank" rel="noopener noreferrer">'+esc(p.url)+'</a>';
      else out += '<span class="muted">'+esc(p.url)+'</span>';
      out += '</div></div>';
    }
  }
  out += '</section>';

  if (r.assessment?.note) {
    out += '<section class="panel"><b>Assessment</b><p class="muted">'+esc(r.assessment.note)+'</p></section>';
  }

  document.getElementById('results').innerHTML = out;
}

function safeUrl(u){
  try { const p = new URL(u); return ['http:','https:'].includes(p.protocol); } catch { return false; }
}

function section(name, v){
  const status = v?.status || 'unknown';
  const pc = status==='found' ? 'found' : status==='rate_limited' ? 'rate' : status==='error' ? 'error' : '';
  let body = '';
  if (v?.found?.length) body += '<p>Found: '+esc(v.found.join(', '))+'</p>';
  if (v?.rate_limited?.length) {
    const total = (v.found?.length||0)+(v.not_found?.length||0)+(v.rate_limited?.length||0);
    const pct = total>0 ? Math.round(100*v.rate_limited.length/total) : 0;
    body += '<details><summary>'+v.rate_limited.length+' platforms rate-limited ('+pct+'%) — click to see</summary>';
    body += '<p class="muted">Blocked by provider rate limits, not a negative result.</p>';
    body += '<p>'+esc(v.rate_limited.join(', '))+'</p></details>';
  }
  if (v?.not_found?.length) body += '<p class="muted">Not found: '+esc(v.not_found.join(', '))+'</p>';
  if (v?.values?.length) body += '<p>'+esc(v.values.join(', '))+'</p>';
  if (v?.results?.length) body += '<p>'+v.results.length+' reference(s)</p>';
  if (v?.error) body += '<p class="bad">Error: '+esc(v.error)+'</p>';
  if (v?.limitation) body += '<p class="muted">'+esc(v.limitation)+'</p>';
  return '<section class="panel"><h3>'+esc(name)+' <span class="pill '+pc+'">'+esc(status)+'</span></h3>'+body+'</section>';
}

function pivotToUsername(username){
  switchTab('username');
  document.getElementById('username-input').value = username;
  runUsernameCheck();
}

if (getToken()) showSearch();
else document.getElementById('auth-panel').style.display = 'block';
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML
