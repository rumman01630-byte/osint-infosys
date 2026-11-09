"""
OSINT Infosys v0.15.1 — hardened email intelligence
- Bearer token auth (saved once in browser localStorage)
- Fernet encryption at rest (key derived from OSINT_API_TOKEN)
- No plaintext email stored in results
- Heartbeat-based job recovery
- Holehe + DNS + DuckDuckGo + Bing
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

VERSION = "0.15.1"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
API_TOKEN = os.environ.get("OSINT_API_TOKEN", "").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")
if len(API_TOKEN) < 32:
    raise RuntimeError(
        "OSINT_API_TOKEN must be at least 32 characters. "
        "Generate one locally with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )

# Derive Fernet key from API token (single secret to manage)
_SALT = b"osint-infosys-v0151-key-derivation"
_DK = hashlib.pbkdf2_hmac("sha256", API_TOKEN.encode(), _SALT, 100_000, dklen=32)
cipher = Fernet(base64.urlsafe_b64encode(_DK))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("osint")
app = FastAPI(title="OSINT Infosys", version=VERSION)
job_semaphore = asyncio.Semaphore(2)


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
                CREATE INDEX IF NOT EXISTS idx_jobs_v0151_status
                ON jobs_v0151(status, created_at DESC)
            """)
            # Only mark jobs stale if heartbeat is truly old (>10 min) — do NOT kill live jobs
            cur.execute("""
                UPDATE jobs_v0151
                SET status='interrupted',
                    error='Job execution was interrupted (no heartbeat for 10+ minutes).',
                    completed_at=NOW(),
                    updated_at=NOW()
                WHERE status='running'
                  AND (last_heartbeat_at IS NULL OR last_heartbeat_at < NOW() - INTERVAL '10 minutes')
            """)
            # Pending jobs that never started for >15 min
            cur.execute("""
                UPDATE jobs_v0151
                SET status='interrupted',
                    error='Job was queued but never started (interrupted by restart before execution).',
                    completed_at=NOW(),
                    updated_at=NOW()
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


def normalize_email(value: str) -> tuple[str, str]:
    try:
        checked = validate_email(value.strip(), check_deliverability=False)
        normalized = checked.normalized
        local, domain = normalized.rsplit("@", 1)
        return f"{local}@{domain.lower()}", domain.lower()
    except EmailNotValidError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def source_record(source: str, status: str, method: str, **kwargs) -> dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "method": method,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        **kwargs,
    }


# ---------- DNS ----------
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
                        values.append("".join(part.decode("utf-8", "replace") for part in item.strings))
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


# ---------- Public search ----------
def clean_text(value: str) -> str:
    value = re.sub(r"<[^>]*>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def safe_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def unwrap_ddg_url(href: str) -> str:
    try:
        parsed = urlparse(href)
        if "duckduckgo.com" in (parsed.hostname or ""):
            target = parse_qs(parsed.query).get("uddg", [])
            if target:
                return unquote(target[0])
        return href
    except Exception:
        return href


async def public_search(provider: str, email: str, limit: int = 12) -> dict[str, Any]:
    headers = {"User-Agent": "OSINT-Infosys/0.15.1 (+authorized public-source research)"}
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
        if any(marker in low for marker in ("captcha", "unusual traffic", "verify you are human",
                                             "consent required", "robot check")):
            return source_record(provider, "blocked", "HTML challenge detection",
                                 results=[], limitation="Provider returned a challenge page.")

        results = []
        if provider == "DuckDuckGo":
            blocks = re.findall(
                r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                page, re.I | re.S
            )
            for href, title in blocks[:limit]:
                url = unwrap_ddg_url(html.unescape(href))
                if safe_http_url(url):
                    results.append({"title": clean_text(title)[:200], "url": url[:1000], "snippet": ""})
        else:
            blocks = re.findall(
                r'<li[^>]+class="[^"]*b_algo[^"]*"[^>]*>.*?<h2[^>]*>.*?<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?</h2>(.*?)(?=<li[^>]+class="[^"]*b_algo|$)',
                page, re.I | re.S
            )
            for href, title, body in blocks[:limit]:
                url = html.unescape(href)
                if safe_http_url(url):
                    snippet_match = re.search(r"<p[^>]*>(.*?)</p>", body, re.I | re.S)
                    snippet = clean_text(snippet_match.group(1))[:400] if snippet_match else ""
                    results.append({"title": clean_text(title)[:200], "url": url[:1000], "snippet": snippet})

        if results:
            status = "found"
        else:
            no_result_markers = ("no results found", "there are no results for", "no results for")
            status = "not_found" if any(m in low for m in no_result_markers) else "unavailable"

        return source_record(provider, status, "exact-email public search",
                             results=results,
                             limitation="HTML parsing is best-effort; empty pages may not mean no results.")

    except httpx.TimeoutException:
        return source_record(provider, "unavailable", "exact-email public search",
                             results=[], error="timeout")
    except Exception as exc:
        return source_record(provider, "error", "exact-email public search",
                             results=[], error=type(exc).__name__)


# ---------- Holehe ----------
async def run_holehe(email: str) -> dict[str, Any]:
    commands = [
        ["holehe", email, "--no-color"],
        [sys.executable, "-m", "holehe", email, "--no-color"],
    ]
    last_error = "Holehe not found"
    for cmd in commands:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=150)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return source_record("Holehe", "error", "CLI execution",
                                     found=[], not_found=[], rate_limited=[],
                                     error="timeout")
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
                                 limitation="Holehe results are association signals only, not ownership proof.")
        except FileNotFoundError:
            continue
        except Exception as exc:
            last_error = type(exc).__name__

    return source_record("Holehe", "unavailable", "CLI execution",
                         found=[], not_found=[], rate_limited=[], error=last_error)


# ---------- Job execution ----------
async def heartbeat_loop(job_id: str, stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE jobs_v0151 SET last_heartbeat_at=NOW(), updated_at=NOW() "
                        "WHERE job_id=%s AND status='running'",
                        (job_id,)
                    )
        except Exception:
            pass
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=20)
        except asyncio.TimeoutError:
            continue


async def execute_investigation(job_id: str, email: str, domain: str):
    async with job_semaphore:
        stop_event = asyncio.Event()
        heartbeat_task = asyncio.create_task(heartbeat_loop(job_id, stop_event))
        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE jobs_v0151 SET status='running', started_at=NOW(), "
                        "last_heartbeat_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                        (job_id,)
                    )

            holehe, dns_r, ddg, bing = await asyncio.gather(
                run_holehe(email), dns_lookup(domain),
                public_search("DuckDuckGo", email), public_search("Bing", email)
            )

            refs = []
            seen = set()
            for pr in (ddg, bing):
                for item in pr.get("results", []):
                    if item["url"] in seen:
                        continue
                    seen.add(item["url"])
                    refs.append({**item, "discovery_source": pr["source"]})

            # NOTE: no "email" field in result — prevents plaintext leak
            result_payload = {
                "schema_version": "0.15.1",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "sources": {
                    "holehe": holehe,
                    "dns": dns_r,
                    "duckduckgo": ddg,
                    "bing": bing,
                },
                "public_references": refs,
                "assessment": {
                    "conclusion": "unresolved",
                    "note": "Observations are leads only. No result establishes account ownership or common identity.",
                },
            }

            encrypted_result = cipher.encrypt(json.dumps(result_payload).encode()).decode()

            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE jobs_v0151 SET status='done', result_ciphertext=%s,
                        error=NULL, completed_at=NOW(), updated_at=NOW()
                        WHERE job_id=%s
                    """, (encrypted_result, job_id))
        except Exception as exc:
            log.exception("Job failed (id=%s)", job_id)
            try:
                with db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE jobs_v0151 SET status='failed', error=%s, "
                            "completed_at=NOW(), updated_at=NOW() WHERE job_id=%s",
                            (type(exc).__name__, job_id)
                        )
            except Exception:
                pass
        finally:
            stop_event.set()
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except (asyncio.CancelledError, Exception):
                pass


# ---------- API ----------
class CheckRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


@app.post("/api/check", dependencies=[Depends(require_auth)])
async def start_check(req: CheckRequest, bg: BackgroundTasks):
    email, domain = normalize_email(req.email)
    job_id = str(uuid.uuid4())
    encrypted_email = cipher.encrypt(email.encode()).decode()
    digest = hashlib.sha256(email.encode()).hexdigest()
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO jobs_v0151 (job_id,status,email_ciphertext,email_sha256)
                VALUES (%s,'pending',%s,%s)
            """, (job_id, encrypted_email, digest))
    bg.add_task(execute_investigation, job_id, email, domain)
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
                SELECT job_id,status,result_ciphertext,error,created_at,updated_at,
                       started_at,completed_at,last_heartbeat_at
                FROM jobs_v0151 WHERE job_id=%s
            """, (job_id,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(404, detail="Job not found")
    payload = dict(row)
    ciphertext = payload.pop("result_ciphertext", None)
    if ciphertext:
        try:
            payload["result"] = json.loads(cipher.decrypt(ciphertext.encode()).decode())
        except (InvalidToken, ValueError):
            payload["result"] = None
            payload["error"] = "Result could not be decrypted (encryption key changed?)"
    return payload


HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Infosys v0.15.1</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:18px;background:#090d12;color:#e5e7eb;font:15px -apple-system,BlinkMacSystemFont,system-ui,sans-serif}
main{max-width:850px;margin:auto}
header{text-align:center;padding:24px 0}
h1{color:#34d399;margin:0;font-size:26px}
.sub{color:#9ca3af;font-size:12px;margin:6px 0}
.panel{background:#111923;border:1px solid #263342;border-radius:12px;padding:16px;margin:14px 0}
input{width:100%;padding:12px;background:#080d13;border:1px solid #374151;border-radius:8px;color:white;margin:6px 0;font-size:15px}
button{width:100%;padding:14px;border:0;border-radius:8px;background:#34d399;color:#000;font-weight:700;margin-top:10px;cursor:pointer;font-size:15px}
button:disabled{opacity:.5;cursor:not-allowed}
button.link{background:transparent;color:#9ca3af;font-weight:400;font-size:12px;margin:0;padding:4px 0;text-align:right;width:auto}
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
hr{border:0;border-top:1px solid #263342;margin:14px 0}
summary{cursor:pointer;color:#fbbf24;font-weight:600;font-size:13px}
details{margin-top:8px}
</style>
</head>
<body>
<main>
<header>
  <h1>OSINT Infosys</h1>
  <p class="sub">Email intelligence · v0.15.1</p>
  <p class="warn">Authorized investigations only · findings are leads, not identity proof</p>
</header>

<section class="panel" id="auth-panel" style="display:none">
  <label>API token (paste once — saved in this browser)</label>
  <input id="token" type="password" autocomplete="off" placeholder="Paste your OSINT_API_TOKEN">
  <button onclick="saveToken()">Save &amp; Continue</button>
  <p class="muted">Stored only in your browser's localStorage. Clear via the Forget button later.</p>
</section>

<section class="panel" id="search-panel" style="display:none">
  <label>Email address</label>
  <input id="email" type="email" autocomplete="off" inputmode="email" placeholder="name@example.com">
  <button id="run" onclick="runCheck()">Investigate</button>
  <button class="link" onclick="forgetToken()">Forget saved token</button>
  <p class="muted">⚠️ External checks send this email to Holehe and DuckDuckGo/Bing. Use only for authorized investigations.</p>
</section>

<div id="status"></div>
<div id="results"></div>

</main>
<script>
const TOKEN_KEY = "osint_api_token_v0151";
let pollHandle = null;

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function getToken() { return localStorage.getItem(TOKEN_KEY) || ''; }

function saveToken() {
  const t = document.getElementById('token').value.trim();
  if (t.length < 32) { alert('Token must be at least 32 characters.'); return; }
  localStorage.setItem(TOKEN_KEY, t);
  showSearch();
}

function forgetToken() {
  localStorage.removeItem(TOKEN_KEY);
  document.getElementById('auth-panel').style.display = 'block';
  document.getElementById('search-panel').style.display = 'none';
}

function showSearch() {
  document.getElementById('auth-panel').style.display = 'none';
  document.getElementById('search-panel').style.display = 'block';
}

function authHeaders() {
  return {'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json'};
}

async function runCheck() {
  const email = document.getElementById('email').value.trim();
  if (!email) { alert('Enter an email address.'); return; }
  const btn = document.getElementById('run');
  btn.disabled = true;
  btn.textContent = 'Investigating…';
  document.getElementById('results').innerHTML = '';
  document.getElementById('status').innerHTML = '<div class="status">Starting investigation. First run after idle may take 60–120s.</div>';
  try {
    const r = await fetch('/api/check', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({email})
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || ('HTTP ' + r.status));
    poll(data.jobId);
  } catch (e) {
    showError(e.message);
  }
}

function poll(id) {
  let attempts = 0;
  clearInterval(pollHandle);
  pollHandle = setInterval(async () => {
    attempts++;
    if (attempts > 100) {
      clearInterval(pollHandle);
      showError('Polling limit reached. Check again later — do not assume completion.');
      return;
    }
    try {
      const r = await fetch('/api/job/' + encodeURIComponent(id), {headers: authHeaders()});
      const j = await r.json();
      if (!r.ok) throw new Error(j.detail || ('HTTP ' + r.status));
      if (['done','failed','interrupted'].includes(j.status)) {
        clearInterval(pollHandle);
        document.getElementById('run').disabled = false;
        document.getElementById('run').textContent = 'Investigate';
        if (j.status === 'done') render(j.result);
        else showError('Job ' + j.status + ': ' + (j.error || 'unknown'));
      } else {
        document.getElementById('status').innerHTML = '<div class="status">Job ' + esc(j.status) + '…</div>';
      }
    } catch (e) {
      clearInterval(pollHandle);
      showError(e.message);
    }
  }, 2500);
}

function showError(msg) {
  document.getElementById('run').disabled = false;
  document.getElementById('run').textContent = 'Investigate';
  document.getElementById('status').innerHTML = '<div class="status error">' + esc(msg) + '</div>';
}

function render(r) {
  document.getElementById('status').innerHTML = '<div class="status">Completed. Empty result is not proof of absence — review source statuses below.</div>';
  let out = '';

  for (const [key, val] of Object.entries(r.sources || {})) {
    if (key === 'dns') {
      for (const [k, v] of Object.entries(val || {})) out += section('DNS · ' + k, v);
    } else {
      out += section(key, val);
    }
  }

  out += '<section class="panel"><h3>Public references (' + (r.public_references || []).length + ')</h3>';
  for (const x of (r.public_references || [])) {
    const u = String(x.url || '');
    let safe = false;
    try { const p = new URL(u); safe = ['http:','https:'].includes(p.protocol); } catch {}
    out += '<div class="item"><b>' + esc(x.title || '(untitled)') + '</b>';
    out += '<p class="muted">' + esc(x.discovery_source || '') + '</p>';
    if (safe) out += '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + esc(u) + '</a>';
    if (x.snippet) out += '<p class="muted">' + esc(x.snippet) + '</p>';
    out += '</div>';
  }
  out += '</section>';

  out += '<section class="panel"><b>Assessment: ' + esc(r.assessment?.conclusion || 'unresolved') + '</b>';
  if (r.assessment?.note) out += '<p class="muted">' + esc(r.assessment.note) + '</p>';
  out += '</section>';

  document.getElementById('results').innerHTML = out;
}

function section(name, v) {
  const status = v?.status || 'unknown';
  const pillClass = status === 'found' ? 'found' : status === 'rate_limited' ? 'rate' : status === 'error' ? 'error' : '';
  let body = '';
  if (v?.found?.length) body += '<p>Found: ' + esc(v.found.join(', ')) + '</p>';
  if (v?.rate_limited?.length) {
    const total = (v.found?.length || 0) + (v.not_found?.length || 0) + (v.rate_limited?.length || 0);
    const pct = total > 0 ? Math.round(100 * v.rate_limited.length / total) : 0;
    body += '<details><summary>' + v.rate_limited.length + ' platforms rate-limited (' + pct + '%) — click to see which</summary>';
    body += '<p class="muted">Blocked by provider rate limits, not a negative result. The Render shared IP is the likely cause.</p>';
    body += '<p>' + esc(v.rate_limited.join(', ')) + '</p></details>';
  }
  if (v?.not_found?.length) body += '<p class="muted">Not found: ' + esc(v.not_found.join(', ')) + '</p>';
  if (v?.values?.length) body += '<p>' + esc(v.values.join(', ')) + '</p>';
  if (v?.results?.length) body += '<p>' + v.results.length + ' reference(s)</p>';
  if (v?.error) body += '<p class="bad">Error: ' + esc(v.error) + '</p>';
  if (v?.limitation) body += '<p class="muted">' + esc(v.limitation) + '</p>';
  return '<section class="panel"><h3>' + esc(name) + ' <span class="pill ' + pillClass + '">' + esc(status) + '</span></h3>' + body + '</section>';
}

// On load: decide auth vs search
if (getToken()) showSearch();
else document.getElementById('auth-panel').style.display = 'block';
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML
