"""
OSINT Infosys v0.14 — Email Intelligence
DNS + Holehe + DuckDuckGo/Bing public references.
"""
import os
import sys
import json
import asyncio
import hashlib
import uuid
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("osint")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

app = FastAPI(title="OSINT Infosys", version="0.14.0")


# ---------------------------------------------------------------- storage
def db():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    conn.autocommit = True
    return conn


def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id      TEXT PRIMARY KEY,
                    status      TEXT NOT NULL,
                    email       TEXT NOT NULL,
                    result      JSONB,
                    error       TEXT,
                    created_at  TIMESTAMPTZ DEFAULT NOW(),
                    updated_at  TIMESTAMPTZ DEFAULT NOW()
                )
            """)


@app.on_event("startup")
async def startup_event():
    log.info("OSINT Infosys v0.14.0 starting")
    init_db()
    log.info("Database: initialized")
    for cmd in [["holehe", "--version"], [sys.executable, "-m", "holehe", "--version"]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            log.info(f"Holehe binary: reachable via '{' '.join(cmd[:2])}'")
            break
        except (FileNotFoundError, asyncio.TimeoutError):
            continue
    else:
        log.warning("Holehe binary: NOT FOUND — scans will return errors")


@app.head("/")
async def root_head():
    return {}


# ---------------------------------------------------------------- holehe
async def run_holehe(email: str) -> dict:
    """Run holehe WITHOUT --only-used so we see found + not-found + rate-limited."""
    commands = [
        ["holehe", email, "--no-color"],
        ["python", "-m", "holehe", email, "--no-color"],
        [sys.executable, "-m", "holehe", email, "--no-color"],
    ]
    last_error = None
    for cmd in commands:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                proc.kill()
                return {"status": "timeout", "found": [], "not_found": [],
                        "rate_limited": [], "error": "Holehe timed out after 180s"}

            output = stdout.decode("utf-8", errors="ignore")
            found, not_found, rate_limited = [], [], []
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "Email used" in line or "Email not used" in line or "Rate limit" in line:
                    continue
                if line.startswith("[+]"):
                    site = line[3:].strip()
                    if site and site not in found:
                        found.append(site)
                elif line.startswith("[-]"):
                    site = line[3:].strip()
                    if site and site not in not_found:
                        not_found.append(site)
                elif line.startswith("[x]"):
                    site = line[3:].strip()
                    if site and site not in rate_limited:
                        rate_limited.append(site)

            return {
                "status": "success",
                "found": found,
                "not_found": not_found,
                "rate_limited": rate_limited,
                "total": len(found) + len(not_found) + len(rate_limited),
            }
        except FileNotFoundError:
            last_error = f"command not found: {' '.join(cmd[:2])}"
            continue
        except Exception as e:
            last_error = str(e)
            continue

    return {"status": "error", "error": last_error or "unknown",
            "found": [], "not_found": [], "rate_limited": [], "total": 0}


# ---------------------------------------------------------------- public web search
async def search_duckduckgo(email: str, limit: int = 15) -> dict:
    """Search DuckDuckGo HTML for the exact email."""
    url = "https://html.duckduckgo.com/html/"
    params = {"q": f'"{email}"'}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Infosys/0.14)"}
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            r = await client.post(url, data=params, headers=headers)
            if r.status_code != 200:
                return {"status": "unavailable", "error": f"HTTP {r.status_code}", "results": []}
            html = r.text

        # Parse result blocks
        results = []
        # DuckDuckGo HTML result structure: <a class="result__a" href="URL">TITLE</a>
        # and <a class="result__snippet">SNIPPET</a>
        blocks = re.findall(
            r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?'
            r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
            html, re.DOTALL | re.IGNORECASE,
        )
        for href, title, snippet in blocks[:limit]:
            title = re.sub(r'<[^>]+>', '', title).strip()
            snippet = re.sub(r'<[^>]+>', '', snippet).strip()
            # Decode DuckDuckGo redirect wrapper
            if "uddg=" in href:
                m = re.search(r'uddg=([^&]+)', href)
                if m:
                    href = m.group(1)
            results.append({
                "title": title[:200],
                "url": href[:500],
                "snippet": snippet[:300],
            })
        return {"status": "success", "error": None, "results": results}
    except Exception as e:
        return {"status": "unavailable", "error": str(e)[:120], "results": []}


async def search_bing(email: str, limit: int = 15) -> dict:
    """Search Bing HTML for the exact email."""
    url = "https://www.bing.com/search"
    params = {"q": f'"{email}"'}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Infosys/0.14)"}
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            r = await client.get(url, params=params, headers=headers)
            if r.status_code != 200:
                return {"status": "unavailable", "error": f"HTTP {r.status_code}", "results": []}
            html = r.text

        results = []
        # Bing: <li class="b_algo"><h2><a href="URL">TITLE</a></h2>...<p>SNIPPET</p>
        blocks = re.findall(
            r'<li class="b_algo".*?<h2><a[^>]+href="([^"]+)"[^>]*>(.*?)</a></h2>.*?<p[^>]*>(.*?)</p>',
            html, re.DOTALL | re.IGNORECASE,
        )
        for href, title, snippet in blocks[:limit]:
            title = re.sub(r'<[^>]+>', '', title).strip()
            snippet = re.sub(r'<[^>]+>', '', snippet).strip()
            results.append({
                "title": title[:200],
                "url": href[:500],
                "snippet": snippet[:300],
            })
        return {"status": "success", "error": None, "results": results}
    except Exception as e:
        return {"status": "unavailable", "error": str(e)[:120], "results": []}


async def discover_public_references(email: str) -> dict:
    """Run DuckDuckGo and Bing searches concurrently, dedupe by URL."""
    dd, bing = await asyncio.gather(
        search_duckduckgo(email),
        search_bing(email),
    )
    combined = []
    seen_urls = set()
    for source_name, source in [("DuckDuckGo", dd), ("Bing", bing)]:
        for r in source["results"]:
            u = r["url"]
            if u in seen_urls:
                continue
            seen_urls.add(u)
            combined.append({
                "source": source_name,
                "title": r["title"],
                "url": u,
                "snippet": r["snippet"],
            })
    return {
        "duckduckgo": dd["status"],
        "duckduckgo_error": dd["error"],
        "bing": bing["status"],
        "bing_error": bing["error"],
        "results": combined,
    }


# ---------------------------------------------------------------- background job
async def run_job(job_id: str, email: str):
    def update(status, result=None, error=None):
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE jobs SET status=%s, result=%s, error=%s, updated_at=NOW() WHERE job_id=%s",
                    (status, json.dumps(result) if result else None, error, job_id),
                )

    update("running")
    log.info(f"Job {job_id}: running for {email}")

    try:
        holehe_result, public_refs = await asyncio.gather(
            run_holehe(email),
            discover_public_references(email),
        )
        result = {
            "email": email,
            "holehe": holehe_result,
            "public_references": public_refs,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        update("done", result=result)
        log.info(f"Job {job_id}: done ({len(holehe_result.get('found', []))} found, "
                 f"{len(holehe_result.get('rate_limited', []))} rate-limited, "
                 f"{len(public_refs.get('results', []))} public refs)")
    except Exception as e:
        log.exception(f"Job {job_id}: failed")
        update("failed", error=str(e))


# ---------------------------------------------------------------- API
class CheckRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


@app.post("/api/check")
async def start_check(req: CheckRequest, bg: BackgroundTasks):
    if "@" not in req.email or "." not in req.email.rpartition("@")[2]:
        raise HTTPException(400, "Invalid email format")
    job_id = str(uuid.uuid4())
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs (job_id, status, email) VALUES (%s, 'pending', %s)",
                (job_id, req.email),
            )
    bg.add_task(run_job, job_id, req.email)
    return {"jobId": job_id}


@app.get("/api/job/{job_id}")
async def get_job(job_id: str):
    with db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM jobs WHERE job_id=%s", (job_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Job not found")
            return dict(row)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "version": "0.14.0"}


# ---------------------------------------------------------------- frontend
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Infosys</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#0a0a0a;color:#e5e7eb;min-height:100vh;padding:20px}
.container{max-width:900px;margin:0 auto}
header{text-align:center;padding:30px 0 20px}
h1{color:#10b981;font-size:28px;margin-bottom:8px}
.sub{color:#6b7280;font-size:13px;margin-bottom:4px}
.warn{color:#f59e0b;font-size:11px;margin-top:8px}
.search{background:#111;border:1px solid #222;border-radius:12px;padding:20px;margin-bottom:20px}
input{width:100%;padding:16px;font-size:16px;background:#0a0a0a;
      border:1px solid #333;border-radius:8px;color:#fff;margin-bottom:12px}
input:focus{outline:none;border-color:#10b981}
button{width:100%;padding:16px;font-size:16px;font-weight:600;background:#10b981;
       color:#000;border:none;border-radius:8px;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
.status{padding:14px;border-radius:8px;margin-bottom:16px;font-size:13px}
.status.running{background:#1e3a8a33;color:#60a5fa;border:1px solid #1e40af66}
.status.error{background:#7f1d1d33;color:#fca5a5;border:1px solid #991b1b66}
.card{background:#111;border:1px solid #222;border-radius:12px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;color:#10b981;text-transform:uppercase;letter-spacing:1px;
         margin-bottom:14px;display:flex;justify-content:space-between;align-items:center}
.count{background:#064e3b;color:#6ee7b7;padding:4px 10px;border-radius:20px;font-size:12px}
.count.amber{background:#78350f;color:#fbbf24}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.platform{background:#1f2937;padding:10px 12px;border-radius:6px;font-size:13px;
          border-left:3px solid #10b981;word-break:break-all}
.ref{background:#111827;border:1px solid #374151;border-radius:8px;padding:12px;
     margin-bottom:10px}
.ref .ref-source{font-size:10px;color:#6b7280;text-transform:uppercase;margin-bottom:4px}
.ref .ref-title{font-size:14px;color:#e5e7eb;font-weight:600;margin-bottom:4px;line-height:1.4}
.ref .ref-url{font-size:11px;color:#10b981;word-break:break-all;margin-bottom:6px}
.ref .ref-snippet{font-size:12px;color:#9ca3af;line-height:1.5}
.footer{text-align:center;font-size:11px;color:#4b5563;padding:30px 0 20px;line-height:1.8}
details.rl{border:1px solid #78350f;background:#1c1917;border-radius:8px;padding:12px;margin-top:12px}
details.rl summary{cursor:pointer;font-size:12px;color:#fbbf24;font-weight:600}
details.rl .rl-note{font-size:11px;color:#9ca3af;margin:8px 0;line-height:1.5}
details.rl .rl-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
details.rl .rl-tags span{background:#292524;color:#fbbf24;padding:3px 8px;border-radius:4px;
                         font-size:10px;font-family:monospace;word-break:break-all}
.empty{color:#6b7280;font-size:13px;font-style:italic}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>OSINT Infosys</h1>
    <p class="sub">Email intelligence investigation</p>
    <p class="warn">For authorized investigations only</p>
  </header>

  <div class="search">
    <input id="email" type="email" placeholder="Enter email address"
           autocomplete="off" inputmode="email">
    <button id="run" onclick="runCheck()">Investigate</button>
  </div>

  <div id="status"></div>
  <div id="results"></div>

  <div class="footer">
    Holehe platform registrations · DuckDuckGo/Bing public references<br>
    All findings require manual verification
  </div>
</div>

<script>
let pollTimer = null;

async function runCheck() {
  const email = document.getElementById('email').value.trim();
  if (!email) return;
  document.getElementById('run').disabled = true;
  document.getElementById('run').textContent = 'Investigating...';
  document.getElementById('results').innerHTML = '';
  document.getElementById('status').innerHTML =
    '<div class="status running">Running Holehe + DuckDuckGo + Bing. First run after idle can take 60-120s.</div>';
  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email})
    });
    if (!res.ok) throw new Error('Server error: ' + res.status);
    const {jobId} = await res.json();
    poll(jobId);
  } catch (e) { showError(e.message); }
}

function poll(jobId) {
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch('/api/job/' + jobId);
      const job = await res.json();
      if (job.status === 'done') {
        clearInterval(pollTimer);
        renderResults(job.result);
        document.getElementById('status').innerHTML = '';
        document.getElementById('run').disabled = false;
        document.getElementById('run').textContent = 'Investigate';
      } else if (job.status === 'failed') {
        clearInterval(pollTimer);
        showError(job.error || 'Investigation failed');
      }
    } catch (e) { clearInterval(pollTimer); showError('Polling error: ' + e.message); }
  }, 3000);
}

function showError(msg) {
  document.getElementById('run').disabled = false;
  document.getElementById('run').textContent = 'Investigate';
  document.getElementById('status').innerHTML =
    '<div class="status error">Error: ' + escapeHtml(msg) + '</div>';
}

function renderResults(r) {
  const h = r.holehe || {};
  const found = h.found || [];
  const notFound = h.not_found || [];
  const rateLimited = h.rate_limited || [];
  const publicRefs = r.public_references || {};
  const refs = publicRefs.results || [];
  let html = '';

  // ---- Public references (most useful section first)
  html += '<div class="card">';
  html += '<h2>Public Web References <span class="count">' + refs.length + ' found</span></h2>';
  const ddStatus = publicRefs.duckduckgo || 'unknown';
  const bingStatus = publicRefs.bing || 'unknown';
  html += '<p style="color:#6b7280;font-size:11px;margin-bottom:12px">Searched DuckDuckGo (' + ddStatus + ') and Bing (' + bingStatus + ') for the exact email string.</p>';
  if (refs.length === 0) {
    html += '<p class="empty">No public web pages mentioned this email. This is a negative result from public search, not proof of absence.</p>';
  } else {
    refs.forEach(ref => {
      html += '<div class="ref">';
      html += '<div class="ref-source">' + escapeHtml(ref.source) + '</div>';
      html += '<div class="ref-title">' + escapeHtml(ref.title) + '</div>';
      html += '<a class="ref-url" href="' + escapeHtml(ref.url) + '" target="_blank" rel="noopener">' + escapeHtml(ref.url) + '</a>';
      if (ref.snippet) {
        html += '<div class="ref-snippet">' + escapeHtml(ref.snippet) + '</div>';
      }
      html += '</div>';
    });
  }
  html += '</div>';

  // ---- Holehe platform registrations
  html += '<div class="card">';
  const totalChecked = found.length + notFound.length + rateLimited.length;
  html += '<h2>Platform Registrations <span class="count">' + found.length + ' found</span> ' +
          '<span class="count amber">' + rateLimited.length + ' rate-limited</span></h2>';
  if (h.status === 'timeout' || h.status === 'error') {
    html += '<p style="color:#fca5a5;font-size:13px">Holehe scan ' +
            (h.status === 'timeout' ? 'timed out' : 'failed: ' + escapeHtml(h.error || '')) + '</p>';
  } else if (found.length === 0) {
    html += '<p class="empty">No platform registrations detected. May be rate-limited on all platforms.</p>';
  } else {
    html += '<div class="grid">';
    found.forEach(p => { html += '<div class="platform">' + escapeHtml(p) + '</div>'; });
    html += '</div>';
  }
  if (totalChecked > 0) {
    html += '<p style="color:#6b7280;font-size:11px;margin-top:12px">Checked ' + totalChecked +
            ' platforms · ' + found.length + ' found · ' + notFound.length + ' not found · ' +
            rateLimited.length + ' rate-limited</p>';
  }
  if (rateLimited.length > 0) {
    const pct = totalChecked > 0 ? Math.round(100 * rateLimited.length / totalChecked) : 0;
    html += '<details class="rl">';
    html += '<summary>' + rateLimited.length + ' platforms rate-limited (' + pct +
            '% of checked) — click to see which</summary>';
    html += '<p class="rl-note">The Render shared IP was blocked by these platforms. This is a coverage limit, not a negative result. Use Sherlock, DuckDuckGo, or a different engine to compensate.</p>';
    html += '<div class="rl-tags">';
    rateLimited.forEach(p => { html += '<span>' + escapeHtml(p) + '</span>'; });
    html += '</div></details>';
  }
  html += '</div>';

  document.getElementById('results').innerHTML = html;
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = String(s == null ? '' : s);
  return d.innerHTML;
}
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML
