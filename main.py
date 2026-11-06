"""
OSINT Infosys v0.13.2 — Email Intelligence
Holehe platform registrations + similar-email candidate discovery.
"""
import os
import sys
import json
import asyncio
import hashlib
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

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

app = FastAPI(title="OSINT Infosys", version="0.13.2")


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
    log.info("OSINT Infosys v0.13.2 starting")
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
    commands = [
        ["holehe", email, "--only-used", "--no-color"],
        ["python", "-m", "holehe", email, "--only-used", "--no-color"],
        [sys.executable, "-m", "holehe", email, "--only-used", "--no-color"],
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
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=150)
            except asyncio.TimeoutError:
                proc.kill()
                return {"status": "timeout", "found": [], "not_found": [],
                        "rate_limited": [], "error": "Holehe timed out after 150s"}

            output = stdout.decode("utf-8", errors="ignore")
            found, not_found, rate_limited = [], [], []
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Skip the summary legend that Holehe prints at the bottom
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


# ---------------------------------------------------------------- similar emails
def generate_variants(email: str, limit: int = 10) -> list[str]:
    local, _, domain = email.lower().rpartition("@")
    if not local or not domain:
        return []

    variants: list[str] = []
    parts = local.split(".")

    if len(parts) > 1:
        variants.append(".".join(reversed(parts)))
        variants.append("".join(reversed(parts)))
        variants.append("_".join(parts))
        variants.append("".join(parts))

    for suffix in ("93", "99", "01", "90", "1", "127", "123"):
        variants.append(f"{local}{suffix}")
        if parts:
            variants.append(f"{parts[0]}{suffix}")

    seen = {local}
    out = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(f"{v}@{domain}")
            if len(out) >= limit:
                break
    return out


async def fetch_gravatar(email: str) -> dict:
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{md5}?d=404&s=200"
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return {"exists": False, "md5": md5, "url": None, "image_sha": None}
            return {
                "exists": True, "md5": md5, "url": url,
                "image_sha": hashlib.sha256(r.content).hexdigest(),
            }
    except Exception:
        return {"exists": False, "md5": md5, "url": None, "image_sha": None}


async def discover_similar(email: str) -> list[dict]:
    variants = generate_variants(email)
    target = await fetch_gravatar(email)
    candidates = []
    for v in variants:
        g = await fetch_gravatar(v)
        if g["exists"] and target["exists"] and g["image_sha"] == target["image_sha"]:
            signal, reason = "HIGH", "Gravatar avatar matches target's avatar exactly. Weak ownership signal — not proof."
        elif g["exists"] and target["exists"]:
            signal, reason = "MEDIUM", "Gravatar avatar exists, but the image differs from target's. Weak signal."
        elif g["exists"]:
            signal, reason = "MEDIUM", "Gravatar avatar exists (target has none to compare)."
        else:
            signal, reason = "NONE", "No Gravatar exists. This variant was generated from rules only — zero evidence."
        candidates.append({
            "email": v, "signal": signal, "reason": reason,
            "gravatar_url": g.get("url"),
        })
    return candidates


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
        holehe_result, similar = await asyncio.gather(
            run_holehe(email),
            discover_similar(email),
        )
        result = {
            "email": email,
            "holehe": holehe_result,
            "similar_emails": similar,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        update("done", result=result)
        log.info(f"Job {job_id}: done ({len(holehe_result.get('found', []))} found, "
                 f"{len(holehe_result.get('rate_limited', []))} rate-limited)")
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
    return {"status": "ok", "version": "0.13.2"}


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
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.platform{background:#1f2937;padding:10px 12px;border-radius:6px;font-size:13px;
          border-left:3px solid #10b981;word-break:break-all}
.candidate{background:#1c1917;border:1px solid #78350f;border-radius:8px;
           padding:12px;margin-bottom:10px}
.candidate.high{border-color:#10b981;background:#052e1f}
.candidate.medium{border-color:#f59e0b}
.candidate.none{border-color:#4b5563;background:#0a0a0a}
.candidate .email{font-family:monospace;font-size:14px;color:#fff;margin-bottom:6px;
                  word-break:break-all}
.candidate .signal{display:inline-block;padding:3px 8px;border-radius:4px;
                   font-size:10px;font-weight:700;margin-right:8px}
.signal.HIGH{background:#065f46;color:#6ee7b7}
.signal.MEDIUM{background:#78350f;color:#fbbf24}
.signal.NONE{background:#374151;color:#9ca3af}
.candidate .reason{font-size:11px;color:#9ca3af;margin-top:6px;line-height:1.5}
.link{font-size:11px;color:#10b981;margin-top:8px;display:inline-block}
.footer{text-align:center;font-size:11px;color:#4b5563;padding:30px 0 20px;line-height:1.8}
details.rl{border:1px solid #78350f;background:#1c1917;border-radius:8px;padding:12px;margin-top:12px}
details.rl summary{cursor:pointer;font-size:12px;color:#fbbf24;font-weight:600}
details.rl .rl-note{font-size:11px;color:#9ca3af;margin:8px 0;line-height:1.5}
details.rl .rl-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
details.rl .rl-tags span{background:#292524;color:#fbbf24;padding:3px 8px;border-radius:4px;
                         font-size:10px;font-family:monospace;word-break:break-all}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>OSINT Infosys</h1>
    <p class="sub">Email intelligence investigation</p>
    <p class="warn">⚠️ For authorized investigations only</p>
  </header>

  <div class="search">
    <input id="email" type="email" placeholder="Enter email address"
           autocomplete="off" inputmode="email">
    <button id="run" onclick="runCheck()">🔍 Investigate</button>
  </div>

  <div id="status"></div>
  <div id="results"></div>

  <div class="footer">
    Holehe platform registrations · Gravatar candidate discovery<br>
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
    '<div class="status running">Scanning platforms via Holehe. First run after idle can take 60-120s.</div>';
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
        document.getElementById('run').textContent = '🔍 Investigate';
      } else if (job.status === 'failed') {
        clearInterval(pollTimer);
        showError(job.error || 'Investigation failed');
      }
    } catch (e) { clearInterval(pollTimer); showError('Polling error: ' + e.message); }
  }, 3000);
}

function showError(msg) {
  document.getElementById('run').disabled = false;
  document.getElementById('run').textContent = '🔍 Investigate';
  document.getElementById('status').innerHTML =
    '<div class="status error">Error: ' + escapeHtml(msg) + '</div>';
}

function renderResults(r) {
  const h = r.holehe || {};
  const found = h.found || [];
  const notFound = h.not_found || [];
  const rateLimited = h.rate_limited || [];
  const similar = r.similar_emails || [];
  const totalChecked = found.length + notFound.length + rateLimited.length;
  let html = '';

  // Platform registrations
  html += '<div class="card">';
  html += '<h2>Platform Registrations <span class="count">' + found.length + ' found</span></h2>';
  if (h.status === 'timeout' || h.status === 'error') {
    html += '<p style="color:#fca5a5;font-size:13px">Holehe scan ' +
            (h.status === 'timeout' ? 'timed out' : 'failed: ' + escapeHtml(h.error || '')) + '</p>';
  } else if (found.length === 0) {
    html += '<p style="color:#9ca3af;font-size:13px">No platform registrations detected. This is not a negative finding — the email may still be registered on platforms Holehe could not reach.</p>';
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
  if (rateLimited.length > 0 && totalChecked > 0) {
    const pct = Math.round(100 * rateLimited.length / totalChecked);
    html += '<details class="rl">';
    html += '<summary>⚠️ ' + rateLimited.length + ' platforms rate-limited (' + pct +
            '% of checked) — click to see which</summary>';
    html += '<p class="rl-note">Render\'s shared IP was blocked by these platforms. This is a coverage limit, not a negative result. To check these properly you need a dedicated IP (Oracle VM) or a paid Render plan.</p>';
    html += '<div class="rl-tags">';
    rateLimited.forEach(p => { html += '<span>' + escapeHtml(p) + '</span>'; });
    html += '</div></details>';
  }
  html += '</div>';

  // Similar emails
  if (similar.length > 0) {
    const high = similar.filter(s => s.signal === 'HIGH').length;
    const med = similar.filter(s => s.signal === 'MEDIUM').length;
    const none = similar.filter(s => s.signal === 'NONE').length;
    html += '<div class="card">';
    html += '<h2>Similar Email Candidates <span class="count">' + similar.length + ' total</span></h2>';
    html += '<p style="color:#f59e0b;font-size:11px;margin-bottom:14px">⚠️ These are <b>generated variants</b> — the tool invents them from name-pattern rules, then checks Gravatar as the only signal. They are <b>not discovered accounts</b>. Verify each manually or ignore if you do not recognise them.</p>';
    similar.forEach(s => {
      const cls = s.signal === 'HIGH' ? 'high' : s.signal === 'MEDIUM' ? 'medium' : 'none';
      const label = s.signal === 'HIGH' ? 'HIGH SIGNAL'
                   : s.signal === 'MEDIUM' ? 'WEAK SIGNAL'
                   : 'NO EVIDENCE';
      html += '<div class="candidate ' + cls + '">';
      html += '<div class="email">' + escapeHtml(s.email) + '</div>';
      html += '<span class="signal ' + s.signal + '">' + label + '</span>';
      html += '<div class="reason">' + escapeHtml(s.reason) + '</div>';
      if (s.gravatar_url) {
        html += '<a class="link" href="' + escapeHtml(s.gravatar_url) +
                '" target="_blank" rel="noopener">Open Gravatar →</a>';
      }
      html += '</div>';
    });
    html += '<p style="color:#6b7280;font-size:11px;margin-top:12px">' +
            high + ' high signal · ' + med + ' weak · ' + none + ' no evidence</p>';
    html += '</div>';
  }
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
