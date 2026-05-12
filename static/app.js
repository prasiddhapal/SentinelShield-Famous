/**
 * SentinelShield — Frontend JavaScript (SQLite Edition)
 * Pulls data from DB-backed API endpoints, renders all panels.
 */

// ──────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────
const ATTACK_COLORS = {
  'SQL Injection':              '#ef4444',
  'Cross-Site Scripting (XSS)': '#f59e0b',
  'Directory Traversal':        '#f97316',
  'Local File Inclusion (LFI)': '#a855f7',
  'Command Injection':          '#ec4899',
  'Brute-force / Rate Limit':   '#06b6d4',
  'SSRF Attack':                '#10b981',
  'XML External Entity (XXE)':  '#8b5cf6',
  'Insecure Deserialization':   '#dc2626',
  'Normal':                     '#22c55e',
};

const SIMULATIONS = {
  sql:      () => fetch(`/search?id=1' OR '1'='1`),
  xss:      () => fetch('/comment', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: "body=<script>alert('xss')</script>",
  }),
  lfi:      () => fetch('/view?file=/etc/shadow'),
  traversal:() => fetch('/view?file=../../etc/passwd'),
  cmd:      () => fetch('/exec?cmd=ls;cat+/etc/passwd'),
  ssrf:     () => fetch('/proxy?url=http://strip.169.254.169.254/latest/meta-data/'),
  xxe:      () => fetch('/upload', {
    method: 'POST',
    headers: {'Content-Type': 'application/xml'},
    body: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
  }),
  deserial: () => fetch('/api/data', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: '{"state": "O:8:\\"stdClass\\":0:{}"}'
  }),
  brute:    async () => {
    const results = [];
    for (let i = 1; i <= 3; i++) {
      const r = await fetch(`/login?user=admin&pass=test${i}`);
      results.push(r.status);
      await sleep(150);
    }
    return { status: results.includes(403) ? 403 : 200 };
  },
  normal:   () => fetch('/index.html'),
};

const SIM_LABELS = {
  sql:      "SQL Injection — GET /search?id=1' OR '1'='1",
  xss:      "XSS — POST /comment body=<script>alert('xss')</script>",
  lfi:      'LFI — GET /view?file=/etc/shadow',
  traversal:'Dir. Traversal — GET /view?file=../../etc/passwd',
  cmd:      'Cmd Injection — GET /exec?cmd=ls;cat+/etc/passwd',
  ssrf:     'SSRF — GET /proxy?url=169.254.169.254',
  xxe:      'XXE — POST /upload (XML external entity)',
  deserial: 'Deserialization — POST /api/data (Serialized Obj)',
  brute:    'Brute Force — 3x rapid GET /login (triggers rate limiter)',
  normal:   'Normal — GET /index.html (should be ALLOWED)',
};

// ──────────────────────────────────────────
//  Utilities
// ──────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function animateNumber(el, target, suffix='') {
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  if (start === target) return;
  const step = (target - start) / 20;
  let cur = start, count = 0;
  const id = setInterval(() => {
    cur += step; count++;
    const done = count >= 20;
    el.textContent = Math.round(done ? target : cur) + suffix;
    if (done) clearInterval(id);
  }, 20);
}

// ──────────────────────────────────────────
//  Clock
// ──────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('headerTime');
  if (el) el.textContent = new Date().toLocaleTimeString('en-GB', {hour12: false});
}
setInterval(updateClock, 1000);
updateClock();

// ──────────────────────────────────────────
//  Toast
// ──────────────────────────────────────────
function showToast(msg, type = 'allowed') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type.toLowerCase()}`;
  const icon = type === 'BLOCKED' ? '🛡️' : type === 'FLAGGED' ? '⚠️' : '✅';
  toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(msg)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ──────────────────────────────────────────
//  Donut Chart (canvas)
// ──────────────────────────────────────────
function drawDonut(canvasId, data, colors) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const total = data.reduce((s, d) => s + d.value, 0);
  if (total === 0) {
    ctx.beginPath();
    ctx.arc(w/2, h/2, w*0.38, 0, Math.PI*2);
    ctx.strokeStyle = 'rgba(68,114,196,0.12)';
    ctx.lineWidth = w * 0.12;
    ctx.stroke();
    return;
  }
  let angle = -Math.PI / 2;
  const cx = w/2, cy = h/2, outerR = w*0.42, innerR = w*0.28;
  data.forEach((item, i) => {
    const sl = (item.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx + innerR * Math.cos(angle), cy + innerR * Math.sin(angle));
    ctx.arc(cx, cy, outerR, angle, angle + sl);
    ctx.arc(cx, cy, innerR, angle + sl, angle, true);
    ctx.closePath();
    ctx.fillStyle = colors[i % colors.length];
    ctx.shadowColor = colors[i % colors.length];
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;
    angle += sl;
  });
}

// ──────────────────────────────────────────
//  Daily Bar Chart
// ──────────────────────────────────────────
async function refreshDaily() {
  try {
    const res = await fetch('/api/daily?days=7');
    const data = await res.json();

    const container = document.getElementById('dailyBars');
    if (!container) return;

    const maxTotal = Math.max(...data.map(d => d.total), 1);
    const chartH = 110; // usable height px

    container.innerHTML = data.map(d => {
      const blockedH = Math.round((d.blocked / maxTotal) * chartH);
      const flaggedH = Math.round((d.flagged / maxTotal) * chartH);
      const allowedH = Math.round((d.allowed / maxTotal) * chartH);
      const label = d.day.slice(5); // MM-DD
      return `
        <div class="daily-bar-group-wrap">
          ${d.total > 0 ? `<div class="daily-bar-count">${d.total}</div>` : ''}
          <div class="daily-bar-stack" style="height:${Math.max(blockedH+flaggedH+allowedH,2)}px">
            ${blockedH > 0 ? `<div class="daily-bar-seg blocked" style="height:${blockedH}px"></div>` : ''}
            ${flaggedH > 0 ? `<div class="daily-bar-seg flagged" style="height:${flaggedH}px"></div>` : ''}
            ${allowedH > 0 ? `<div class="daily-bar-seg allowed" style="height:${allowedH}px"></div>` : ''}
          </div>
          <div class="daily-bar-label">${label}</div>
        </div>`;
    }).join('');
  } catch(e) { console.warn('Daily refresh error:', e); }
}

// ──────────────────────────────────────────
//  IP Reputation Table
// ──────────────────────────────────────────
async function refreshReputation() {
  try {
    const res = await fetch('/api/reputation');
    const data = await res.json();
    const tbody = document.getElementById('repTableBody');
    if (!tbody) return;

    if (data.length === 0) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty-state small"><p>No IP records yet</p></div></td></tr>`;
      return;
    }

    tbody.innerHTML = data.map(r => {
      const threatLevel = r.blocked_count > 5 ? 'var(--blocked-color)' :
                          r.blocked_count > 0 ? 'var(--flagged-color)' : 'var(--text-secondary)';
      return `
        <tr class="${r.blocked_count > 0 ? 'row-blocked' : 'row-allowed'}">
          <td class="td-ip" style="color:${threatLevel};font-weight:600">${r.ip}</td>
          <td class="td-timestamp">${r.total_requests}</td>
          <td style="color:var(--blocked-color);font-weight:600;font-family:var(--font-mono);font-size:.75rem">${r.blocked_count}</td>
          <td style="color:var(--flagged-color);font-weight:600;font-family:var(--font-mono);font-size:.75rem">${r.flagged_count}</td>
          <td class="td-timestamp">${(r.first_seen||'—').slice(0,16)}</td>
          <td class="td-timestamp">${(r.last_seen||'—').slice(0,16)}</td>
        </tr>`;
    }).join('');
  } catch(e) { console.warn('Reputation refresh error:', e); }
}

// ──────────────────────────────────────────
//  Risk Score System
// ──────────────────────────────────────────
const GAUGE_ARC_LEN = 172; // SVG arc total length

function riskColor(level) {
  return {critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#22c55e'}[level] || '#3b82f6';
}

async function refreshRisk() {
  try {
    const res = await fetch('/api/risk');
    const data = await res.json();
    const d = data.distribution;
    const total = data.total || 1;

    // Count cards
    ['critical','high','medium','low'].forEach(lvl => {
      const count = d[lvl]?.count || 0;
      const pct   = Math.round(count / total * 100);
      const countEl = document.getElementById(`risk${lvl.charAt(0).toUpperCase()+lvl.slice(1)}Count`);
      const barEl   = document.getElementById(`risk${lvl.charAt(0).toUpperCase()+lvl.slice(1)}Bar`);
      if (countEl) animateNumber(countEl, count);
      if (barEl)   barEl.style.width = pct + '%';
    });

    // Gauge arc (avg score)
    const avgScore = data.overall_avg || 0;
    const maxScore = data.overall_max || 0;
    const gaugeEl = document.getElementById('gaugeArc');
    const avgEl   = document.getElementById('riskAvgScore');
    const maxEl   = document.getElementById('riskMaxScore');

    if (gaugeEl) {
      const offset = GAUGE_ARC_LEN - (avgScore / 100) * GAUGE_ARC_LEN;
      const color  = avgScore >= 76 ? '#ef4444' : avgScore >= 51 ? '#f97316' : avgScore >= 26 ? '#f59e0b' : '#22c55e';
      gaugeEl.style.strokeDashoffset = offset;
      gaugeEl.style.stroke = color;
      gaugeEl.style.transition = 'stroke-dashoffset 0.8s ease, stroke 0.4s';
    }
    if (avgEl) avgEl.textContent = avgScore;
    if (maxEl) { maxEl.textContent = maxScore; }

    // High-risk events table
    const tbody = document.getElementById('riskEventsBody');
    const badgeEl = document.getElementById('riskEventsBadge');
    const events = data.recent_high_risk || [];
    if (badgeEl) badgeEl.textContent = events.length ? `${events.length} critical/high events` : 'Critical & High only';

    if (!tbody) return;
    if (events.length === 0) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty-state small"><p>No critical or high risk events yet</p></div></td></tr>`;
      return;
    }
    tbody.innerHTML = events.map(e => {
      const lvl   = e.risk_level || 'low';
      const color = riskColor(lvl);
      const pill  = `<span class="action-pill pill-${e.action.toLowerCase()}">${e.action}</span>`;
      return `
        <tr class="row-${e.action.toLowerCase()}">
          <td class="td-timestamp" style="color:var(--text-dim)">${e.id}</td>
          <td class="td-timestamp">${e.timestamp}</td>
          <td class="td-ip">${e.ip}</td>
          <td style="color:${ATTACK_COLORS[e.attack_type]||'#fff'};font-size:.75rem;font-weight:500">${e.attack_type}</td>
          <td><span class="risk-pill risk-pill-${lvl}">${e.risk_score}</span></td>
          <td><span style="color:${color};font-size:.72rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase">${lvl}</span></td>
          <td>${pill}</td>
        </tr>`;
    }).join('');
  } catch(e) { console.warn('Risk refresh error:', e); }
}


async function refreshReport() {
  try {
    const res = await fetch('/api/report');
    const data = await res.json();
    const grid = document.getElementById('reportGrid');
    const genEl = document.getElementById('reportGenTime');
    if (!grid) return;

    if (genEl) genEl.textContent = `Generated: ${data.generated_at}`;

    const s = data.summary;
    const detRate = s.total_requests > 0
      ? ((s.total_blocked + s.total_flagged) / s.total_requests * 100).toFixed(1)
      : '0.0';

    grid.innerHTML = `
      <!-- Summary Card -->
      <div class="report-card">
        <div class="report-card-title">📊 Session Summary</div>
        <div class="report-card-body">
          <div class="report-stat-row"><span class="report-stat-key">Total Requests</span><span class="report-stat-val">${s.total_requests}</span></div>
          <div class="report-stat-row"><span class="report-stat-key">Blocked</span><span class="report-stat-val" style="color:var(--blocked-color)">${s.total_blocked}</span></div>
          <div class="report-stat-row"><span class="report-stat-key">Flagged</span><span class="report-stat-val" style="color:var(--flagged-color)">${s.total_flagged}</span></div>
          <div class="report-stat-row"><span class="report-stat-key">Allowed</span><span class="report-stat-val" style="color:var(--allowed-color)">${s.total_allowed}</span></div>
          <div class="report-stat-row"><span class="report-stat-key">Detection Rate</span><span class="report-stat-val" style="color:var(--accent-primary)">${detRate}%</span></div>
          <div class="report-stat-row"><span class="report-stat-key">Unique IPs</span><span class="report-stat-val">${s.unique_ips}</span></div>
          <div class="report-stat-row"><span class="report-stat-key">First Event</span><span class="report-stat-val">${(s.first_event||'—').slice(0,16)}</span></div>
          <div class="report-stat-row"><span class="report-stat-key">Last Event</span><span class="report-stat-val">${(s.last_event||'—').slice(0,16)}</span></div>
        </div>
      </div>

      <!-- Attack Breakdown Card -->
      <div class="report-card">
        <div class="report-card-title">💉 Attack Breakdown</div>
        <div class="report-card-body">
          ${data.attack_breakdown.length === 0
            ? '<div style="color:var(--text-muted);font-size:.8rem;padding:.5rem 0">No attacks recorded yet</div>'
            : data.attack_breakdown.map(a => `
              <div class="report-stat-row">
                <span class="report-stat-key" style="color:${ATTACK_COLORS[a.attack_type]||'#fff'}">${a.attack_type}</span>
                <span class="report-stat-val">${a.count} hits / ${a.unique_ips} IPs</span>
              </div>`).join('')}
        </div>
      </div>

      <!-- Repeat Offenders Card -->
      <div class="report-card">
        <div class="report-card-title">🔁 Repeat Offenders</div>
        <div class="report-card-body">
          ${data.repeat_offenders.length === 0
            ? '<div style="color:var(--text-muted);font-size:.8rem;padding:.5rem 0">No repeat attackers yet</div>'
            : data.repeat_offenders.map(r => `
              <div class="report-stat-row">
                <span class="report-stat-key" style="font-family:var(--font-mono);font-size:.72rem">${r.ip}</span>
                <span class="report-stat-val" style="color:var(--blocked-color)">${r.blocked_count}B / ${r.flagged_count}F</span>
              </div>`).join('')}
        </div>
      </div>
    `;
  } catch(e) { console.warn('Report refresh error:', e); }
}

// ──────────────────────────────────────────
//  Stats Update
// ──────────────────────────────────────────
async function refreshStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();

    animateNumber(document.getElementById('statTotal'),   data.total);
    animateNumber(document.getElementById('statBlocked'), data.blocked);
    animateNumber(document.getElementById('statFlagged'), data.flagged);
    animateNumber(document.getElementById('statAllowed'), data.allowed);
    const rateEl = document.getElementById('statRate');
    if (rateEl) rateEl.textContent = data.detection_rate + '%';

    // Donut chart
    const dist = data.attack_distribution || {};
    const keys = Object.keys(dist);
    const chartData = keys.map(k => ({ label: k, value: dist[k] }));
    const chartColors = keys.map(k => ATTACK_COLORS[k] || '#4472C4');
    const totalThreats = chartData.reduce((s, d) => s + d.value, 0);
    drawDonut('distChart', chartData, chartColors);
    animateNumber(document.getElementById('chartCenterNum'), totalThreats);
    const badgeEl = document.getElementById('attackBadge');
    if (badgeEl) badgeEl.textContent = keys.length ? `${keys.length} threat type${keys.length>1?'s':''}` : 'No attacks yet';

    // Legend
    const legendEl = document.getElementById('chartLegend');
    if (legendEl) {
      legendEl.innerHTML = chartData.map((d,i) => `
        <div class="legend-item">
          <div class="legend-left"><div class="legend-dot" style="background:${chartColors[i]}"></div><span class="legend-name">${d.label}</span></div>
          <span class="legend-count">${d.value}</span>
        </div>`).join('') || `<div class="legend-item"><span style="color:var(--text-muted);font-size:.78rem">No attack events yet</span></div>`;
    }

    // Top attackers
    const attackerList = document.getElementById('attackerList');
    if (attackerList) {
      const top = data.top_attackers || [];
      if (top.length === 0) {
        attackerList.innerHTML = `<div class="empty-state"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><p>No threats detected yet</p></div>`;
      } else {
        const maxCount = top[0]?.count || 1;
        attackerList.innerHTML = top.map((a, i) => `
          <div class="attacker-item">
            <div class="attacker-rank">${i+1}</div>
            <div class="attacker-ip">${a.ip}</div>
            <div class="attacker-bar-wrap"><div class="attacker-bar" style="width:${Math.round(a.count/maxCount*100)}%"></div></div>
            <div class="attacker-count">${a.count}</div>
          </div>`).join('');
      }
    }
  } catch(e) { console.warn('Stats refresh error:', e); }
}

// ──────────────────────────────────────────
//  Log Table
// ──────────────────────────────────────────
let lastLogId = 0;

function triggerThreatAnimation(newLogs) {
  const overlay = document.getElementById('threatOverlay');
  if (!overlay || newLogs.length === 0) return;

  // Clear existing animations to re-trigger
  overlay.classList.remove('flash-critical', 'flash-high', 'flash-medium', 'flash-low');
  document.body.style.animation = '';
  
  // Force a reflow
  void overlay.offsetWidth;

  const hasCrit = newLogs.some(l => l.risk_level === 'critical');
  const hasHigh = newLogs.some(l => l.risk_level === 'high');
  const hasMed = newLogs.some(l => l.risk_level === 'medium');

  if (hasCrit) {
    overlay.classList.add('flash-critical');
    document.body.style.animation = 'shakeCrit 0.5s cubic-bezier(.36,.07,.19,.97) both';
    setTimeout(() => { document.body.style.animation = ''; }, 500);
  } else if (hasHigh) {
    overlay.classList.add('flash-high');
  } else if (hasMed) {
    overlay.classList.add('flash-medium');
  } else {
    // Flash low severity color if it's a blocked/flagged event but only low risk
    const isThreat = newLogs.some(l => l.action !== 'ALLOWED' || l.attack_type !== 'Normal');
    if (isThreat) overlay.classList.add('flash-low');
  }
}

async function refreshLogs() {
  try {
    const res = await fetch('/api/logs?limit=80');
    const logs = await res.json();
    const tbody = document.getElementById('logTableBody');
    if (!tbody || logs.length === 0) {
      if (tbody) tbody.innerHTML = `<tr class="empty-row"><td colspan="9"><div class="empty-state small"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><p>No logs yet. All events save to SQLite automatically.</p></div></td></tr>`;
      return;
    }

    const topId = logs[0]?.id || 0;
    
    // Determine new logs for animation (skip initial load)
    if (lastLogId > 0 && topId > lastLogId) {
      const newLogs = logs.filter(l => l.id > lastLogId);
      triggerThreatAnimation(newLogs);
    }
    
    if (topId === lastLogId) return;
    lastLogId = topId;

    const ATTACK_COLORS_local = ATTACK_COLORS;
    tbody.innerHTML = logs.map((e, idx) => {
      const action = e.action || 'ALLOWED';
      const rowClass = `row-${action.toLowerCase()}`;
      const pillClass = `pill-${action.toLowerCase()}`;
      const methodClass = `method-${e.method}`;
      const isNew = idx === 0 ? 'new-row' : '';
      const aColor = ATTACK_COLORS_local[e.attack_type] || 'var(--text-secondary)';
      const pathFull = e.query ? `${e.path}?${e.query}` : e.path;
      const sevClass = `sev-${(e.severity||'info').toLowerCase()}`;
      return `
        <tr class="${rowClass} ${isNew}">
          <td class="td-timestamp" style="color:var(--text-dim)">${e.id}</td>
          <td class="td-timestamp">${e.timestamp}</td>
          <td class="td-ip">${e.ip}</td>
          <td class="td-method"><span class="${methodClass}">${e.method}</span></td>
          <td class="td-path" title="${escapeHtml(pathFull)}">${escapeHtml(pathFull.slice(0,40))}${pathFull.length>40?'…':''}</td>
          <td style="color:${aColor};font-size:.75rem;font-weight:500">${e.attack_type}</td>
          <td><span class="${sevClass}">${e.severity}</span></td>
          <td><span class="risk-pill risk-pill-${e.risk_level||'low'}">${e.risk_score||0}</span></td>
          <td class="td-payload" title="${escapeHtml(e.payload||'')}"><code>${escapeHtml((e.payload||'—').slice(0,50))}${(e.payload||'').length>50?'…':''}</code></td>
          <td><span class="action-pill ${pillClass}">${action}</span></td>
        </tr>`;
    }).join('');
  } catch(e) { console.warn('Log refresh error:', e); }
}

// ──────────────────────────────────────────
//  Attack Simulator
// ──────────────────────────────────────────
window.simulate = async function(type) {
  const btn = document.querySelector(`[onclick="simulate('${type}')"]`);
  const resultEl = document.getElementById('simResult');
  if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; }
  resultEl.className = 'sim-result visible';
  resultEl.innerHTML = `<span>⏳</span><span>Sending request to WAF...</span>`;

  try {
    const resp = await SIMULATIONS[type]();
    const status = typeof resp.status !== 'undefined' ? resp.status : 200;
    const isBlocked = status === 403;
    const isNormal = type === 'normal';
    const color = isBlocked ? 'var(--blocked-color)' : isNormal ? 'var(--allowed-color)' : 'var(--flagged-color)';
    const icon = isBlocked ? '🛡️' : isNormal ? '✅' : '⚠️';
    const result = isBlocked ? 'BLOCKED' : 'ALLOWED';
    const toastType = isBlocked ? 'BLOCKED' : isNormal ? 'ALLOWED' : 'FLAGGED';
    resultEl.innerHTML = `<span>${icon}</span><span style="color:${color};font-weight:600">${result} (HTTP ${status}) — saved to DB</span> — <span style="color:var(--text-secondary)">${SIM_LABELS[type]}</span>`;
    showToast(`${result}: ${type.toUpperCase()} simulation logged to SQLite`, toastType);
    await sleep(400);
    await refreshAll();
  } catch(err) {
    resultEl.innerHTML = `<span>❌</span><span style="color:var(--blocked-color)">Request failed: ${err.message}</span>`;
  } finally {
    if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
  }
};

// ──────────────────────────────────────────
//  Clear Logs
// ──────────────────────────────────────────
document.getElementById('clearBtn')?.addEventListener('click', async () => {
  if (!confirm('Delete all logs from SQLite database and reset rate limiter?')) return;
  await fetch('/api/clear', { method: 'POST' });
  lastLogId = 0;
  await refreshAll();
  showToast('Database cleared', 'allowed');
});

// ──────────────────────────────────────────
//  Users by Risk Tier
// ──────────────────────────────────────────
async function refreshUsersByRisk() {
  try {
    const res = await fetch('/api/users-by-risk');
    const data = await res.json();
    
    const badgeEl = document.getElementById('usersRiskBadge');
    if (badgeEl) badgeEl.textContent = `Tracking ${data.total_unique_ips} distinct IPs`;

    const tiers = ['critical', 'high', 'medium', 'low'];
    
    tiers.forEach(tier => {
      const tierData = data.tiers[tier];
      const countEl = document.getElementById(`tier${tier.charAt(0).toUpperCase() + tier.slice(1)}Count`);
      const listEl = document.getElementById(`tier${tier.charAt(0).toUpperCase() + tier.slice(1)}List`);
      
      if (countEl) countEl.textContent = tierData.count;
      
      if (!listEl) return;
      if (tierData.ips.length === 0) {
        listEl.innerHTML = `<div class="empty-state small"><p>No ${tier} risk users</p></div>`;
        return;
      }
      
      listEl.innerHTML = tierData.ips.map(u => {
        const attackColor = ATTACK_COLORS[u.top_attack] || 'var(--text-secondary)';
        return `
          <div class="user-risk-card">
            <div class="urc-top">
              <span class="urc-ip">${u.ip}</span>
              <span class="urc-score">${u.max_score} max</span>
            </div>
            <div class="urc-stats">
              <span title="Total Requests"><b>${u.total_requests}</b> reqs</span>
              <span title="Blocked Hits" style="color:var(--blocked-color)"><b>${u.blocked}</b> B</span>
              <span title="Flagged Hits" style="color:var(--flagged-color)"><b>${u.flagged}</b> F</span>
            </div>
            <div class="urc-attack" style="color:${attackColor}">
              Top Threat: ${u.top_attack}
            </div>
          </div>
        `;
      }).join('');
    });

  } catch (err) {
    console.warn('Users by Risk refresh error:', err);
  }
}

// ──────────────────────────────────────────
//  Banned Actors
// ──────────────────────────────────────────
async function refreshBans() {
  try {
    const res = await fetch('/api/bans');
    const data = await res.json();
    const tbody = document.getElementById('banTableBody');
    if (!tbody) return;

    if (data.length === 0) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="5"><div class="empty-state small"><p>No permanent bans active</p></div></td></tr>`;
      return;
    }

    tbody.innerHTML = data.map(b => `
      <tr class="row-blocked">
        <td class="td-ip" style="color:var(--blocked-color);font-weight:700">${b.ip}</td>
        <td style="font-size:.78rem;color:var(--text-secondary)">${b.reason}</td>
        <td class="td-timestamp">${b.timestamp.slice(0,16)}</td>
        <td><span class="risk-pill risk-pill-critical">${b.total_risk_at_ban}</span></td>
        <td>
          <button class="btn-export" style="font-size:.65rem;padding:.2rem .5rem;" onclick="liftBan('${b.ip}')">
            Lift Ban
          </button>
        </td>
      </tr>`).join('');
  } catch(e) { console.warn('Bans refresh error:', e); }
}

window.liftBan = async function(ip) {
  if (!confirm(`Are you sure you want to lift the permanent ban for ${ip}?`)) return;
  try {
    const res = await fetch('/api/bans/lift', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip })
    });
    if (res.ok) {
      showToast(`Ban lifted for ${ip}`, 'allowed');
      await refreshBans();
    }
  } catch(e) { showToast('Failed to lift ban', 'blocked'); }
};

// ──────────────────────────────────────────
//  Geographic Intelligence (D3 Map)
// ──────────────────────────────────────────
let d3MapInitialized = false;

async function initD3Map() {
  const container = document.getElementById('d3-map-container');
  if (!container || !window.d3 || !window.topojson) return;

  const width = container.clientWidth || 800;
  const height = container.clientHeight || 450;

  const svg = d3.select('#d3-map-container')
    .append('svg')
    .attr('class', 'world-map-svg')
    .attr('viewBox', `0 0 ${width} ${height}`)
    .style('width', '100%')
    .style('height', '100%');

  const projection = d3.geoMercator()
    .scale(120)
    .translate([width / 2, height / 1.5]);
  
  const path = d3.geoPath().projection(projection);

  try {
    const world = await d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
    const countries = topojson.feature(world, world.objects.countries).features;
    
    svg.append('g')
      .selectAll('.country-path')
      .data(countries)
      .enter().append('path')
      .attr('class', 'country-path')
      .attr('d', path)
      .attr('data-cname', d => d.properties.name);
      
    d3MapInitialized = true;
  } catch(e) { console.warn("D3 Error:", e); }
}

async function refreshGeo() {
  if (!d3MapInitialized) await initD3Map();
  try {
    const res = await fetch('/api/geo');
    const data = await res.json();
    
    // 1. Update Badge
    const badge = document.getElementById('geoBadge');
    if (badge) badge.textContent = `${data.total_countries} regions targeted globally`;

    // 2. Update Map Paths (Pulsate active regions)
    if (window.d3 && d3MapInitialized) {
      d3.selectAll('.country-path').each(function() {
        const pathEl = d3.select(this);
        const cname = pathEl.attr('data-cname');
        if (!cname) return;
        
        // Match by country name (fuzzy matching for topology differences)
        const countryData = data.distribution.find(d => 
          d.country_name === cname || cname.includes(d.country_name) || d.country_name.includes(cname) || d.country_name === "United States" && cname === "United States of America"
        );
        
        if (countryData) {
          pathEl.classed('country-active', true);
          pathEl.classed('country-pulse', countryData.max_risk >= 70);
        } else {
          pathEl.classed('country-active', false);
          pathEl.classed('country-pulse', false);
        }
      });
    }

    // 3. Update Leaderboard
    const rankList = document.getElementById('geoRankList');
    if (rankList) {
      if (data.distribution.length === 0) {
        rankList.innerHTML = `<div class="empty-state small"><p>No global threats yet</p></div>`;
      } else {
        rankList.innerHTML = data.distribution.slice(0, 5).map(c => `
          <div class="country-rank-item">
            <img src="https://flagcdn.com/w40/${c.country_code.toLowerCase()}.png" class="country-flag" alt="${c.country_code}">
            <span class="country-name-txt">${c.country_name}</span>
            <span class="country-hits">${c.count} atk</span>
          </div>
        `).join('');
      }
    }

    // 4. Update Geo Feed
    const geoFeed = document.getElementById('geoFeed');
    if (geoFeed) {
      if (data.recent_geo.length === 0) {
        geoFeed.innerHTML = `<div class="empty-state small"><p>Local traffic only...</p></div>`;
      } else {
        geoFeed.innerHTML = data.recent_geo.map(g => `
          <div class="geo-feed-item">
            <div class="geo-feed-dot"></div>
            <div class="geo-feed-body">
              <div class="geo-feed-ip">${g.ip} (${g.country_code})</div>
              <div class="geo-feed-meta">${g.attack_type} · ${g.timestamp.split(' ')[1]}</div>
            </div>
          </div>
        `).join('');
      }
    }

  } catch (err) { console.warn('Geo refresh error:', err); }
}

// ──────────────────────────────────────────
//  Master Refresh
// ──────────────────────────────────────────
async function refreshAll() {
  await Promise.all([
    refreshStats(),
    refreshLogs(),
    refreshDaily(),
    refreshReputation(),
    refreshReport(),
    refreshRisk(),
    refreshUsersByRisk(),
    refreshBans(),
    refreshGeo(),
  ]);
}

// Startup + polling
refreshAll();
setInterval(refreshAll, 3000);
