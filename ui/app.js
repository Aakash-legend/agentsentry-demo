/**
 * app.js – AgentSentry UI
 *
 * Connects to:
 *   - Gateway backend: http://localhost:8002
 *   - Attacker backend: http://localhost:8001
 *   - Mock collector:   http://localhost:9999
 *
 * Uses SSE for live streaming from both backends.
 * Evidence panel checks real filesystem via attacker backend proxy endpoints.
 */

const GATEWAY_URL   = 'http://localhost:8002';
const ATTACKER_URL  = 'http://localhost:8001';
const COLLECTOR_URL = 'http://localhost:9999';

// ── State ─────────────────────────────────────────────────────────────────
let gatewayActive   = false;
let gatewayEnforce  = true;
let attackRunning   = false;
let feedCount       = 0;
let bpfCount        = 0;
let attackerSSE     = null;
let gatewaySSE      = null;
let statusPollTimer = null;

// ── DOM helpers ───────────────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const el = (tag, cls, html='') => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html) e.innerHTML = html;
  return e;
};

// ── Init ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  pollGatewayStatus();
  pollAttackStatus();
  connectGatewaySSE();
  refreshEvidence();
  statusPollTimer = setInterval(() => {
    pollGatewayStatus();
    pollAttackStatus();
  }, 3000);
  setInterval(refreshEvidence, 5000);
});

// ── Gateway status ────────────────────────────────────────────────────────
async function pollGatewayStatus() {
  try {
    const r = await fetch(`${GATEWAY_URL}/status`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) throw new Error('non-2xx');
    const d = await r.json();
    updateGatewayUI(d.active, d.enforce, d.cgroup_id);
  } catch {
    updateGatewayUI(false, false, null, true);
  }
}

function updateGatewayUI(active, enforce, cgroupId, unreachable=false) {
  gatewayActive  = active;
  gatewayEnforce = enforce;

  const dot   = $('gateway-status-dot');
  const text  = $('gateway-status-text');
  const mode  = $('gateway-mode-text');
  const cgEl  = $('gateway-cgroup-id');
  const btnOn = $('btn-gateway-start');
  const btnOff= $('btn-gateway-stop');

  if (unreachable) {
    dot.className = 'status-dot danger';
    text.textContent = '⚠ Gateway unreachable';
    text.style.color = '#f87171';
    mode.textContent = '—';
    return;
  }

  if (active) {
    dot.className = 'status-dot active';
    text.textContent = '● ACTIVE';
    text.style.color = '#6ee7b7';
    btnOn.disabled = true;
    btnOff.disabled = false;
  } else {
    dot.className = 'status-dot';
    text.textContent = '○ INACTIVE';
    text.style.color = '#94a3b8';
    btnOn.disabled = false;
    btnOff.disabled = true;
  }

  mode.textContent = active ? (enforce ? '🔴 ENFORCE (deny)' : '🟡 LOG-ONLY') : '—';
  mode.style.color = enforce && active ? '#f87171' : '#fbbf24';

  if (cgroupId) {
    cgEl.textContent = String(cgroupId);
  }

  // Sync toggle
  $('enforce-toggle').checked = enforce;
}

// ── Attack status ─────────────────────────────────────────────────────────
async function pollAttackStatus() {
  try {
    const r = await fetch(`${ATTACKER_URL}/status`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) return;
    const d = await r.json();
    attackRunning = d.running;
    $('attack-status-text').textContent = d.running ? '⚡ Running…' : 'Idle';
    $('attack-status-text').style.color = d.running ? '#fbbf24' : '#94a3b8';
    $('attack-steps-done').textContent  = `${d.steps_completed} / 7`;
    $('attack-status-dot').className = d.running ? 'status-dot danger' : 'status-dot';
    $('btn-run-attack').disabled = d.running;
  } catch { /* attacker not reachable */ }
}

// ── Gateway control ───────────────────────────────────────────────────────
async function gatewayStart() {
  const enforce = $('enforce-toggle').checked;
  try {
    const r = await fetch(`${GATEWAY_URL}/start?enforce=${enforce}`, { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      showToast('✅ Gateway started', 'success');
      await pollGatewayStatus();
      connectGatewaySSE();
    } else {
      showToast('❌ ' + d.msg, 'error');
    }
  } catch(e) {
    showToast('❌ Gateway unreachable: ' + e.message, 'error');
  }
}

async function gatewayStop() {
  if (!confirm('Stop gateway? Demo will be FAIL-OPEN. Attacker will succeed.')) return;
  try {
    const r = await fetch(`${GATEWAY_URL}/stop`, { method: 'POST' });
    const d = await r.json();
    showToast(d.ok ? '🟡 Gateway stopped (fail-open)' : '❌ ' + d.msg, d.ok ? 'warn' : 'error');
    await pollGatewayStatus();
  } catch(e) {
    showToast('❌ Gateway unreachable', 'error');
  }
}

async function toggleEnforce(enable) {
  try {
    await fetch(`${GATEWAY_URL}/enforce`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enable }),
    });
    await pollGatewayStatus();
    showToast(enable ? '🔴 Enforce mode ON' : '🟡 Log-only mode', enable ? 'warn' : 'info');
  } catch {
    showToast('Cannot reach gateway', 'error');
  }
}

// ── Run attack ────────────────────────────────────────────────────────────
async function runAttack() {
  // Clear terminal, reconnect SSE
  clearTerminal();
  connectAttackerSSE();

  try {
    const r = await fetch(`${ATTACKER_URL}/run`, { method: 'POST' });
    const d = await r.json();
    if (!d.ok) {
      showToast('❌ ' + d.msg, 'error');
    } else {
      showToast('⚔️ Attack sequence started', 'info');
      $('btn-run-attack').disabled = true;
    }
  } catch(e) {
    showToast('❌ Attacker backend unreachable: ' + e.message, 'error');
  }
}

// ── SSE: Attacker feed ────────────────────────────────────────────────────
function connectAttackerSSE() {
  if (attackerSSE) { attackerSSE.close(); attackerSSE = null; }

  const src = new EventSource(`${ATTACKER_URL}/stream`);
  attackerSSE = src;

  src.onmessage = e => {
    try {
      const data = JSON.parse(e.data);
      handleAttackerEvent(data);
    } catch {}
  };
  src.onerror = () => {
    // SSE auto-reconnects; we'll reconnect manually on run
  };
}

function handleAttackerEvent(data) {
  if (data.type === 'connected') return;
  if (data.type === 'attack_start') {
    appendTerminalLine('─'.repeat(60), 'color: #374151');
    appendTerminalLine(`ATTACK SEQUENCE STARTED @ ${new Date().toLocaleTimeString()}`, 'color: #fbbf24; font-weight: 600;');
    appendTerminalLine('─'.repeat(60), 'color: #374151');
    return;
  }
  if (data.type === 'attack_done') {
    appendTerminalLine('─'.repeat(60), 'color: #374151');
    appendTerminalLine(`ATTACK COMPLETE – ${data.total_steps || '?'} steps executed`, 'color: #94a3b8');
    $('btn-run-attack').disabled = false;
    refreshEvidence();
    return;
  }
  if (data.type === 'step' || data.name) {
    renderStepCard(data);
    feedCount++;
    $('feed-count').textContent = `${feedCount} events`;
  }
}

// ── SSE: Gateway BPF events ───────────────────────────────────────────────
function connectGatewaySSE() {
  if (gatewaySSE) { gatewaySSE.close(); gatewaySSE = null; }

  const src = new EventSource(`${GATEWAY_URL}/events`);
  gatewaySSE = src;

  src.onmessage = e => {
    try {
      const data = JSON.parse(e.data);
      if (data.type === 'connected') return;
      renderBPFEvent(data);
    } catch {}
  };
}

// ── Render: step card ─────────────────────────────────────────────────────
function renderStepCard(step) {
  const terminal = $('terminal');

  // Remove idle placeholder
  const idle = terminal.querySelector('.terminal-idle');
  if (idle) idle.remove();

  const verdict   = (step.verdict || 'ERROR').toLowerCase();
  const isBlocked = verdict.includes('blocked');
  const verdictClass = isBlocked ? 'blocked' : (verdict === 'succeeded' ? 'succeeded' : 'error');
  const badgeText    = isBlocked ? '🛡 BLOCKED by kernel' : (verdict === 'succeeded' ? '✅ SUCCEEDED' : '⚠ ERROR');

  const expl = step.explanation_card || {};
  const stdout = (step.stdout || '').trim();
  const stderr = (step.stderr || '').trim();
  const output = stdout + (stderr ? (stdout ? '\n' : '') + '[stderr] ' + stderr : '');

  const ts = step.timestamp ? new Date(step.timestamp * 1000).toLocaleTimeString() : '';

  const card = el('div', `step-card ${verdictClass}`);
  card.innerHTML = `
    <div class="step-header">
      <div class="step-meta">
        <div class="step-num">Step ${step.step_num || '?'}</div>
        <div class="step-name">${esc(step.name || 'Unknown')}</div>
      </div>
      <div class="verdict-badge ${verdictClass}">${badgeText}</div>
    </div>
    <div class="step-command">${esc(step.command || '')}</div>
    ${output ? `<div class="step-output${isBlocked ? ' error-out' : ''}">${esc(output)}</div>` : ''}
    <div class="explanation-card">
      <div class="explanation-hook">${esc(expl.kernel_hook || step.kernel_event || 'kernel event')}</div>
      <div class="explanation-text">${esc(expl.plain_english || step.explanation || '')}</div>
    </div>
    <div class="step-timestamp">⏱ ${ts} · exit ${step.exit_code !== null && step.exit_code !== undefined ? step.exit_code : '?'}</div>
  `;

  terminal.appendChild(card);
  terminal.scrollTop = terminal.scrollHeight;
}

// ── Render: BPF event row ─────────────────────────────────────────────────
function renderBPFEvent(evt) {
  const feed = $('bpf-feed');
  const idle = feed.querySelector('.bpf-idle');
  if (idle) idle.remove();

  const isAllow = evt.verdict === 'allow';
  const ts = evt.ts ? new Date(evt.ts * 1000).toLocaleTimeString('en', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';

  const row = el('div', `bpf-event ${isAllow ? 'allow' : 'deny'}`);
  row.innerHTML = `
    <span class="bpf-ts">${ts}</span>
    <span class="bpf-pid">pid:${evt.pid || '?'}</span>
    <span class="bpf-kind">${esc(evt.kind || '?')}</span>
    <span class="bpf-path" title="${esc(evt.path || '')}">${esc((evt.path || '').slice(0, 50))}</span>
    <span class="bpf-verdict ${isAllow ? 'allow' : 'deny'}">${isAllow ? 'ALLOW' : 'DENY'}</span>
  `;

  feed.appendChild(row);
  feed.scrollTop = feed.scrollHeight;

  bpfCount++;
  $('bpf-count').textContent = `${bpfCount} events`;
}

// ── Evidence panel ────────────────────────────────────────────────────────
async function refreshEvidence() {
  // Check 1: /tmp/outside/pwned.txt – via attacker backend proxy
  await checkPwnedFile();
  // Check 2: collector received data
  await checkCollector();
  // Check 3: secrets readable (test read via attacker)
  await checkSecretsReadable();
}

async function checkPwnedFile() {
  // We need the attacker backend to check the real filesystem
  // (UI running in browser can't directly stat files)
  // Use a dedicated endpoint
  try {
    const r = await fetch(`${ATTACKER_URL}/check/pwned`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) throw new Error();
    const d = await r.json();
    setEvidence('pwned', d.exists,
      d.exists ? `EXISTS – ${d.content?.slice(0, 60) || 'content present'}` : 'Does not exist',
      d.exists ? 'PWNED' : 'SAFE'
    );
  } catch {
    setEvidence('pwned', null, 'Gateway unreachable', '—');
  }
}

async function checkCollector() {
  try {
    const r = await fetch(`${COLLECTOR_URL}/entries`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) throw new Error();
    const d = await r.json();
    const got = d.count > 0;
    setEvidence('collector', got,
      got ? `${d.count} payload(s) received` : 'No data received',
      got ? 'PWNED' : 'SAFE'
    );
  } catch {
    setEvidence('collector', null, 'Collector unreachable', '—');
  }
}

async function checkSecretsReadable() {
  try {
    const r = await fetch(`${ATTACKER_URL}/check/secrets`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) throw new Error();
    const d = await r.json();
    setEvidence('secrets', d.readable,
      d.readable ? `Readable (first 60 chars): ${d.content?.slice(0, 60)}…` : 'Blocked (EPERM)',
      d.readable ? 'PWNED' : 'SAFE'
    );
  } catch {
    setEvidence('secrets', null, 'Attacker unreachable', '—');
  }
}

function setEvidence(key, pwned, detail, badgeText) {
  const valEl   = $(`ev-${key}-val`);
  const badgeEl = $(`ev-${key}-badge`);
  if (valEl)   valEl.textContent = detail;
  if (badgeEl) {
    badgeEl.textContent = badgeText;
    badgeEl.className = 'evidence-badge ' + (pwned === null ? 'unknown' : pwned ? 'pwned' : 'safe');
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────
function clearResults() {
  clearTerminal();
  feedCount = 0; bpfCount = 0;
  $('feed-count').textContent = '0 events';
  $('bpf-count').textContent  = '0 events';
  $('bpf-feed').innerHTML = '<div class="bpf-idle">Kernel events will appear here when gateway is active…</div>';
}

function clearTerminal() {
  $('terminal').innerHTML = '<div class="terminal-idle"><div class="idle-icon">🖥️</div><div class="idle-text">Waiting for attack…</div><div class="idle-sub">Press <strong>Run Attack</strong> to start the demo sequence</div></div>';
}

function appendTerminalLine(text, style='') {
  const terminal = $('terminal');
  const idle = terminal.querySelector('.terminal-idle');
  if (idle) idle.remove();
  const line = el('div', '');
  line.style.cssText = `font-family: var(--font-mono); font-size: 0.72rem; padding: 2px 0; ${style}`;
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Toast notifications ───────────────────────────────────────────────────
function showToast(msg, type='info') {
  const colors = {
    success: '#10b981', error: '#ef4444', warn: '#f59e0b', info: '#6366f1'
  };
  const toast = el('div', '');
  toast.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 9999;
    background: #1a1f2e; border: 1px solid ${colors[type] || '#6366f1'};
    border-left: 4px solid ${colors[type] || '#6366f1'};
    color: #f1f5f9; padding: 12px 18px; border-radius: 10px;
    font-family: var(--font-sans); font-size: 0.78rem; font-weight: 500;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    animation: slideInToast 0.3s cubic-bezier(0.16,1,0.3,1);
    max-width: 360px;
  `;
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
