/* Stack — encrypted supplement tracker (client app).
 * All crypto client-side. Server stores one opaque vault blob.
 * Keys live in memory only; auto-lock after 15 min idle.
 */
import {
  generateMnemonic, validateMnemonic, mnemonicToSeed, deriveKeys,
  sealVault, openVault, encodeVaultState, decodeVaultState,
  createDeviceSeal, openDeviceSeal, randomId, wipe,
} from './crypto.js';

const $ = (sel, el = document) => el.querySelector(sel);
const root = $('#root');
const toastEl = $('#toast');

const SEAL_KEY = 'stack_seal_v1';
const THEME_KEY = 'stack_theme';
const LOCK_MS = 15 * 60 * 1000;

/* ---------------- helpers ---------------- */

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function localDate(d = new Date()) {
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

function shiftDate(ds, n) {
  const [y, m, d] = ds.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  dt.setDate(dt.getDate() + n);
  return localDate(dt);
}

function fmtDate(ds) {
  const [y, m, d] = ds.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
}

function relDay(ds) {
  const t = localDate();
  if (ds === t) return 'Today';
  if (ds === shiftDate(t, -1)) return 'Yesterday';
  if (ds === shiftDate(t, 1)) return 'Tomorrow';
  return '';
}

function notifPerm() {
  try { return (typeof Notification !== 'undefined' && Notification.permission) || 'unsupported'; }
  catch (e) { return 'unsupported'; }
}
function notifStatus() {
  const p = notifPerm();
  return p === 'granted' ? 'Enabled' : p === 'denied' ? 'Blocked in browser settings' : p === 'unsupported' ? 'Not supported in this browser' : 'Not enabled';
}
function notifCanAsk() {
  const p = notifPerm();
  return p !== 'granted' && p !== 'denied' && p !== 'unsupported';
}

let toastTimer;
function toast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2600);
}

async function apiGet(path) {
  const r = await fetch(path);
  if (r.status === 404) return { exists: false, status: 404 };
  const j = await r.json();
  j.status = r.status; j.ok = r.ok;
  return j;
}

async function apiPut(path, body) {
  const r = await fetch(path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  j.status = r.status; j.ok = r.ok;
  return j;
}

/* ---------------- session (memory only) ---------------- */

let session = null;      // { seed, dataKey, ownerId }
let vault = null;        // decrypted vault state
let serverVersion = 0;
let tab = 'today';
let viewDate = localDate();
let calYear, calMonth, calSelected = null;
let syncBusy = false;
const notified = {};     // groupId -> dateStr already notified

function lock(reason) {
  if (session) { wipe(session.seed); wipe(session.dataKey); }
  session = null; vault = null; serverVersion = 0;
  clearTimeout(lockTimer);
  renderUnlock(reason);
}

let lockTimer;
function armLock() {
  clearTimeout(lockTimer);
  lockTimer = setTimeout(() => { if (session) { toast('Locked after 15 min idle'); lock(); } }, LOCK_MS);
}
['pointerdown', 'keydown', 'touchstart'].forEach(ev =>
  window.addEventListener(ev, () => { if (session) armLock(); }, { passive: true }));

/* ---------------- vault model ---------------- */

function newVaultState() {
  const t = localDate();
  return {
    v: 1,
    groups: [
      { id: randomId(), name: 'Morning', sort: 0, reminder: null },
      { id: randomId(), name: 'Afternoon', sort: 1, reminder: null },
      { id: randomId(), name: 'Evening', sort: 2, reminder: null },
    ],
    supplements: [],
    logs: {},
    created: t,
  };
}

function activeOn(s, d) {
  return s.created <= d && (!s.archived || s.archived >= d);
}

function isTaken(suppId, d) {
  return (vault.logs[suppId] || []).includes(d);
}

function sortedGroups() {
  return [...vault.groups].sort((a, b) => a.sort - b.sort);
}

function groupSupps(gid, d) {
  return vault.supplements
    .filter(s => s.groupId === gid && !s.archived && activeOn(s, d))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function dayStats(d) {
  let taken = 0, total = 0;
  for (const s of vault.supplements) {
    if (!activeOn(s, d)) continue;
    total++;
    if (isTaken(s.id, d)) taken++;
  }
  return { taken, total };
}

function suppDates(suppId) {
  return [...new Set(vault.logs[suppId] || [])].sort();
}

function streaks(dates) {
  if (!dates.length) return { current: 0, longest: 0 };
  const ds = [...new Set(dates)].sort();
  let longest = 1, run = 1;
  for (let i = 1; i < ds.length; i++) {
    const a = new Date(ds[i - 1] + 'T12:00:00'), b = new Date(ds[i] + 'T12:00:00');
    if ((b - a) / 86400000 === 1) run++;
    else { longest = Math.max(longest, run); run = 1; }
  }
  longest = Math.max(longest, run);
  const set = new Set(ds);
  const t = localDate(), y = shiftDate(t, -1);
  let cur = t, current = 0;
  if (!set.has(t)) cur = y;
  while (set.has(cur)) { current++; cur = shiftDate(cur, -1); }
  return { current, longest };
}

/* ---------------- persistence ---------------- */

function setSync(busy) {
  syncBusy = busy;
  const el = $('#syncdot');
  if (el) el.className = 'sync-dot' + (busy ? ' busy' : '');
}

async function loadVaultFromServer() {
  const meta = await apiGet('/api/vault');
  if (!meta.exists) throw new Error('no vault on server');
  const pt = openVault(session.dataKey, meta.iv, meta.ciphertext);
  return { state: decodeVaultState(pt), version: meta.version };
}

async function commit(mutFn) {
  mutFn(vault);               // mutFns must be idempotent (re-applied on 409)
  renderTab();
  setSync(true);
  const blob = () => {
    const s = sealVault(session.dataKey, encodeVaultState(vault));
    return { iv: s.nonceB64, ciphertext: s.ctB64 };
  };
  let r = await apiPut('/api/vault', { ...blob(), base_version: serverVersion });
  if (r.status === 409) {
    try {
      const fresh = await loadVaultFromServer();
      vault = fresh.state; serverVersion = fresh.version;
      mutFn(vault);
      renderTab();
      r = await apiPut('/api/vault', { ...blob(), base_version: serverVersion });
    } catch (e) { /* fall through to failure handling */ }
  }
  if (r && r.ok) {
    serverVersion = r.version;
  } else {
    toast('Sync failed — reloading server state');
    try {
      const fresh = await loadVaultFromServer();
      vault = fresh.state; serverVersion = fresh.version; renderTab();
    } catch (e) { /* offline; keep local */ }
  }
  setSync(false);
}

/* mutations (idempotent) */
const mToggle = (suppId, d) => v => {
  const arr = v.logs[suppId] || (v.logs[suppId] = []);
  const i = arr.indexOf(d);
  if (i === -1) arr.push(d); else arr.splice(i, 1);
};
const mLogAll = (gid, d) => v => {
  for (const s of v.supplements) {
    if (s.groupId !== gid || s.archived || !activeOn(s, d)) continue;
    const arr = v.logs[s.id] || (v.logs[s.id] = []);
    if (!arr.includes(d)) arr.push(d);
  }
};
const mAddSupp = obj => v => {
  if (!v.supplements.find(s => s.id === obj.id)) v.supplements.push(obj);
};
const mEditSupp = (id, patch) => v => {
  const s = v.supplements.find(x => x.id === id);
  if (s) Object.assign(s, patch);
};
const mArchiveSupp = (id, d) => v => {
  const s = v.supplements.find(x => x.id === id);
  if (s) { s.archived = d; }
};
const mAddGroup = obj => v => {
  if (!v.groups.find(g => g.id === obj.id)) {
    obj.sort = Math.max(-1, ...v.groups.map(g => g.sort)) + 1;
    v.groups.push(obj);
  }
};
const mEditGroup = (id, patch) => v => {
  const g = v.groups.find(x => x.id === id);
  if (g) Object.assign(g, patch);
};
const mDeleteGroup = (id, moveTo) => v => {
  if (moveTo) for (const s of v.supplements) if (s.groupId === id) s.groupId = moveTo;
  else { const d = localDate(); for (const s of v.supplements) if (s.groupId === id && !s.archived) s.archived = d; }
  v.groups = v.groups.filter(g => g.id !== id);
};

/* ---------------- theme ---------------- */

function applyTheme() {
  const t = localStorage.getItem(THEME_KEY) || 'dark';
  document.documentElement.dataset.theme = t;
  document.querySelector('meta[name="theme-color"]').content = t === 'dark' ? '#070510' : '#eef0ff';
}
function toggleTheme() {
  const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem(THEME_KEY, t);
  applyTheme();
}

/* ---------------- icons ---------------- */

const ICONS = {
  today: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
  cal: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="5" width="18" height="16" rx="3"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>',
  hist: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 20h18"/><path d="M6 16v-5M11 16V8M16 16v-8M21 16V5"/></svg>',
  gear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.06-.4.1-.8.1-1.2z"/></svg>',
  pill: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><rect x="3" y="8" width="18" height="8" rx="4" transform="rotate(-45 12 12)"/><path d="M8.5 15.5l7-7"/></svg>',
  mark: '<svg class="app-mark" viewBox="0 0 48 48"><defs><linearGradient id="hmbg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#1a1b3a"/><stop offset=".5" stop-color="#2d1b4e"/><stop offset="1" stop-color="#0f0c29"/></linearGradient><linearGradient id="hmp1" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#a78bfa"/><stop offset="1" stop-color="#3b82f6"/></linearGradient><linearGradient id="hmp2" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#c4b5fd"/><stop offset="1" stop-color="#6366f1"/></linearGradient><linearGradient id="hmp3" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#8b5cf6"/><stop offset="1" stop-color="#2563eb"/></linearGradient></defs><rect width="48" height="48" rx="14" fill="url(#hmbg)"/><g transform="translate(24 15.5) rotate(-18)"><rect x="-10" y="-3.2" width="20" height="6.4" rx="3.2" fill="url(#hmp1)"/><rect x="-10" y="-3.2" width="10" height="6.4" rx="3.2" fill="#fff" opacity=".3"/></g><g transform="translate(24 24.5) rotate(12)"><rect x="-10" y="-3.2" width="20" height="6.4" rx="3.2" fill="url(#hmp2)"/><rect x="-10" y="-3.2" width="10" height="6.4" rx="3.2" fill="#fff" opacity=".28"/></g><g transform="translate(26.5 33.5) rotate(-22)"><rect x="-10" y="-3.2" width="20" height="6.4" rx="3.2" fill="url(#hmp3)"/><rect x="-10" y="-3.2" width="10" height="6.4" rx="3.2" fill="#fff" opacity=".28"/></g></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="4" y="10" width="16" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5z"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="8" cy="15" r="4.5"/><path d="M11.5 11.5L20 3M15.5 7.5l3 3M12.5 10.5l2.5 2.5"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3L2.5 20h19L12 3z"/><path d="M12 9.5V14"/><circle cx="12" cy="17" r="0.5" fill="currentColor"/></svg>',
  flame: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c4.4 0 7.5-3 7.5-7.2 0-3.1-1.9-5.4-3.7-7.2-.4 1.2-1.1 2.3-2.1 3.1.3-2.7-.8-6.1-3.2-8.7-2.6 2.9-6 7.3-6 12.8 0 4.2 3.1 7.2 7.5 7.2z"/></svg>',
  clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12.5l5 5L20 6.5"/></svg>',
};

/* ==================================================================
   ONBOARDING
   ================================================================== */

let ob = null;

function renderOnboarding() {
  ob = { step: 'welcome' };
  drawOnboarding();
}

function stepDots(n, total) {
  let s = '<div class="step-dots">';
  for (let i = 0; i < total; i++) s += `<i class="${i < n ? 'on' : ''}"></i>`;
  return s + '</div>';
}

function drawOnboarding() {
  const c = ob.step;
  let html = '';
  if (c === 'welcome') {
    html = `
    <div class="screen fadein"><div class="glass-deep onboard-card">
      <div class="hero-mark">${ICONS.mark}</div>
      <div class="hero-title">Stack</div>
      <div class="hero-sub">Your supplement tracker, sealed with encryption.<br>
      Your <b>12-word recovery code</b> is the only key —<br>not even this server can read your data.</div>
      <button class="btn" id="ob-create">Create new vault</button>
      <div class="divider">OR</div>
      <button class="btn btn-ghost" id="ob-restore">I have a recovery code</button>
    </div></div>`;
  } else if (c === 'show-words') {
    const words = ob.mnemonic.split(' ');
    html = `
    <div class="screen fadein"><div class="glass-deep onboard-card">
      ${stepDots(1, 4)}
      <h1>Your recovery code</h1>
      <div class="sub" style="margin:8px 0 4px">Write these 12 words down <b>in order</b>. You'll confirm them next.</div>
      <div class="words-grid">${words.map((w, i) => `<div class="word-chip"><span class="num">${i + 1}</span>${esc(w)}</div>`).join('')}</div>
      <div class="warning-box"><b class="warn-inline">${ICONS.warn} No recovery exists.</b> If you lose these 12 words, your data is gone forever. Nobody — not even the developer — can get it back.</div>
      <label class="checkline"><input type="checkbox" id="ob-written"><span>I've written down all 12 words in order</span></label>
      <button class="btn" id="ob-words-next" disabled>Continue</button>
    </div></div>`;
  } else if (c === 'confirm-words') {
    html = `
    <div class="screen fadein"><div class="glass-deep onboard-card confirm-words">
      ${stepDots(2, 4)}
      <h1>Confirm your code</h1>
      <div class="sub" style="margin:8px 0 16px">Enter the requested words from your recovery code.</div>
      ${ob.confirmIdx.map(i => `
        <div class="field"><label>Word #${i + 1}</label>
        <input class="input" id="cw-${i}" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="word #${i + 1}"></div>`).join('')}
      <div class="err" id="ob-err" style="display:none"></div>
      <button class="btn" id="ob-confirm-next">Verify</button>
      <button class="link-btn" id="ob-back-words">← Back to my words</button>
    </div></div>`;
  } else if (c === 'device-pw') {
    html = `
    <div class="screen fadein"><div class="glass-deep onboard-card">
      ${stepDots(3, 4)}
      <h1>Quick unlock?</h1>
      <div class="sub" style="margin:8px 0 4px">Set a password to unlock quickly on <b>this device only</b>.
      It never leaves this browser.</div>
      <div class="warning-box blue"><b>Know the tradeoff:</b> if someone steals this device, they can try to
      brute-force your password offline. A strong password + the heavy Argon2id key derivation are your protection.
      You can skip this and just use your 12 words every time.</div>
      <div id="pw-form" style="display:none">
        <div class="field" style="text-align:left"><label>Device password</label>
        <input class="input" type="password" id="ob-pw1" autocomplete="new-password" placeholder="Choose a strong password"></div>
        <div class="field" style="text-align:left"><label>Confirm password</label>
        <input class="input" type="password" id="ob-pw2" autocomplete="new-password" placeholder="Repeat it"></div>
        <div class="err" id="ob-err" style="display:none"></div>
      </div>
      <button class="btn" id="ob-pw-set" style="display:none">Encrypt & continue</button>
      <button class="btn btn-ghost" id="ob-pw-show">Set a device password</button>
      <div class="divider">OR</div>
      <button class="link-btn" id="ob-skip-pw">Skip — I'll use my 12 words</button>
    </div></div>`;
  } else if (c === 'working') {
    html = `
    <div class="screen"><div class="glass-deep onboard-card">
      <div class="hero-mark">${ICONS.mark}</div>
      <h1>${esc(ob.workingText || 'Working…')}</h1>
      <div class="spinner"></div>
      <div class="sub">${esc(ob.workingSub || 'Deriving encryption keys. This takes a few seconds by design.')}</div>
    </div></div>`;
  } else if (c === 'restore') {
    html = `
    <div class="screen fadein"><div class="glass-deep onboard-card">
      <div class="hero-mark">${ICONS.mark}</div>
      <h1>Restore vault</h1>
      <div class="sub" style="margin:8px 0 16px">Enter your 12-word recovery code to unlock your vault.</div>
      <div class="field" style="text-align:left"><label>Recovery code</label>
      <textarea class="input" id="ob-restore-words" rows="3" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="twelve words separated by spaces"></textarea></div>
      <div class="err" id="ob-err" style="display:none"></div>
      <button class="btn" id="ob-restore-go">Unlock</button>
      <button class="link-btn" id="ob-back-welcome">← Back</button>
    </div></div>`;
  }
  root.innerHTML = html;
  wireOnboarding();
}

function obError(msg) {
  const e = $('#ob-err');
  if (e) { e.textContent = msg; e.style.display = 'block'; }
}

function wireOnboarding() {
  const c = ob.step;
  if (c === 'welcome') {
    $('#ob-create').onclick = () => {
      ob.mnemonic = generateMnemonic();
      ob.confirmIdx = [...Array(12).keys()].sort(() => Math.random() - 0.5).slice(0, 3).sort((a, b) => a - b);
      ob.step = 'show-words';
      drawOnboarding();
    };
    $('#ob-restore').onclick = () => { ob.step = 'restore'; drawOnboarding(); };
  } else if (c === 'show-words') {
    const cb = $('#ob-written'), btn = $('#ob-words-next');
    cb.onchange = () => { btn.disabled = !cb.checked; };
    btn.onclick = () => { ob.step = 'confirm-words'; drawOnboarding(); };
  } else if (c === 'confirm-words') {
    $('#ob-back-words').onclick = () => { ob.step = 'show-words'; drawOnboarding(); };
    $('#ob-confirm-next').onclick = () => {
      const words = ob.mnemonic.split(' ');
      for (const i of ob.confirmIdx) {
        if (($('#cw-' + i).value || '').trim().toLowerCase() !== words[i]) {
          obError('That doesn\'t match word #' + (i + 1) + '. Check your written copy.');
          return;
        }
      }
      ob.step = 'device-pw';
      drawOnboarding();
    };
  } else if (c === 'device-pw') {
    $('#ob-pw-show').onclick = () => {
      $('#pw-form').style.display = 'block';
      $('#ob-pw-set').style.display = 'block';
      $('#ob-pw-show').style.display = 'none';
    };
    $('#ob-skip-pw').onclick = () => finishOnboarding(null);
    $('#ob-pw-set').onclick = () => {
      const p1 = $('#ob-pw1').value, p2 = $('#ob-pw2').value;
      if (p1.length < 8) { obError('Use at least 8 characters.'); return; }
      if (p1 !== p2) { obError('Passwords don\'t match.'); return; }
      finishOnboarding(p1);
    };
  } else if (c === 'restore') {
    $('#ob-back-welcome').onclick = () => { ob.step = 'welcome'; drawOnboarding(); };
    $('#ob-restore-go').onclick = async () => {
      const words = $('#ob-restore-words').value;
      if (!validateMnemonic(words)) { obError('That doesn\'t look like a valid 12-word code. Check each word.'); return; }
      ob.mnemonic = words.toLowerCase().trim().split(/\s+/).join(' ');
      ob.step = 'working'; ob.workingText = 'Unlocking…'; ob.workingSub = 'Deriving keys and decrypting your vault.';
      drawOnboarding();
      await new Promise(r => setTimeout(r, 60));
      try {
        const seed = mnemonicToSeed(ob.mnemonic);
        const { dataKey, ownerId } = deriveKeys(seed);
        const meta = await apiGet('/api/vault');
        if (!meta.exists) { ob.step = 'welcome'; drawOnboarding(); toast('No vault on this server — creating a new one'); return; }
        const pt = openVault(dataKey, meta.iv, meta.ciphertext);
        session = { seed, dataKey, ownerId };
        vault = decodeVaultState(pt);
        serverVersion = meta.version;
        const keepMnemonic = ob.mnemonic;
        ob = { step: 'device-pw', mnemonic: keepMnemonic, restoreMode: true };
        drawOnboarding();
      } catch (e) {
        console.error(e);
        ob.step = 'restore'; drawOnboarding();
        obError('Couldn\'t decrypt the vault with that code. Double-check your words.');
      }
    };
  }
}

async function finishOnboarding(devicePassword) {
  ob.step = 'working';
  ob.workingText = devicePassword ? 'Sealing your vault…' : 'Creating your vault…';
  drawOnboarding();
  await new Promise(r => setTimeout(r, 60));
  try {
    const seed = ob.restoreMode ? session.seed : mnemonicToSeed(ob.mnemonic);
    const { dataKey, ownerId } = ob.restoreMode ? { dataKey: session.dataKey, ownerId: session.ownerId } : deriveKeys(seed);
    if (!ob.restoreMode) {
      vault = newVaultState();
      const s = sealVault(dataKey, encodeVaultState(vault));
      const r = await apiPut('/api/vault', { iv: s.nonceB64, ciphertext: s.ctB64, base_version: 0 });
      if (!r.ok) throw new Error('server rejected vault creation (status ' + r.status + ')');
      serverVersion = r.version;
      session = { seed, dataKey, ownerId };
    }
    if (devicePassword) {
      ob.workingSub = 'Sealing your recovery code with Argon2id — a few seconds…';
      drawOnboarding();
      await new Promise(r => setTimeout(r, 60));
      const seal = createDeviceSeal(devicePassword, session.seed, () => {});
      localStorage.setItem(SEAL_KEY, seal);
    }
    const words = ob.mnemonic; // don't keep after this
    ob = null;
    armLock();
    renderApp();
    toast(devicePassword ? 'Vault ready — quick unlock enabled' : 'Vault ready');
  } catch (e) {
    console.error(e);
    toast('Something went wrong: ' + e.message);
    ob.step = 'welcome';
    drawOnboarding();
  }
}

/* ==================================================================
   UNLOCK
   ================================================================== */

let unlockMode = 'auto'; // 'auto' | 'password' | 'code'

function renderUnlock(reason) {
  unlockMode = 'auto';
  const hasSeal = !!localStorage.getItem(SEAL_KEY);
  const err = reason ? `<div class="err">${esc(reason)}</div>` : '';
  root.innerHTML = `
  <div class="screen fadein"><div class="glass-deep onboard-card">
    <div class="hero-mark">${ICONS.mark}</div>
    <div class="hero-title">Stack</div>
    <div class="sub" style="margin-bottom:20px">Your vault is encrypted.<br>Unlock to continue.</div>
    ${err}
    <div id="unlock-body"></div>
  </div></div>`;
  drawUnlockBody(hasSeal);
}

function drawUnlockBody(hasSeal) {
  const body = $('#unlock-body');
  const mode = unlockMode === 'auto' ? (hasSeal ? 'password' : 'code') : unlockMode;
  if (mode === 'password') {
    body.innerHTML = `
      <div class="field" style="text-align:left"><label>Device password</label>
      <input class="input" type="password" id="ul-pw" autocomplete="current-password" placeholder="Your device password"></div>
      <div class="err" id="ul-err" style="display:none"></div>
      <button class="btn" id="ul-go">Unlock</button>
      <button class="link-btn" id="ul-switch">Use recovery code instead</button>`;
    $('#ul-switch').onclick = () => { unlockMode = 'code'; drawUnlockBody(hasSeal); };
    const go = async () => {
      const pw = $('#ul-pw').value;
      const errEl = $('#ul-err');
      errEl.style.display = 'none';
      const btn = $('#ul-go'); btn.disabled = true; btn.textContent = 'Deriving key…';
      await new Promise(r => setTimeout(r, 60));
      try {
        const seed = openDeviceSeal(pw, localStorage.getItem(SEAL_KEY), () => {});
        await unlockWithSeed(seed);
      } catch (e) {
        console.error(e);
        btn.disabled = false; btn.textContent = 'Unlock';
        errEl.textContent = 'Wrong password — the seal wouldn\'t open.';
        errEl.style.display = 'block';
      }
    };
    $('#ul-go').onclick = go;
    $('#ul-pw').onkeydown = e => { if (e.key === 'Enter') go(); };
    setTimeout(() => $('#ul-pw').focus(), 100);
  } else {
    body.innerHTML = `
      <div class="field" style="text-align:left"><label>12-word recovery code</label>
      <textarea class="input" id="ul-words" rows="3" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="twelve words separated by spaces"></textarea></div>
      <div class="err" id="ul-err" style="display:none"></div>
      <button class="btn" id="ul-go">Unlock</button>
      ${hasSeal ? '<button class="link-btn" id="ul-switch">Use device password instead</button>' : ''}`;
    if (hasSeal) $('#ul-switch').onclick = () => { unlockMode = 'password'; drawUnlockBody(hasSeal); };
    const go = async () => {
      const words = $('#ul-words').value;
      const errEl = $('#ul-err');
      if (!validateMnemonic(words)) {
        errEl.textContent = 'That doesn\'t look like a valid 12-word code.';
        errEl.style.display = 'block';
        return;
      }
      errEl.style.display = 'none';
      const btn = $('#ul-go'); btn.disabled = true; btn.textContent = 'Decrypting…';
      await new Promise(r => setTimeout(r, 60));
      try {
        const seed = mnemonicToSeed(words);
        await unlockWithSeed(seed);
      } catch (e) {
        console.error(e);
        btn.disabled = false; btn.textContent = 'Unlock';
        errEl.textContent = 'Wrong code — the vault wouldn\'t decrypt.';
        errEl.style.display = 'block';
      }
    };
    $('#ul-go').onclick = go;
  }
}

async function unlockWithSeed(seed) {
  const { dataKey, ownerId } = deriveKeys(seed);
  const meta = await apiGet('/api/vault');
  if (!meta.exists) throw new Error('vault vanished from server');
  const pt = openVault(dataKey, meta.iv, meta.ciphertext); // throws if wrong code
  session = { seed, dataKey, ownerId };
  vault = decodeVaultState(pt);
  serverVersion = meta.version;
  viewDate = localDate();
  armLock();
  renderApp();
}

/* ==================================================================
   APP SHELL
   ================================================================== */

function renderApp() {
  const now = new Date();
  calYear = now.getFullYear(); calMonth = now.getMonth();
  calSelected = null;
  root.innerHTML = `
  <header class="app-header">
    <div class="brand">
      <div class="brand-mark">${ICONS.mark}</div>
      <div><div class="brand-name">Stack</div><div class="brand-tag"><span id="syncdot" class="sync-dot"></span> encrypted</div></div>
    </div>
    <div style="display:flex;gap:10px">
      <button class="icon-btn" id="btn-theme" title="Toggle theme">${document.documentElement.dataset.theme === 'dark' ? ICONS.moon : ICONS.sun}</button>
      <button class="icon-btn" id="btn-lock" title="Lock now">${ICONS.lock}</button>
    </div>
  </header>
  <div id="view" class="fadein"></div>
  <nav class="tabbar">
    <button class="tab" data-tab="today">${ICONS.today}<span>Today</span></button>
    <button class="tab" data-tab="calendar">${ICONS.cal}<span>Calendar</span></button>
    <button class="tab" data-tab="history">${ICONS.hist}<span>History</span></button>
    <button class="tab" data-tab="manage">${ICONS.gear}<span>Manage</span></button>
  </nav>`;
  $('#btn-theme').onclick = () => { toggleTheme(); renderApp(); };
  $('#btn-lock').onclick = () => lock();
  document.querySelectorAll('.tab').forEach(b => {
    b.onclick = () => { tab = b.dataset.tab; renderTab(); };
  });
  renderTab();
  startReminders();
  startSyncPoll();
}

function renderTab() {
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  const v = $('#view');
  try {
    if (tab === 'today') v.innerHTML = viewToday();
    else if (tab === 'calendar') v.innerHTML = viewCalendar();
    else if (tab === 'history') v.innerHTML = viewHistory();
    else v.innerHTML = viewManage();
  } catch (e) {
    console.error('renderTab failed for tab', tab, e);
    v.innerHTML = `<div class="glass empty-day"><div class="big-emoji">${ICONS.warn}</div>
      <div style="font-weight:800;font-size:17px;margin-bottom:6px">Something went wrong</div>
      <div class="sub">Please reload the page. If it persists, lock and unlock your vault.</div></div>`;
  }
  try { wireTab(); } catch (e) { console.error('wireTab failed for tab', tab, e); }
}

/* ---------------- TODAY (dashboard) ---------------- */

function streaksWidget() {
  const rows = vault.supplements
    .filter(s => !s.archived)
    .map(s => ({ s, ...streaks(suppDates(s.id)) }))
    .filter(r => r.current > 0)
    .sort((a, b) => b.current - a.current)
    .slice(0, 3);
  if (!rows.length) return '<h3>Streaks</h3><div class="sub">Log supplements to start a streak.</div>';
  return '<h3>Streaks</h3>' + rows.map(r => `
    <div class="streak-row">
      <span class="badge hot">${ICONS.flame} ${r.current}d</span>
      <div class="grow"><div class="t">${esc(r.s.name)}</div><div class="s">best ${r.longest}d</div></div>
    </div>`).join('') +
    '<button class="link-btn" id="w-go-history" style="padding:8px 0 0">View all history →</button>';
}

function statsWidget() {
  const active = vault.supplements.filter(s => !s.archived).length;
  const groups = vault.groups.length;
  const allDates = new Set();
  for (const id in vault.logs) for (const dt of vault.logs[id]) allDates.add(dt);
  return `<h3>At a glance</h3>
    <div class="stat-grid">
      <div class="hist-stat"><div class="n">${active}</div><div class="l">supplements</div></div>
      <div class="hist-stat"><div class="n">${groups}</div><div class="l">groups</div></div>
      <div class="hist-stat"><div class="n">${allDates.size}</div><div class="l">days logged</div></div>
    </div>`;
}

function viewToday() {
  viewDate = localDate(); // home is always today — no day navigation
  const d = viewDate;
  const { taken, total } = dayStats(d);
  const pct = total ? Math.round((taken / total) * 100) : 0;
  const R = 34, CIRC = 2 * Math.PI * R;
  let groupsHtml = '';
  for (const g of sortedGroups()) {
    const items = groupSupps(g.id, d);
    if (!items.length) continue;
    const done = items.filter(s => isTaken(s.id, d)).length;
    groupsHtml += `
    <div class="glass group-card">
      <div class="group-head">
        <div class="group-name">${esc(g.name)} <span class="group-count">${done}/${items.length}</span></div>
        ${done < items.length ? `<button class="log-all" data-logall="${g.id}">Log all</button>` : ''}
      </div>
      ${items.map(s => `
        <div class="supp-row ${isTaken(s.id, d) ? 'taken' : ''}" data-toggle="${s.id}">
          <div class="check">${ICONS.check}</div>
          <div class="supp-info">
            <div class="supp-name">${esc(s.name)}</div>
            ${s.dose || s.brand ? `<div class="supp-sub">${esc([s.dose, s.brand].filter(Boolean).join(' · '))}</div>` : ''}
          </div>
        </div>`).join('')}
    </div>`;
  }
  if (!groupsHtml) {
    groupsHtml = `<div class="glass empty-day"><div class="big-emoji">${ICONS.pill}</div>
      <div style="font-weight:800;font-size:17px;margin-bottom:6px">Nothing scheduled</div>
      <div class="sub">Add supplements in the Manage tab to start tracking.</div></div>`;
  }
  return `
  <div class="dash-head">
    <div>
      <div class="dash-title">Today</div>
      <div class="sub">${esc(fmtDate(d))}</div>
    </div>
  </div>
  <div class="dash-grid">
    <div class="dash-main">${groupsHtml}</div>
    <aside class="dash-side">
      <div class="glass progress-card widget w-order-progress">
        <div class="ring">
          <svg width="84" height="84"><circle cx="42" cy="42" r="${R}" stroke="rgba(127,127,160,0.25)" stroke-width="9" fill="none"/>
          <circle cx="42" cy="42" r="${R}" stroke="url(#grad)" stroke-width="9" fill="none" stroke-linecap="round"
            stroke-dasharray="${CIRC}" stroke-dashoffset="${CIRC * (1 - pct / 100)}" style="transition:stroke-dashoffset .6s ease"/>
          <defs><linearGradient id="grad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#a78bfa"/><stop offset="100%" stop-color="#6366f1"/></linearGradient></defs></svg>
          <div class="pct">${pct}%</div>
        </div>
        <div class="progress-meta">
          <div class="big">${taken} of ${total} taken</div>
          <div class="sub2">${total === 0 ? 'Add supplements to get started' : pct === 100 ? 'All done. Streak protected.' : 'Tap a supplement to log it'}</div>
        </div>
      </div>
      <div class="glass widget w-order-later">${streaksWidget()}</div>
      <div class="glass widget w-order-later">${statsWidget()}</div>
    </aside>
  </div>`;
}

/* ---------------- CALENDAR ---------------- */

const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

function viewCalendar() {
  const first = new Date(calYear, calMonth, 1);
  const startPad = first.getDay();
  const daysInMonth = new Date(calYear, calMonth + 1, 0).getDate();
  const today = localDate();
  let cells = '';
  for (let i = 0; i < startPad; i++) cells += '<div class="cal-day pad"></div>';
  for (let d = 1; d <= daysInMonth; d++) {
    const ds = `${calYear}-${String(calMonth + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const { taken, total } = dayStats(ds);
    let cls = 'none';
    if (total > 0) cls = taken === total ? 'full' : taken > 0 ? 'partial' : 'none';
    if (ds === today) cls += ' today';
    if (ds > today) cls += ' future';
    if (ds === calSelected) cls += ' selected';
    cells += `<div class="cal-day ${cls}" data-day="${ds}">${d}</div>`;
  }
  let detail = '';
  if (calSelected) {
    const { taken, total } = dayStats(calSelected);
    const items = vault.supplements
      .filter(s => activeOn(s, calSelected))
      .sort((a, b) => a.name.localeCompare(b.name));
    detail = `
    <div class="glass day-detail">
      <h3>${esc(fmtDate(calSelected))} — ${taken}/${total} taken</h3>
      ${items.map(s => {
        const t = isTaken(s.id, calSelected);
        return `<div class="day-detail-item"><span class="dot ${t ? 'yes' : 'no'}"></span>
          <div><div style="font-weight:700">${esc(s.name)}</div>
          ${s.dose ? `<div class="tiny">${esc(s.dose)}</div>` : ''}</div></div>`;
      }).join('') || '<div class="sub">Nothing scheduled that day.</div>'}
    </div>`;
  }
  return `
  <div class="cal-head">
    <button class="icon-btn" id="cal-prev">‹</button>
    <div class="cal-title">${MONTHS[calMonth]} ${calYear}</div>
    <button class="icon-btn" id="cal-next">›</button>
  </div>
  <div class="glass cal-grid">
    ${['S','M','T','W','T','F','S'].map(d => `<div class="cal-dow">${d}</div>`).join('')}
    ${cells}
  </div>
  <div style="display:flex;gap:14px;justify-content:center;margin:14px 0 4px" class="tiny">
    <span><span class="dot yes" style="display:inline-block"></span> all taken</span>
    <span><span class="dot" style="display:inline-block;background:var(--warn)"></span> partial</span>
    <span><span class="dot no" style="display:inline-block"></span> missed</span>
  </div>
  ${detail}`;
}

/* ---------------- HISTORY ---------------- */

function viewHistory() {
  const supps = [...vault.supplements].sort((a, b) => (b.archived ? 0 : 1) - (a.archived ? 0 : 1) || a.name.localeCompare(b.name));
  if (!supps.length) {
    return `<div class="glass empty-day"><div class="big-emoji">${ICONS.hist}</div>
      <div style="font-weight:800;font-size:17px;margin-bottom:6px">No history yet</div>
      <div class="sub">Log some supplements and your streaks will show up here.</div></div>`;
  }
  return `<div class="hist-list">` + supps.map(s => {
    const dates = suppDates(s.id);
    const { current, longest } = streaks(dates);
    const g = vault.groups.find(g => g.id === s.groupId);
    return `
    <div class="glass hist-card">
      <div class="hist-top">
        <div><div class="hist-name">${esc(s.name)}</div>
        <div class="hist-sub">${esc([s.dose, s.brand, g ? g.name : ''].filter(Boolean).join(' · '))}</div></div>
        ${s.archived
          ? '<span class="badge archived">archived</span>'
          : current >= 7 ? '<span class="badge hot">${ICONS.flame} on fire</span>' : ''}
      </div>
      <div class="hist-stats">
        <div class="hist-stat"><div class="n">${dates.length}</div><div class="l">days taken</div></div>
        <div class="hist-stat"><div class="n">${current}</div><div class="l">day streak</div></div>
        <div class="hist-stat"><div class="n">${longest}</div><div class="l">best streak</div></div>
      </div>
      <div class="tiny" style="margin-top:10px">First logged ${dates.length ? esc(dates[0]) : '— never logged —'}</div>
    </div>`;
  }).join('') + '</div>';
}

/* ---------------- MANAGE ---------------- */

function viewManage() {
  const supps = vault.supplements.filter(s => !s.archived).sort((a, b) => a.name.localeCompare(b.name));
  const archived = vault.supplements.filter(s => s.archived);
  const hasSeal = !!localStorage.getItem(SEAL_KEY);
  return `
  <div class="manage-grid">
  <div class="glass manage-sec">
    <h2>Supplements</h2>
    <div class="sub">${supps.length} active${archived.length ? ` · ${archived.length} archived (kept in history)` : ''}</div>
    ${supps.map(s => {
      const g = vault.groups.find(g => g.id === s.groupId);
      return `<div class="item-row"><div class="grow"><div class="t">${esc(s.name)}</div>
        <div class="s">${esc([s.dose, s.brand, g ? g.name : ''].filter(Boolean).join(' · '))}</div></div>
        <button class="mini-btn" data-edit-supp="${s.id}">Edit</button>
        <button class="mini-btn danger" data-del-supp="${s.id}">Remove</button></div>`;
    }).join('') || '<div class="sub">None yet.</div>'}
    <button class="btn" id="add-supp" style="margin-top:14px">+ Add supplement</button>
  </div>

  <div class="glass manage-sec">
    <h2>Groups</h2>
    <div class="sub">Default: Morning, Afternoon, Evening. Add as many custom groups as you want.</div>
    ${sortedGroups().map(g => {
      const n = vault.supplements.filter(s => s.groupId === g.id && !s.archived).length;
      return `<div class="item-row"><div class="grow"><div class="t">${esc(g.name)}</div>
        <div class="s">${n} supplement${n === 1 ? '' : 's'}${g.reminder ? ` · <span class="inline-ico">${ICONS.clock}</span> ${esc(g.reminder)}` : ''}</div></div>
        <button class="mini-btn" data-edit-group="${g.id}">Edit</button>
        <button class="mini-btn danger" data-del-group="${g.id}">Delete</button></div>`;
    }).join('')}
    <button class="btn btn-ghost" id="add-group" style="margin-top:14px">+ Add group</button>
  </div>

  <div class="glass manage-sec">
    <h2>Security</h2>
    <div class="sub">Your vault ID — derived from your recovery code. The account <b>is</b> the phrase.</div>
    <div class="vault-id">${esc(session.ownerId)}</div>
    <div class="item-row" style="margin-top:8px"><div class="grow"><div class="t">Device password</div>
      <div class="s">${hasSeal ? 'Enabled on this browser' : 'Not set — you use your 12 words each time'}</div></div></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:6px">
      ${hasSeal
        ? '<button class="mini-btn" id="sec-change-pw">Change password</button><button class="mini-btn danger" id="sec-remove-pw">Remove password</button>'
        : '<button class="mini-btn" id="sec-set-pw">Set device password</button>'}
      <button class="mini-btn" id="sec-lock">Lock now</button>
    </div>
  </div>

  <div class="glass manage-sec">
    <h2>Notifications</h2>
    <div class="sub">Get a reminder when a group's time hits (works while this page is open).</div>
    <div class="item-row"><div class="grow"><div class="t">Browser notifications</div>
      <div class="s">${notifStatus()}</div></div>
      ${notifCanAsk()
        ? '<button class="mini-btn" id="notif-enable">Enable</button>' : ''}
    </div>
  </div>

  <div class="tiny" style="text-align:center;margin:18px 0 6px;grid-column:1/-1">Stack v1 · vault v${vault.v} · server rev ${serverVersion}<br>Keys live in memory only. Locking wipes them.</div>
  </div>`;
}

/* ---------------- tab wiring ---------------- */

function on(id, fn) {
  const el = document.getElementById(id);
  if (el) el.onclick = fn;
  return el;
}

function wireTab() {
  if (tab === 'today') {
    document.querySelectorAll('[data-toggle]').forEach(el => {
      el.onclick = () => commit(mToggle(el.dataset.toggle, viewDate));
    });
    on('w-go-history', () => { tab = 'history'; renderTab(); });
    document.querySelectorAll('[data-logall]').forEach(el => {
      el.onclick = e => { e.stopPropagation(); commit(mLogAll(el.dataset.logall, viewDate)); toast('Logged'); };
    });
  } else if (tab === 'calendar') {
    on('cal-prev', () => {
      calMonth--; if (calMonth < 0) { calMonth = 11; calYear--; }
      renderTab();
    });
    on('cal-next', () => {
      calMonth++; if (calMonth > 11) { calMonth = 0; calYear++; }
      renderTab();
    });
    document.querySelectorAll('[data-day]').forEach(el => {
      el.onclick = () => {
        calSelected = calSelected === el.dataset.day ? null : el.dataset.day;
        renderTab();
      };
    });
  } else if (tab === 'manage') {
    on('add-supp', () => suppModal(null));
    on('add-group', () => groupModal(null));
    document.querySelectorAll('[data-edit-supp]').forEach(b => b.onclick = () => suppModal(b.dataset.editSupp));
    document.querySelectorAll('[data-del-supp]').forEach(b => b.onclick = () => {
      const s = vault.supplements.find(x => x.id === b.dataset.delSupp);
      confirmModal(`Remove <b>${esc(s.name)}</b>?`, 'It stays in your history, but won\'t show in daily logging anymore.',
        'Remove', () => commit(mArchiveSupp(s.id, localDate())));
    });
    document.querySelectorAll('[data-edit-group]').forEach(b => b.onclick = () => groupModal(b.dataset.editGroup));
    document.querySelectorAll('[data-del-group]').forEach(b => b.onclick = () => deleteGroupFlow(b.dataset.delGroup));
    const se = document.getElementById('sec-set-pw'); if (se) se.onclick = () => devicePwModal('set');
    const ch = document.getElementById('sec-change-pw'); if (ch) ch.onclick = () => reauthModal(pw => devicePwModal('change', pw));
    const rm = document.getElementById('sec-remove-pw'); if (rm) rm.onclick = () => reauthModal(() => {
      confirmModal('Remove device password?', 'You\'ll use your 12-word code to unlock on this browser from now on.', 'Remove', () => {
        localStorage.removeItem(SEAL_KEY); renderTab(); toast('Device password removed');
      });
    });
    on('sec-lock', () => lock());
    const ne = document.getElementById('notif-enable'); if (ne) ne.onclick = async () => {
      await Notification.requestPermission(); renderTab();
    };
  }
}

/* ---------------- modals ---------------- */

function openModal(html) {
  closeModal();
  const w = document.createElement('div');
  w.className = 'modal-wrap'; w.id = 'modal-wrap';
  w.innerHTML = `<div class="glass-deep modal">${html}</div>`;
  w.onclick = e => { if (e.target === w) closeModal(); };
  document.body.appendChild(w);
}
function closeModal() { const w = $('#modal-wrap'); if (w) w.remove(); }

function confirmModal(title, body, okLabel, onOk) {
  openModal(`<h2>${title}</h2><div class="sub" style="margin-bottom:18px">${body}</div>
    <button class="btn btn-danger" id="cf-ok">${esc(okLabel)}</button>
    <button class="btn btn-ghost" id="cf-cancel" style="margin-top:10px">Cancel</button>`);
  $('#cf-ok').onclick = () => { closeModal(); onOk(); };
  $('#cf-cancel').onclick = closeModal;
}

function groupOptions(selected) {
  return sortedGroups().map(g => `<option value="${g.id}" ${g.id === selected ? 'selected' : ''}>${esc(g.name)}</option>`).join('');
}

function suppModal(sid) {
  const s = sid ? vault.supplements.find(x => x.id === sid) : null;
  const defGroup = sortedGroups()[0];
  openModal(`
    <h2>${s ? 'Edit supplement' : 'Add supplement'}</h2>
    <div class="field"><label>Name *</label><input class="input" id="f-name" value="${esc(s?.name || '')}" placeholder="Vitamin D3"></div>
    <div class="row2">
      <div class="field"><label>Dose</label><input class="input" id="f-dose" value="${esc(s?.dose || '')}" placeholder="2000 IU"></div>
      <div class="field"><label>Brand</label><input class="input" id="f-brand" value="${esc(s?.brand || '')}" placeholder="Optional"></div>
    </div>
    <div class="field"><label>Group</label><select class="select" id="f-group">${groupOptions(s?.groupId || defGroup?.id)}</select></div>
    <div class="field"><label>Notes</label><textarea class="input" id="f-notes" placeholder="Optional">${esc(s?.notes || '')}</textarea></div>
    <div class="err" id="f-err" style="display:none"></div>
    <button class="btn" id="f-save">${s ? 'Save' : 'Add'}</button>
    <button class="btn btn-ghost" id="f-cancel" style="margin-top:10px">Cancel</button>`);
  $('#f-cancel').onclick = closeModal;
  $('#f-save').onclick = () => {
    const name = $('#f-name').value.trim();
    if (!name) { const e = $('#f-err'); e.textContent = 'Name is required.'; e.style.display = 'block'; return; }
    const patch = {
      name,
      dose: $('#f-dose').value.trim(),
      brand: $('#f-brand').value.trim(),
      notes: $('#f-notes').value.trim(),
      groupId: $('#f-group').value,
    };
    closeModal();
    if (s) commit(mEditSupp(sid, patch));
    else commit(mAddSupp({ id: randomId(), created: localDate(), archived: null, ...patch }));
    toast(s ? 'Saved' : 'Added');
  };
}

function groupModal(gid) {
  const g = gid ? vault.groups.find(x => x.id === gid) : null;
  openModal(`
    <h2>${g ? 'Edit group' : 'New group'}</h2>
    <div class="field"><label>Name *</label><input class="input" id="g-name" value="${esc(g?.name || '')}" placeholder="Pre-workout"></div>
    <div class="field"><label>Daily reminder (optional)</label>
      <div class="reminder-input"><input class="input" type="time" id="g-rem" value="${esc(g?.reminder || '')}">
      ${g?.reminder ? '<button class="mini-btn" id="g-rem-clear">Clear</button>' : ''}</div>
      <div class="tiny" style="margin-top:6px">Notifies you while this page is open.</div></div>
    <div class="err" id="g-err" style="display:none"></div>
    <button class="btn" id="g-save">${g ? 'Save' : 'Create group'}</button>
    <button class="btn btn-ghost" id="g-cancel" style="margin-top:10px">Cancel</button>`);
  $('#g-cancel').onclick = closeModal;
  const rc = $('#g-rem-clear');
  if (rc) rc.onclick = () => { $('#g-rem').value = ''; };
  $('#g-save').onclick = () => {
    const name = $('#g-name').value.trim();
    if (!name) { const e = $('#g-err'); e.textContent = 'Name is required.'; e.style.display = 'block'; return; }
    const reminder = $('#g-rem').value || null;
    closeModal();
    if (g) commit(mEditGroup(gid, { name, reminder }));
    else commit(mAddGroup({ id: randomId(), name, reminder }));
    toast(g ? 'Saved' : 'Group created');
  };
}

function deleteGroupFlow(gid) {
  const g = vault.groups.find(x => x.id === gid);
  const n = vault.supplements.filter(s => s.groupId === gid && !s.archived).length;
  if (vault.groups.length <= 1) { toast('You need at least one group'); return; }
  if (n > 0) {
    const others = sortedGroups().filter(x => x.id !== gid);
    openModal(`<h2>Delete "${esc(g.name)}"?</h2>
      <div class="sub" style="margin-bottom:14px">It has ${n} supplement${n === 1 ? '' : 's'}. Move them to:</div>
      <div class="field"><select class="select" id="dg-move">${others.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join('')}</select></div>
      <button class="btn btn-danger" id="dg-ok">Move & delete</button>
      <button class="btn btn-ghost" id="dg-cancel" style="margin-top:10px">Cancel</button>`);
    $('#dg-cancel').onclick = closeModal;
    $('#dg-ok').onclick = () => { const t = $('#dg-move').value; closeModal(); commit(mDeleteGroup(gid, t)); toast('Group deleted'); };
  } else {
    confirmModal(`Delete "${esc(g.name)}"?`, 'This can\'t be undone.', 'Delete', () => { commit(mDeleteGroup(gid, null)); toast('Group deleted'); });
  }
}

/* re-auth with 12 words before sensitive security changes */
function reauthModal(onOk) {
  openModal(`<h2>Confirm it's you</h2>
    <div class="sub" style="margin-bottom:14px">Enter your 12-word recovery code to continue.</div>
    <div class="field"><textarea class="input" id="ra-words" rows="3" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="twelve words"></textarea></div>
    <div class="err" id="ra-err" style="display:none"></div>
    <button class="btn" id="ra-ok">Confirm</button>
    <button class="btn btn-ghost" id="ra-cancel" style="margin-top:10px">Cancel</button>`);
  $('#ra-cancel').onclick = closeModal;
  $('#ra-ok').onclick = async () => {
    const w = $('#ra-words').value;
    if (!validateMnemonic(w)) { const e = $('#ra-err'); e.textContent = 'Invalid 12-word code.'; e.style.display = 'block'; return; }
    const { ownerId } = deriveKeys(mnemonicToSeed(w));
    if (ownerId !== session.ownerId) { const e = $('#ra-err'); e.textContent = 'That code doesn\'t match this vault.'; e.style.display = 'block'; return; }
    closeModal();
    onOk();
  };
}

function devicePwModal(mode) {
  openModal(`<h2>${mode === 'set' ? 'Set' : 'Change'} device password</h2>
    <div class="warning-box blue" style="margin-top:0"><b>Remember:</b> this password only unlocks <b>this browser</b>.
    If someone steals this device they can try to brute-force it offline — make it strong.</div>
    <div class="field"><label>New password (min 8 chars)</label><input class="input" type="password" id="dp-1" autocomplete="new-password"></div>
    <div class="field"><label>Confirm</label><input class="input" type="password" id="dp-2" autocomplete="new-password"></div>
    <div class="err" id="dp-err" style="display:none"></div>
    <button class="btn" id="dp-ok">Save</button>
    <button class="btn btn-ghost" id="dp-cancel" style="margin-top:10px">Cancel</button>`);
  $('#dp-cancel').onclick = closeModal;
  $('#dp-ok').onclick = async () => {
    const p1 = $('#dp-1').value, p2 = $('#dp-2').value;
    const err = m => { const e = $('#dp-err'); e.textContent = m; e.style.display = 'block'; };
    if (p1.length < 8) return err('Use at least 8 characters.');
    if (p1 !== p2) return err('Passwords don\'t match.');
    $('#dp-ok').disabled = true; $('#dp-ok').textContent = 'Sealing… (a few seconds)';
    await new Promise(r => setTimeout(r, 60));
    try {
      localStorage.setItem(SEAL_KEY, createDeviceSeal(p1, session.seed, () => {}));
      closeModal(); renderTab(); toast('Device password ' + (mode === 'set' ? 'enabled' : 'changed'));
    } catch (e) { err('Failed: ' + e.message); $('#dp-ok').disabled = false; $('#dp-ok').textContent = 'Save'; }
  };
}

/* ---------------- reminders ---------------- */

let reminderTimer = null;
function startReminders() {
  if (reminderTimer) clearInterval(reminderTimer);
  const check = () => {
    if (!session || notifPerm() !== 'granted') return;
    const now = new Date();
    const hm = String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
    const today = localDate();
    for (const g of vault.groups) {
      if (g.reminder === hm && notified[g.id] !== today) {
        notified[g.id] = today;
        const pending = groupSupps(g.id, today).filter(s => !isTaken(s.id, today)).length;
        try {
          new Notification(`${g.name} stack`, {
            body: pending ? `${pending} supplement${pending === 1 ? '' : 's'} waiting in Stack` : 'All logged — nice work',
          });
        } catch (e) { /* ignore */ }
      }
    }
  };
  reminderTimer = setInterval(check, 30000);
  check();
}

/* ---------------- background sync poll ---------------- */

let pollTimer = null;
function startSyncPoll() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (!session || syncBusy) return;
    try {
      const meta = await apiGet('/api/vault');
      if (meta.exists && meta.version > serverVersion) {
        const pt = openVault(session.dataKey, meta.iv, meta.ciphertext);
        vault = decodeVaultState(pt);
        serverVersion = meta.version;
        renderTab();
        toast('Synced from another device');
      }
    } catch (e) { /* offline or locked; ignore */ }
  }, 60000);
}

/* ---------------- boot ---------------- */

applyTheme();
(async function boot() {
  try {
    const meta = await apiGet('/api/vault');
    if (meta.exists) renderUnlock();
    else renderOnboarding();
  } catch (e) {
    root.innerHTML = `<div class="screen"><div class="glass-deep onboard-card">
      <h1>Can't reach the server</h1><div class="sub" style="margin:12px 0 20px">Is the Stack container running?</div>
      <button class="btn" onclick="location.reload()">Retry</button></div></div>`;
  }
})();
