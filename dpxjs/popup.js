/* DPXJS v1 - Author: 0xdexblood - https://github.com/0xdexblood */
'use strict';

const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const CRANK = { High: 2, Medium: 1, Low: 0 };
const PAGE = 150; // rows rendered per batch, keeps big result sets snappy
const DEFAULT_MODEL = 'deepseek/deepseek-v4.1-flash';
const DEFAULTS = { token: '', model: DEFAULT_MODEL, autoScan: false, showCandidates: false };
const INFO_CATS = ['Client-side Info', 'Library', 'Public Identifier'];

const state = {
  tab: null, pageUrl: '', key: '', data: null, view: 'findings', sev: new Set(SEVS), q: '',
  hideLow: false, sort: 'severity', limit: PAGE, candLimit: 100, scope: 'all', collapsed: new Set(),
  cfg: Object.assign({}, DEFAULTS), ai: new Map(), hidden: new Set(), openDetails: new Set(), inTab: false, scanning: false
};

const $ = s => document.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isHttp = u => /^https?:/i.test(u || '');
const realUrl = u => String(u || '').replace(/^view-source:/i, ''); // view-source:https://x -> https://x
const isScannable = u => isHttp(realUrl(u));
const stripHash = u => { try { const x = new URL(u); x.hash = ''; return x.href; } catch (e) { return u || ''; } };
const tabOf = c => (c === 'Secret' ? 'secrets' : INFO_CATS.includes(c) ? 'info' : 'findings');

// runtime.sendMessage with retry: the event page may still be waking up
async function send(msg) {
  for (let i = 0; ; i++) {
    try {
      return await browser.runtime.sendMessage(msg);
    } catch (e) {
      if (i < 3 && /Receiving end does not exist/i.test(String((e && e.message) || e))) { await sleep(300); continue; }
      throw e;
    }
  }
}

// short stable hash (cyrb53)
function hash(str) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}
const findingKey = f => hash([f.category, f.file, f.line, f.column, f.snippet].join('|'));
const endpointKey = e => e.url;
const summaryKey = () => 'summary:' + state.pageUrl;

// DOM builder: strings become text nodes, so scanned data is never parsed as HTML
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const k in attrs) {
      const v = attrs[k];
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else n.setAttribute(k, v === true ? '' : v);
    }
  }
  for (const kid of kids) if (kid != null) n.append(kid);
  return n;
}

function button(label, cls, onClick, title) {
  const b = el('button', { class: cls, type: 'button', title }, label);
  b.addEventListener('click', onClick);
  return b;
}

async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const t = el('textarea');
    t.value = text;
    document.body.append(t);
    t.select();
    document.execCommand('copy');
    t.remove();
  }
  if (btn) {
    const old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = old; }, 900);
  }
}

const shortName = f => {
  if (!/^https?:/i.test(f)) return f;
  try { const u = new URL(f); return u.pathname.split('/').filter(Boolean).pop() || u.host; } catch (e) { return f; }
};

// ---------- tiny markdown renderer (DOM only) ----------

function inline(text) {
  const frag = document.createDocumentFragment();
  for (const part of text.split(/(\*\*[^*]+\*\*|`[^`]+`)/)) {
    if (!part) continue;
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) frag.append(el('b', null, part.slice(2, -2)));
    else if (part.startsWith('`') && part.endsWith('`') && part.length > 2) frag.append(el('code', null, part.slice(1, -1)));
    else frag.append(part);
  }
  return frag;
}

function md(text) {
  const root = el('div', { class: 'md' });
  let pre = null, ul = null;
  for (const line of text.split('\n')) {
    if (/^\s*```/.test(line)) {
      if (pre) { root.append(pre); pre = null; } else { pre = el('pre'); ul = null; }
      continue;
    }
    if (pre) { pre.append(line + '\n'); continue; }
    const li = /^\s*(?:[-*]|\d+[.)])\s+(.*)/.exec(line);
    if (li) {
      if (!ul) { ul = el('ul'); root.append(ul); }
      ul.append(el('li', null, inline(li[1])));
      continue;
    }
    ul = null;
    const h = /^#{1,4}\s+(.*)/.exec(line);
    if (h) root.append(el('div', { class: 'h' }, inline(h[1])));
    else if (line.trim()) root.append(el('p', null, inline(line)));
  }
  if (pre) root.append(pre);
  return root;
}

// ---------- AI panels: rendered from storage, so they survive popup close / render() ----------

const aiHosts = new Map(); // key -> { host, make }

function registerAi(key, host, make) {
  aiHosts.set(key, { host, make });
  if (state.ai.has(key)) syncPanel(key);
}

function statusLabel(e) {
  if (e.status === 'queued') return 'Queued...';
  if (e.status === 'running') return 'Answering...';
  if (e.status === 'error') return 'AI error';
  return 'AI answer';
}

function buildPanel(key) {
  const panel = el('div', { class: 'aipanel', 'data-aikey': key });
  const st = el('span', { class: 'st' });
  const bCopy = button('Copy', '', e => { const x = state.ai.get(key); if (x && x.text) copy(x.text.trim(), e.target); });
  const bRetry = button('Retry', '', () => startAi(key));
  const bClear = button('Clear', '', async () => {
    state.ai.delete(key);
    state.hidden.delete(key);
    syncPanel(key);
    try { await send({ type: 'ai-clear', key }); } catch (e) { /* the entry is gone from the view anyway */ }
  });
  panel._ui = { st, bCopy, bRetry };
  panel.append(el('div', { class: 'aitool' }, st, bCopy, bRetry, bClear), el('div', { class: 'aibody' }));
  return panel;
}

function fillPanel(panel, e) {
  const sig = e.status + '|' + (e.text || '').length + '|' + (e.error || '') + '|' + (state.cfg.token ? 1 : 0);
  if (panel.dataset.sig === sig) return;
  panel.dataset.sig = sig;
  const { st, bCopy, bRetry } = panel._ui;
  st.replaceChildren();
  if (e.status === 'running' || e.status === 'queued') st.append(el('span', { class: 'spin' }));
  st.append(statusLabel(e));
  bCopy.disabled = !e.text;
  bRetry.disabled = e.status === 'queued' || e.status === 'running';
  const body = panel.querySelector('.aibody');
  body.replaceChildren();
  if (e.text) body.append(md(e.text)); // old stored chat URLs are just shown as plain text
  else if (e.status === 'queued') body.append('Waiting for a free slot...');
  else if (e.status === 'running') body.append('Waiting for the first words...');
  if (e.error) body.append(el('div', { class: 'err' }, e.error));
  if (!state.cfg.token && !e.text) body.append(el('div', { class: 'hint' }, 'Add your Numes API key in Settings to use AI.'));
}

function syncPanel(key) {
  const h = aiHosts.get(key);
  if (!h || !h.host.isConnected) return;
  const e = state.ai.get(key);
  let panel = h.host.querySelector(':scope > .aipanel');
  if (!e || state.hidden.has(key)) { if (panel) panel.remove(); return; }
  if (!panel) { panel = buildPanel(key); h.host.append(panel); }
  fillPanel(panel, e);
}

async function startAi(key) {
  const h = aiHosts.get(key);
  if (!h) return;
  const req = h.make();
  state.hidden.delete(key);
  state.ai.set(key, { status: 'queued', text: '', error: '', updatedAt: Date.now() });
  syncPanel(key);
  try {
    const r = await send({ type: 'ai-start', key, kind: req.kind, payload: req.payload });
    if (!r || !r.ok) throw new Error((r && r.error) || 'No response from the background script');
  } catch (e) {
    state.ai.set(key, { status: 'error', text: '', error: String((e && e.message) || e), updatedAt: Date.now() });
    syncPanel(key);
  }
}

function aiToggle(key) {
  if (!state.ai.has(key)) { startAi(key); return; }
  if (state.hidden.has(key)) state.hidden.delete(key); else state.hidden.add(key);
  syncPanel(key);
}

async function loadAi() {
  state.ai.clear();
  const { aiIndex } = await browser.storage.local.get('aiIndex');
  const keys = Object.keys(aiIndex || {}).map(k => 'ai:' + k);
  if (!keys.length) return;
  const got = await browser.storage.local.get(keys);
  for (const k of keys) if (got[k]) state.ai.set(k.slice(3), got[k]);
}

const aiOf = key => { const e = state.ai.get(key); return e ? { status: e.status, text: e.text, error: e.error, updatedAt: e.updatedAt } : undefined; };

// ---------- links ----------

function viewerUrl(file, line, col, len) {
  const q = new URLSearchParams({ file, page: state.pageUrl, line: String(line || 1), col: String(col || 1) });
  if (len) q.set('len', String(len));
  return browser.runtime.getURL('viewer.html') + '?' + q.toString();
}
function openViewer(file, line, col, len) { browser.tabs.create({ url: viewerUrl(file, line, col, len) }); }

// http(s) files are real links that open the raw JS; inline scripts / page.html have no URL of their own
function fileNode(file, line, col) {
  const label = shortName(file) + ':' + line + ':' + col;
  if (!isHttp(file)) return el('span', { class: 'loc', title: file }, label);
  const a = el('a', { class: 'loc', href: file, target: '_blank', rel: 'noopener', title: file }, label);
  a.addEventListener('click', e => { e.preventDefault(); browser.tabs.create({ url: file }); });
  return a;
}

function ctxToggle(row, anchorSel, ctx, line) {
  let box = null;
  return button('ctx', 'mini', () => {
    if (box) { box.remove(); box = null; return; }
    box = el('div', { class: 'ctx' });
    ctx.lines.forEach((text, i) => {
      const n = ctx.start + i;
      box.append(el('div', { class: n === line ? 'hit' : '' }, el('span', { class: 'n' }, String(n)), text));
    });
    const anchor = row.querySelector(anchorSel);
    (anchor || row).after(box);
  }, 'Show code context');
}

// ---------- rows ----------

function slim(f) { const o = Object.assign({}, f); delete o.value; return o; }

function findingRow(f, cand) {
  const row = el('div', { class: 'row' + (cand ? ' cand' : '') });
  const key = findingKey(f);
  const copyText = f.category === 'Secret' ? f.value : f.desc + ' @ ' + f.file + ':' + f.line + (f.chain ? '\n' + f.chain : '') + '\n' + f.snippet;
  row.append(el('div', { class: 'rh' },
    el('span', { class: 'sev s' + f.severity }, f.severity),
    el('span', { class: 'desc', title: f.category + ' - ' + f.desc }, f.desc),
    fileNode(f.file, f.line, f.column),
    ctxToggle(row, ':scope > .snip', f.ctx, f.line),
    button('↗', 'mini', () => openViewer(f.file, f.line, f.column, f.len), 'Open in viewer'),
    el('span', { class: 'conf c' + f.confidence }, f.confidence),
    button('Copy', '', e => copy(copyText, e.target)),
    button('AI', 'ai', () => aiToggle(key))));
  if (f.chain) row.append(el('div', { class: 'chain' }, f.chain));
  row.append(el('div', { class: 'snip' }, f.snippet));
  registerAi(key, row, () => ({ kind: 'finding', payload: { item: slim(f), pageUrl: state.pageUrl } }));
  return row;
}

function endpointRow(e) {
  const row = el('div', { class: 'row' });
  const loc = (e.locs && e.locs[0]) || { file: e.files[0], line: e.line || 1, column: 1 };
  const key = endpointKey(e);
  const head = el('div', { class: 'rh' },
    el('span', { class: 'kind' }, e.kind),
    el('span', { class: 'url', title: e.url }, e.url),
    el('span', { class: 'tag' + (e.same ? '' : ' third') }, e.same ? 'same-origin' : 'third-party'),
    fileNode(loc.file, loc.line, loc.column || 1));
  if (e.count > 1) head.append(el('span', { class: 'conf', title: e.files.join('\n') }, '+' + (e.count - 1)));
  if (e.ctx) head.append(ctxToggle(row, ':scope > .rh', e.ctx, loc.line));
  head.append(
    button('↗', 'mini', () => openViewer(loc.file, loc.line, loc.column, loc.len), 'Open in viewer'),
    button('Copy', '', ev => copy(e.url, ev.target)),
    button('AI', 'ai', () => aiToggle(key)));
  row.append(head);
  registerAi(key, row, () => ({ kind: 'endpoint', payload: { item: { url: e.url, kind: e.kind, same: e.same, files: e.files, locs: e.locs, line: e.line }, pageUrl: state.pageUrl } }));
  return row;
}

// ---------- Info tab extras: sources inventory, unverified candidates ----------

function details(id, title, count, build) {
  const d = el('details', { class: 'inv', open: state.openDetails.has(id) });
  d.append(el('summary', null, title + ' ', el('span', null, '(' + count + ')')));
  d.addEventListener('toggle', () => { if (d.open) state.openDetails.add(id); else state.openDetails.delete(id); });
  const body = el('div', { class: 'body' });
  d.append(body);
  build(body);
  return d;
}

function sourcesBlock() {
  const list = state.data.sources || [];
  if (!list.length) return null;
  const total = list.reduce((n, s) => n + s.count, 0);
  return details('sources', 'Sources found - inventory, not findings', list.length + ' kinds, ' + total + ' uses', body => {
    for (const s of list) {
      const links = el('span', { class: 'links' });
      for (const l of s.locs.slice(0, 6)) {
        const a = el('a', { href: viewerUrl(l.file, l.line, l.column, l.len), target: '_blank', title: l.file }, shortName(l.file) + ':' + l.line);
        a.addEventListener('click', ev => { ev.preventDefault(); openViewer(l.file, l.line, l.column, l.len); });
        links.append(a);
      }
      body.append(el('div', { class: 'src' }, el('b', null, s.name), el('em', null, '×' + s.count), links));
    }
  });
}

function candidatesBlock() {
  const q = state.q.toLowerCase();
  const list = (state.data.candidates || []).filter(f => !q || (f.desc + ' ' + f.file + ' ' + f.snippet + ' ' + f.chain).toLowerCase().includes(q));
  if (!list.length) return null;
  return details('cands', 'Unverified candidates - heuristics without proof', list.length, body => {
    for (const f of list.slice(0, state.candLimit)) body.append(findingRow(f, true));
    if (list.length > state.candLimit) body.append(button('Show more (' + (list.length - state.candLimit) + ' left)', 'more', () => { state.candLimit += 200; render(); }));
  });
}

// ---------- filtering / rendering ----------

function visible() {
  const d = state.data;
  if (!d) return [];
  const q = state.q.toLowerCase();
  if (state.view === 'endpoints') {
    return d.endpoints.filter(e =>
      (state.scope === 'all' || (state.scope === 'same') === e.same) && (!q || e.url.toLowerCase().includes(q) || e.kind.includes(q)));
  }
  return d.findings.filter(f =>
    tabOf(f.category) === state.view && state.sev.has(f.severity) && !(state.hideLow && f.confidence === 'Low') &&
    (!q || (f.desc + ' ' + f.category + ' ' + f.file + ' ' + f.snippet + ' ' + f.chain).toLowerCase().includes(q)));
}

function sorter(a, b) {
  if (state.sort === 'file') return a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line;
  return RANK[b.severity] - RANK[a.severity] || CRANK[b.confidence] - CRANK[a.confidence] || a.line - b.line;
}

function renderTabs() {
  const d = state.data, counts = { findings: 0, endpoints: d ? d.endpoints.length : 0, secrets: 0, info: 0 };
  if (d) for (const f of d.findings) counts[tabOf(f.category)]++;
  const nav = $('#tabs');
  nav.replaceChildren();
  for (const [id, label] of [['findings', 'Findings'], ['endpoints', 'Endpoints'], ['secrets', 'Secrets'], ['info', 'Info']]) {
    const b = el('button', { class: state.view === id ? 'on' : '', type: 'button' }, label, el('b', null, String(counts[id])));
    b.addEventListener('click', () => { state.view = id; state.limit = PAGE; render(); });
    nav.append(b);
  }
  $('#chips').style.display = state.view === 'endpoints' ? 'none' : '';
  $('#sort').style.display = state.view === 'endpoints' ? 'none' : '';
  $('#hideLow').parentElement.style.display = state.view === 'endpoints' ? 'none' : '';
}

function renderChips() {
  const box = $('#chips');
  box.replaceChildren();
  for (const s of SEVS) {
    const c = el('button', { class: 'chip sev s' + s + (state.sev.has(s) ? ' on' : ''), type: 'button' }, s);
    c.addEventListener('click', () => {
      if (state.sev.has(s)) state.sev.delete(s); else state.sev.add(s);
      state.limit = PAGE;
      render();
    });
    box.append(c);
  }
}

function emptyText() {
  if (!state.pageUrl) return 'Open a regular http(s) page to scan it.';
  return state.cfg.autoScan ? 'No results for this page yet.' : null;
}

// rows are attached to the DOM only at the end of renderInner(), then stored AI answers are restored into them
function render() {
  renderInner();
  for (const k of aiHosts.keys()) if (state.ai.has(k)) syncPanel(k);
}

function renderInner() {
  renderTabs();
  renderChips();
  aiHosts.clear();
  const view = $('#view'), keep = $('#summary');
  view.replaceChildren();
  if (keep) { view.append(keep); registerSummary(keep); }
  if (!state.data) {
    const t = emptyText();
    view.append(el('div', { class: 'empty' }, t || el('span', { class: 'hint' }, 'New page - press Scan')));
    return;
  }
  const items = visible();
  if (state.view === 'endpoints') {
    const bar = el('div', { class: 'eptools' });
    const sel = el('select');
    for (const [v, t] of [['all', 'All'], ['same', 'Same-origin'], ['third', 'Third-party']]) sel.append(el('option', { value: v, selected: v === state.scope }, t));
    sel.addEventListener('change', () => { state.scope = sel.value; state.limit = PAGE; render(); });
    bar.append(sel,
      button('Copy all', '', e => copy(items.map(x => [x.url, x.kind, x.same ? 'same-origin' : 'third-party', x.files.join(',')].join('\t')).join('\n'), e.target)),
      button('Copy as list', '', e => copy(items.map(x => x.url).join('\n'), e.target)),
      el('span', null, items.length + ' endpoints'));
    view.append(bar);
  }

  let shown = 0;
  if (!items.length && state.view !== 'info') { view.append(el('div', { class: 'empty' }, 'Nothing to show.')); return; }
  if (state.view === 'endpoints') {
    for (const e of items.slice(0, state.limit)) { view.append(endpointRow(e)); shown++; }
  } else {
    items.sort(sorter);
    const groups = new Map();
    for (const f of items) { if (!groups.has(f.category)) groups.set(f.category, []); groups.get(f.category).push(f); }
    const order = [...groups.entries()].sort((a, b) => RANK[b[1][0].severity] - RANK[a[1][0].severity] || b[1].length - a[1].length);
    for (const [cat, list] of order) {
      const head = el('div', { class: 'gh' }, cat, el('span', null, list.length + (state.collapsed.has(cat) ? ' (collapsed)' : '')));
      head.addEventListener('click', () => { if (state.collapsed.has(cat)) state.collapsed.delete(cat); else state.collapsed.add(cat); render(); });
      view.append(head);
      if (state.collapsed.has(cat)) continue;
      for (const f of list) {
        if (shown >= state.limit) break;
        view.append(findingRow(f));
        shown++;
      }
    }
  }
  if (shown < items.length) {
    view.append(button('Show more (' + (items.length - shown) + ' left)', 'more', () => { state.limit += PAGE * 2; render(); }));
  }
  if (state.view === 'info') {
    if (!items.length) view.append(el('div', { class: 'empty' }, 'No informational findings.'));
    const s = sourcesBlock();
    if (s) view.append(s);
    if (state.cfg.showCandidates) { const c = candidatesBlock(); if (c) view.append(c); }
  }
}

// ---------- target tab / results ----------

function setTarget(tab) {
  state.tab = tab || null;
  const url = tab && isScannable(tab.url) ? realUrl(tab.url) : '';
  state.pageUrl = url ? stripHash(url) : '';
  state.key = state.pageUrl ? 'scan:' + state.pageUrl : '';
  const t = $('#target');
  t.hidden = !state.pageUrl;
  t.textContent = state.pageUrl;
  t.title = state.pageUrl;
}

async function resolveTarget() {
  if (!state.inTab) {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    setTarget(tab);
    return;
  }
  const want = Number(new URLSearchParams(location.search).get('target'));
  if (want) {
    try { const t = await browser.tabs.get(want); if (isScannable(t.url)) { setTarget(t); return; } } catch (e) { /* closed, use the last active tab */ }
  }
  const r = await send({ type: 'last-tab' });
  setTarget(r && r.ok ? r.tab : null);
}

async function loadResults() {
  state.data = null;
  if (state.key) {
    const got = await browser.storage.local.get(state.key);
    state.data = got[state.key] || null;
  }
  render();
}

// ---------- scan flow ----------

function showProgress(s) {
  const box = $('#progress');
  if (s.state === 'collecting' || s.state === 'scanning') {
    box.hidden = false;
    const pct = s.total ? Math.round((s.done / s.total) * 100) : 5;
    box.querySelector('i').style.width = pct + '%';
    box.querySelector('span').textContent = s.state === 'collecting' ? 'Collecting scripts...' : 'Scanned ' + s.done + ' / ' + s.total + (s.failed ? ' (' + s.failed + ' skipped)' : '');
  } else {
    box.hidden = true;
  }
}

async function poll() {
  if (state.scanning || !state.tab) return;
  state.scanning = true;
  $('#scan').disabled = true;
  try {
    for (;;) {
      const s = await send({ type: 'status', tabId: state.tab.id });
      showProgress(s);
      if (s.state === 'error') { toast(s.error || 'Scan failed'); break; }
      if (s.state !== 'collecting' && s.state !== 'scanning') break;
      await sleep(250);
    }
  } catch (e) {
    toast(String((e && e.message) || e));
  }
  state.scanning = false;
  $('#scan').disabled = false;
  showProgress({ state: 'idle' });
  await loadResults();
}

function toast(msg) {
  const row = el('div', { class: 'row err' }, msg);
  $('#view').prepend(row);
  setTimeout(() => row.remove(), 6000);
}

async function startScan() {
  if (!state.pageUrl) { toast('Open a regular http(s) page to scan it.'); return; }
  try {
    const r = await send({ type: 'scan', tabId: state.tab.id });
    if (r && r.ok === false) { toast(r.error || 'Scan failed'); return; }
  } catch (e) { toast(String((e && e.message) || e)); return; }
  poll();
}

// ---------- summary / export ----------

function summaryItems() {
  return state.data.findings.filter(f => !INFO_CATS.includes(f.category))
    .sort((a, b) => RANK[b.severity] - RANK[a.severity] || CRANK[b.confidence] - CRANK[a.confidence]).slice(0, 20)
    .map(f => ({ severity: f.severity, confidence: f.confidence, category: f.category, desc: f.desc, file: f.file, line: f.line, chain: f.chain, snippet: f.snippet }));
}

function registerSummary(box) {
  registerAi(summaryKey(), box, () => ({ kind: 'summary', payload: { items: summaryItems(), target: state.pageUrl } }));
}

function ensureSummaryBox() {
  let box = $('#summary');
  if (box) return box;
  box = el('div', { id: 'summary' });
  box.append(el('div', { class: 'sumhead' }, el('span', null, 'AI triage of the top findings'), button('Hide', '', () => { state.hidden.add(summaryKey()); box.remove(); })));
  $('#view').prepend(box);
  return box;
}

function showSummary() {
  if (!state.data || !state.data.findings.some(f => !INFO_CATS.includes(f.category))) { toast('Run a scan first.'); return; }
  const key = summaryKey();
  const box = ensureSummaryBox();
  registerSummary(box);
  state.hidden.delete(key);
  if (state.ai.has(key)) syncPanel(key); else startAi(key);
}

function exportJson() {
  if (!state.data) { toast('Nothing to export yet.'); return; }
  const d = state.data;
  const out = {
    meta: { tool: 'DPXJS', version: 'v1', author: '0xdexblood', github: 'https://github.com/0xdexblood', target: d.meta.url, scannedAt: d.meta.scannedAt },
    aiSummary: aiOf(summaryKey()),
    files: d.meta.files, failedFetches: d.meta.failed,
    findings: d.findings.map(f => Object.assign({}, f, { ai: aiOf(findingKey(f)) })),
    endpoints: d.endpoints.map(e => Object.assign({}, e, { ai: aiOf(endpointKey(e)) })),
    sources: d.sources || [],
    candidates: (d.candidates || []).map(f => Object.assign({}, f, { ai: aiOf(findingKey(f)) }))
  };
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' }));
  a.download = 'dpxjs-' + new URL(d.meta.url).hostname + '-' + Date.now() + '.json';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ---------- settings ----------

async function loadCfg() {
  const { cfg } = await browser.storage.local.get('cfg');
  const s = cfg || {};
  const c = { token: s.token, model: s.model, autoScan: s.autoScan === undefined ? DEFAULTS.autoScan : s.autoScan, showCandidates: s.showCandidates === undefined ? DEFAULTS.showCandidates : s.showCandidates };
  c.token = String(c.token || '').trim();
  if (c.token === 'sk-deepseek') c.token = '';
  c.model = String(c.model || '').trim();
  if (!c.model || c.model === 'deepseek-v3.2') c.model = DEFAULT_MODEL;
  state.cfg = c;
}

async function openSettings() {
  await loadCfg();
  const c = state.cfg;
  $('#cfgToken').value = c.token;
  $('#cfgModel').value = c.model;
  $('#cfgHint').hidden = !!c.token;
  $('#cfgAuto').checked = !!c.autoScan;
  $('#cfgCand').checked = !!c.showCandidates;
  $('#cfgStatus').textContent = '';
  $('#settings').hidden = false;
}

async function saveSettings() {
  const cfg = {
    token: $('#cfgToken').value.trim(), model: $('#cfgModel').value.trim() || DEFAULT_MODEL,
    autoScan: $('#cfgAuto').checked, showCandidates: $('#cfgCand').checked
  };
  await browser.storage.local.set({ cfg });
  state.cfg = Object.assign({}, DEFAULTS, cfg);
  $('#cfgStatus').textContent = 'Saved.';
  $('#cfgHint').hidden = !!cfg.token;
  render();
}

async function testConnection() {
  await saveSettings();
  const out = $('#cfgStatus');
  out.className = '';
  out.textContent = 'Testing...';
  try {
    const r = await send({ type: 'health' });
    out.className = r.ok ? '' : 'err';
    out.textContent = r.ok ? r.text : r.error;
  } catch (e) {
    out.className = 'err';
    out.textContent = String((e && e.message) || e);
  }
}

// ---------- init ----------

async function init() {
  try { state.inTab = !!(await browser.tabs.getCurrent()); } catch (e) { state.inTab = false; }
  document.documentElement.classList.toggle('tab', state.inTab);
  $('#openTab').hidden = state.inTab;

  const logo = $('#logo');
  const hideLogo = () => { logo.style.display = 'none'; };
  logo.addEventListener('error', hideLogo);
  if (logo.complete && logo.naturalWidth === 0 && logo.getAttribute('src')) hideLogo();

  $('#scan').addEventListener('click', startScan);
  $('#aiSum').addEventListener('click', showSummary);
  $('#export').addEventListener('click', exportJson);
  $('#gear').addEventListener('click', openSettings);
  $('#cfgSave').addEventListener('click', saveSettings);
  $('#cfgTest').addEventListener('click', testConnection);
  $('#cfgClose').addEventListener('click', () => { $('#settings').hidden = true; });
  $('#openTab').addEventListener('click', async () => {
    const q = state.tab ? '?target=' + state.tab.id : '';
    await browser.tabs.create({ url: browser.runtime.getURL('popup.html') + q });
    window.close();
  });
  $('#q').addEventListener('input', e => { state.q = e.target.value; state.limit = PAGE; render(); });
  $('#hideLow').addEventListener('change', e => { state.hideLow = e.target.checked; state.limit = PAGE; render(); });
  $('#sort').addEventListener('change', e => { state.sort = e.target.value; render(); });

  await loadCfg();
  await resolveTarget();
  await loadAi();
  await loadResults();
  if (state.pageUrl && state.ai.has(summaryKey()) && state.data) { registerSummary(ensureSummaryBox()); syncPanel(summaryKey()); }

  // live updates: streamed AI answers, finished scans, settings
  browser.storage.onChanged.addListener((ch, area) => {
    if (area !== 'local') return;
    for (const k of Object.keys(ch)) {
      if (k.startsWith('ai:')) {
        const key = k.slice(3);
        if (ch[k].newValue) state.ai.set(key, ch[k].newValue); else state.ai.delete(key);
        syncPanel(key);
      } else if (k === state.key && !state.scanning) {
        loadResults();
      } else if (k === 'cfg') {
        loadCfg().then(render);
      }
    }
  });

  // the target tab navigated: show that page's own result, never the previous one
  browser.tabs.onUpdated.addListener(async (id, ch) => {
    if (!state.tab || id !== state.tab.id || !ch.url) return;
    let t;
    try { t = await browser.tabs.get(id); } catch (e) { return; }
    const was = state.pageUrl;
    setTarget(t);
    if (state.pageUrl === was) return;
    const box = $('#summary');
    if (box) box.remove();
    state.hidden.clear();
    state.candLimit = 100;
    await loadResults();
  });

  if (state.tab) {
    const s = await send({ type: 'status', tabId: state.tab.id });
    if (s.state === 'collecting' || s.state === 'scanning') poll();
  }
}

init();
