/* DPXJS v1 - Author: 0xdexblood - https://github.com/0xdexblood */
'use strict';

const NUMES_BASE = 'https://api.numes.ai/api/v1';
const DEFAULT_MODEL = 'deepseek/deepseek-v4.1-flash';
const DEFAULTS = { token: '', model: DEFAULT_MODEL, autoScan: false, showCandidates: false };
const FLUSH_MS = 250;            // throttle for live AI answer writes
const MAX_FILE = 3 * 1024 * 1024;
const FETCH_TIMEOUT = 8000;
const CONCURRENCY = 6;
const MAX_FINDINGS = 2000;
const MAX_CANDIDATES = 800;
const MAX_ENDPOINTS = 4000;
const MAX_SCRIPTS = 500;
const KEEP_SCANS = 30;
const CODE_BUDGET = 5500000;   // characters of script text kept in storage.session
const CODE_PAGES = 3;
const MAX_JOBS = 2;            // parallel AI jobs
const IDLE_MS = 90 * 1000;     // abort when no chunk arrives for this long
const ABS_MS = 6 * 60 * 1000;  // absolute cap per AI job
const KEEPALIVE_MS = 20 * 1000;
const AI_MAX = 100, AI_TTL = 24 * 3600 * 1000;
const RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const CRANK = { High: 2, Medium: 1, Low: 0 };

const ss = browser.storage.session;
const sl = browser.storage.local;
const scans = new Map(); // tabId -> { state, url, done, total, failed, count, error, cancelled }


// ---------- Strip the Origin header on Numes requests ----------
// Numes rejects any request that carries a browser Origin (403 cors_forbidden).
// Requests from this extension carry "Origin: moz-extension://<uuid>" on POST,
// so remove it. GET /models happens to be sent without it, which is why
// "Test connection" passed while chat requests failed.
const NUMES_URL_PATTERN = 'https://api.numes.ai/*';
function stripOrigin(d) {
  return { requestHeaders: (d.requestHeaders || []).filter(h => {
    const n = h.name.toLowerCase();
    return n !== 'origin';
  }) };
}
try {
  browser.webRequest.onBeforeSendHeaders.addListener(stripOrigin, { urls: [NUMES_URL_PATTERN] }, ['blocking', 'requestHeaders']);
} catch (e) { /* fallback below */ }
(async () => {
  try {
    if (browser.declarativeNetRequest && browser.declarativeNetRequest.updateSessionRules) {
      await browser.declarativeNetRequest.updateSessionRules({
        removeRuleIds: [7001],
        addRules: [{
          id: 7001, priority: 1,
          action: { type: 'modifyHeaders', requestHeaders: [{ header: 'origin', operation: 'remove' }] },
          condition: { urlFilter: '||api.numes.ai/', resourceTypes: ['xmlhttprequest', 'other'] }
        }]
      });
    }
  } catch (e) { /* webRequest listener above is the primary path */ }
})();

const isHttp = u => /^https?:/i.test(u || '');
const VS_RE = /^view-source:/i;
const realUrl = u => String(u || '').replace(VS_RE, '');                 // view-source:https://x -> https://x
const isScannable = u => isHttp(realUrl(u));                              // http(s) page or view-source: of one
const stripHash = u => { try { const x = new URL(u); x.hash = ''; return x.href; } catch (e) { return u || ''; } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function getCfg() {
  const { cfg } = await sl.get('cfg');
  const s = cfg || {};
  const c = { token: s.token, model: s.model, autoScan: s.autoScan === undefined ? DEFAULTS.autoScan : s.autoScan, showCandidates: s.showCandidates === undefined ? DEFAULTS.showCandidates : s.showCandidates }; // only known keys: old local-server settings are dropped
  c.token = String(c.token || '').trim();
  if (c.token === 'sk-deepseek') c.token = '';            // old placeholder token
  c.model = String(c.model || '').trim();
  if (!c.model || c.model === 'deepseek-v3.2') c.model = DEFAULT_MODEL;
  return c;
}

// ---------- messages ----------

browser.runtime.onMessage.addListener(msg => {
  switch (msg && msg.type) {
    case 'scan': return startScan(msg.tabId);
    case 'status': return publicStatus(msg.tabId);
    case 'ai-start': return aiStart(msg);
    case 'ai-clear': return aiClear(msg.key);
    case 'health': return health();
    case 'last-tab': return lastTab();
    case 'devtools-urls': return addDevtoolsUrls(msg.tabId, msg.urls);
  }
});

// ---------- script tracking (webRequest / webNavigation), kept in storage.session ----------

const srcMem = new Map();   // tabId -> { pageUrl, scripts: [{url, frameId, documentUrl, ts, src}], docs: [] }
const srcChain = new Map(); // tabId -> Promise (serialises read-modify-write)
const srcTimers = new Map();

function withSrc(tabId, fn) {
  const prev = srcChain.get(tabId) || Promise.resolve();
  const next = prev.then(async () => {
    let e = srcMem.get(tabId);
    if (!e) {
      const k = 'src:' + tabId;
      const got = await ss.get(k);
      e = got[k] || { pageUrl: '', scripts: [], docs: [], ts: 0 };
      srcMem.set(tabId, e);
    }
    const r = fn(e);
    scheduleSrcFlush(tabId);
    return r;
  }).catch(() => null);
  srcChain.set(tabId, next);
  return next;
}

function scheduleSrcFlush(tabId) {
  if (srcTimers.has(tabId)) return;
  srcTimers.set(tabId, setTimeout(() => {
    srcTimers.delete(tabId);
    const e = srcMem.get(tabId);
    if (e) ss.set({ ['src:' + tabId]: e }).catch(() => {});
  }, 400));
}

const getSrc = tabId => withSrc(tabId, e => JSON.parse(JSON.stringify(e)));

function addScript(tabId, s) {
  if (!isHttp(s.url)) return;
  return withSrc(tabId, e => {
    const u = stripHash(s.url);
    if (e.scripts.some(x => x.url === u && x.frameId === s.frameId)) return;
    if (e.scripts.length >= 1000) e.scripts.shift();
    e.scripts.push({ url: u, frameId: s.frameId, documentUrl: s.documentUrl ? stripHash(s.documentUrl) : '', ts: s.ts || Date.now(), src: s.src || 'webRequest' });
  });
}

function addDoc(tabId, d) {
  return withSrc(tabId, e => {
    if (e.docs.length < 200) e.docs.push({ url: stripHash(d.url), frameId: d.frameId, type: d.type, ts: d.ts });
    if (d.frameId === 0 && d.type === 'main_frame' && !e.pageUrl) e.pageUrl = stripHash(d.url);
  });
}

browser.webRequest.onCompleted.addListener(d => {
  if (d.tabId < 0 || (d.statusCode && d.statusCode >= 400)) return;
  if (d.type === 'script') addScript(d.tabId, { url: d.url, frameId: d.frameId, documentUrl: d.documentUrl, ts: d.timeStamp });
  else addDoc(d.tabId, { url: d.url, frameId: d.frameId, type: d.type, ts: d.timeStamp });
}, { urls: ['<all_urls>'], types: ['script', 'sub_frame', 'main_frame'] });

const navFilter = { url: [{ schemes: ['http', 'https'] }] };

browser.webNavigation.onCommitted.addListener(d => {
  if (d.frameId === 0) {
    const u = stripHash(d.url);
    withSrc(d.tabId, e => {
      // new top-level document: drop everything that belongs to the previous page
      e.scripts = e.scripts.filter(s => s.ts >= d.timeStamp - 2000 && (s.frameId !== 0 || !s.documentUrl || s.documentUrl === u));
      e.docs = [{ url: u, frameId: 0, type: 'main_frame', ts: d.timeStamp }];
      e.pageUrl = u;
      e.ts = d.timeStamp;
    });
  } else {
    addDoc(d.tabId, { url: d.url, frameId: d.frameId, type: 'sub_frame', ts: d.timeStamp });
  }
}, navFilter);

// SPA route change: keep the script list, update the current URL
browser.webNavigation.onHistoryStateUpdated.addListener(d => {
  if (d.frameId !== 0) return;
  withSrc(d.tabId, e => { e.pageUrl = stripHash(d.url); });
  maybeAutoScan(d.tabId);
}, navFilter);

browser.webNavigation.onCompleted.addListener(d => { if (d.frameId === 0) maybeAutoScan(d.tabId); }, navFilter);

browser.tabs.onRemoved.addListener(tabId => {
  srcMem.delete(tabId);
  srcChain.delete(tabId);
  scans.delete(tabId);
  ss.remove(['src:' + tabId, 'status:' + tabId]).catch(() => {});
});

async function addDevtoolsUrls(tabId, urls) {
  if (!Number.isInteger(tabId) || !Array.isArray(urls)) return { ok: false };
  for (const u of urls.slice(0, 500)) if (typeof u === 'string') await addScript(tabId, { url: u, frameId: 0, ts: Date.now(), src: 'devtools' });
  return { ok: true };
}

// last active http(s) tab, used when popup.html runs in a normal tab
async function noteTab(tab) {
  if (tab && tab.id >= 0 && isScannable(tab.url)) await ss.set({ lastTab: { id: tab.id, windowId: tab.windowId, url: tab.url } }).catch(() => {});
}
browser.tabs.onActivated.addListener(a => { browser.tabs.get(a.tabId).then(noteTab, () => {}); });
browser.tabs.onUpdated.addListener((id, ch, tab) => { if (tab.active && (ch.url || ch.status === 'complete')) noteTab(tab); });

async function lastTab() {
  const { lastTab: lt } = await ss.get('lastTab');
  if (lt) { try { const t = await browser.tabs.get(lt.id); if (isScannable(t.url)) return { ok: true, tab: { id: t.id, url: t.url } }; } catch (e) { /* closed */ } }
  const list = await browser.tabs.query({ active: true, windowType: 'normal' });
  const t = list.find(x => isScannable(x.url));
  return t ? { ok: true, tab: { id: t.id, url: t.url } } : { ok: false };
}

// ---------- scan status ----------

const statusTimers = new Map();
function saveStatus(tabId, st, now) {
  const write = () => { statusTimers.delete(tabId); ss.set({ ['status:' + tabId]: pub(st) }).catch(() => {}); };
  if (now) { clearTimeout(statusTimers.get(tabId)); write(); return; }
  if (!statusTimers.has(tabId)) statusTimers.set(tabId, setTimeout(write, 300));
}
function pub(st) {
  const { state, url, done, total, failed, count, error } = st;
  return { state, url, done, total, failed, count, error };
}
async function publicStatus(tabId) {
  const st = scans.get(tabId);
  if (st) return pub(st);
  const k = 'status:' + tabId;
  const got = await ss.get(k);
  const s = got[k];
  if (!s) return { state: 'idle' };
  // an event page restart killed a running scan: report it instead of hanging forever
  if (s.state === 'collecting' || s.state === 'scanning') return Object.assign({}, s, { state: 'error', error: 'Scan was interrupted (extension restarted). Press Scan again.' });
  return s;
}

// ---------- scanning ----------

// runs inside the page: only plain data goes back
function collectPage() {
  const external = [], inline = [], perf = [];
  for (const s of document.scripts) {
    if (s.type && !/javascript|ecmascript|module/i.test(s.type)) continue;
    if (s.src) external.push(s.src);
    else if (s.textContent && s.textContent.trim()) inline.push(s.textContent);
  }
  try {
    for (const e of performance.getEntriesByType('resource')) {
      if (e.initiatorType === 'script' || /\.m?js(?:[?#]|$)/i.test(e.name)) perf.push(e.name);
    }
  } catch (e) { /* no performance API */ }
  return { url: location.href, html: document.documentElement.outerHTML, external, inline, perf };
}

async function startScan(tabId) {
  let tab;
  try { tab = await browser.tabs.get(tabId); } catch (e) { return { ok: false, error: 'Tab not found' }; }
  if (!isScannable(tab.url)) return { ok: false, error: 'Open a regular http(s) page to scan it.' };
  const url = stripHash(realUrl(tab.url));
  const cur = scans.get(tabId);
  if (cur && (cur.state === 'collecting' || cur.state === 'scanning')) {
    if (cur.url === url) return { ok: true };
    cur.cancelled = true; // the tab moved on: the old scan must not touch the new page
  }
  const st = { state: 'collecting', url, done: 0, total: 0, failed: 0, count: 0, error: '', cancelled: false };
  scans.set(tabId, st);
  saveStatus(tabId, st, true);
  runScan(tabId, st).catch(e => { st.state = 'error'; st.error = String((e && e.message) || e); saveStatus(tabId, st, true); });
  return { ok: true };
}

const autoTimers = new Map();
async function maybeAutoScan(tabId) {
  const cfg = await getCfg();
  if (!cfg.autoScan) return;
  clearTimeout(autoTimers.get(tabId));
  autoTimers.set(tabId, setTimeout(() => { autoTimers.delete(tabId); startScan(tabId); }, 1500));
}

async function fetchText(url) {
  if (!isHttp(url)) return null;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT);
  try {
    const r = await fetch(url, { signal: ctl.signal, credentials: 'omit', cache: 'force-cache' });
    if (!r.ok) return null;
    const text = await r.text();
    return text.length > MAX_FILE ? text.slice(0, MAX_FILE) : text;
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const cmpVer = (a, b) => {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
  return 0;
};

// view-source: tabs cannot be scripted: fetch the page source and read its <script> tags instead
async function collectFromSource(url) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT * 2);
  try {
    const r = await fetch(url, { signal: ctl.signal, credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status + ' while loading ' + url);
    let html = await r.text();
    if (html.length > MAX_FILE) html = html.slice(0, MAX_FILE);
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const external = [], inline = [];
    for (const s of doc.querySelectorAll('script')) {
      if (s.type && !/javascript|ecmascript|module/i.test(s.type)) continue;
      const src = s.getAttribute('src');
      if (src) { try { external.push(new URL(src, url).href); } catch (e) { /* bad src */ } }
      else if (s.textContent && s.textContent.trim()) inline.push(s.textContent);
    }
    return { url, html, external, inline, perf: [] };
  } catch (e) {
    if (e && e.name === 'AbortError') throw new Error('Timeout while loading ' + url);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function runScan(tabId, st) {
  let page;
  let tabUrl = '';
  try { tabUrl = (await browser.tabs.get(tabId)).url || ''; } catch (e) { /* tab gone */ }
  if (VS_RE.test(tabUrl)) {
    page = await collectFromSource(realUrl(tabUrl));
  } else {
    const [res] = await browser.scripting.executeScript({ target: { tabId }, func: collectPage });
    page = res && res.result;
  }
  if (!page) throw new Error('Could not read this page (restricted or not loaded yet).');
  const pageUrl = stripHash(page.url);
  st.url = pageUrl;
  if (st.cancelled) return;

  // script list: what the page really loaded (webRequest) + DOM + resource timing + DevTools
  const tracked = await getSrc(tabId);
  const urls = new Map(); // url -> origin label
  const put = (u, label) => {
    if (!isHttp(u)) return;
    u = stripHash(u);
    if (!urls.has(u)) urls.set(u, label);
  };
  if (tracked && tracked.pageUrl === pageUrl) for (const s of tracked.scripts) put(s.url, s.src === 'devtools' ? 'devtools' : 'network');
  for (const u of page.external) put(u, 'dom');
  for (const u of page.perf) put(u, 'timing');

  const queue = [{ name: 'page.html', type: 'html', code: page.html, src: 'dom' }]
    .concat(page.inline.map((code, i) => ({ name: 'inline#' + (i + 1), type: 'js', code, src: 'dom' })))
    .concat([...urls.entries()].slice(0, MAX_SCRIPTS).map(([url, src]) => ({ name: url, type: 'js', url, src })));
  st.total = queue.length;
  st.state = 'scanning';
  saveStatus(tabId, st, true);

  const findings = [], candidates = [], endpoints = new Map(), sources = new Map(), files = [], texts = new Map(), libVersions = {};
  const withHits = new Set();

  async function worker() {
    while (queue.length && !st.cancelled) {
      const job = queue.shift();
      try {
        if (job.url) job.code = await fetchText(job.url);
        if (job.code == null) { st.failed++; continue; }
        const r = await DPXAnalyzer.analyze(job, { pageUrl, acorn: self.acorn });
        texts.set(job.name, job.code);
        for (const f of r.findings) findings.push(f);
        for (const f of r.candidates) candidates.push(f);
        if (r.findings.length || r.candidates.length) withHits.add(job.name);
        for (const [k, v] of Object.entries(r.libs || {})) if (!libVersions[k] || cmpVer(v, libVersions[k]) < 0) libVersions[k] = v;
        for (const s of r.sources) {
          let cur = sources.get(s.name);
          if (!cur) { cur = { name: s.name, count: 0, locs: [] }; sources.set(s.name, cur); }
          cur.count += s.count;
          for (const l of s.locs) if (cur.locs.length < 10) cur.locs.push({ file: job.name, line: l.line, column: l.column, len: l.len });
        }
        for (const e of r.endpoints) {
          const loc = { file: e.file, line: e.line, column: e.column, len: e.len };
          const cur = endpoints.get(e.url);
          if (!cur) endpoints.set(e.url, { url: e.url, kind: e.kind, same: e.same, files: [e.file], locs: [loc], line: e.line, ctx: e.ctx, count: 1 });
          else {
            cur.count++;
            if (cur.files.length < 5 && !cur.files.includes(e.file)) { cur.files.push(e.file); cur.locs.push(loc); }
          }
        }
        files.push({ name: job.name, size: r.size, mode: r.mode, findings: r.findings.length, lib: !!r.lib, src: job.src });
      } catch (e) {
        st.failed++; // one bad file never breaks the scan
      } finally {
        st.done++;
        saveStatus(tabId, st);
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  if (st.cancelled) return;

  // known-vulnerable-version gate for library based prototype pollution
  const kept = [];
  for (const f of findings) {
    if (f.category === 'Prototype Pollution' && f.lib) {
      const v = libVersions[f.lib];
      const patched = f.lib === 'jquery' ? '3.4.0' : '4.17.21';
      if (v && cmpVer(v, patched) >= 0) continue;                       // patched library: not exploitable
      if (!v) { f.confidence = 'Low'; f.why = 'library-version-unknown'; candidates.push(f); continue; }
      f.desc += ' (' + f.lib + ' ' + v + ' is vulnerable)';
      f.confidence = 'High';
    }
    kept.push(f);
  }
  kept.sort((a, b) => RANK[b.severity] - RANK[a.severity] || CRANK[b.confidence] - CRANK[a.confidence]);
  const result = {
    meta: { url: pageUrl, origin: new URL(pageUrl).origin, scannedAt: new Date().toISOString(), files, total: st.total, failed: st.failed, libs: libVersions },
    findings: kept.slice(0, MAX_FINDINGS),
    candidates: candidates.sort((a, b) => RANK[b.severity] - RANK[a.severity]).slice(0, MAX_CANDIDATES),
    sources: [...sources.values()].sort((a, b) => b.count - a.count),
    endpoints: [...endpoints.values()].slice(0, MAX_ENDPOINTS)
  };
  await storeScan(pageUrl, result);
  await persistCode(pageUrl, texts, withHits);
  st.count = result.findings.length;
  st.state = 'done';
  saveStatus(tabId, st, true);
}

async function storeScan(pageUrl, result) {
  const key = 'scan:' + pageUrl;
  const { scanIndex } = await sl.get('scanIndex');
  let idx = (scanIndex || []).filter(x => x.key !== key);
  idx.unshift({ key, at: Date.now() });
  const drop = idx.slice(KEEP_SCANS);
  idx = idx.slice(0, KEEP_SCANS);
  await sl.set({ [key]: result, scanIndex: idx });
  if (drop.length) await sl.remove(drop.map(x => x.key));
}

// script texts needed for code context / viewer: inline + page.html first, then files that have hits
async function persistCode(pageUrl, texts, withHits) {
  const order = [];
  for (const n of texts.keys()) if (!/^https?:/i.test(n)) order.push(n);
  for (const n of texts.keys()) if (/^https?:/i.test(n) && withHits.has(n)) order.push(n);
  const files = {};
  let used = 0;
  for (const n of order) {
    let t = texts.get(n);
    if (n === 'page.html' && t.length > 1500000) t = t.slice(0, 1500000);
    if (used + t.length > CODE_BUDGET) continue;
    files[n] = t;
    used += t.length;
  }
  const key = 'code:' + pageUrl;
  const { codeIndex } = await ss.get('codeIndex');
  let idx = (codeIndex || []).filter(k => k !== key);
  idx.unshift(key);
  const drop = idx.slice(CODE_PAGES);
  idx = idx.slice(0, CODE_PAGES);
  try {
    await ss.set({ [key]: files, codeIndex: idx });
  } catch (e) {
    const small = {};
    for (const n of Object.keys(files)) if (!/^https?:/i.test(n)) small[n] = files[n].slice(0, 400000);
    try { await ss.set({ [key]: small, codeIndex: idx }); } catch (x) { /* viewer falls back to refetching */ }
  }
  if (drop.length) await ss.remove(drop).catch(() => {});
}

async function getCode(pageUrl, file) {
  try {
    const got = await ss.get('code:' + pageUrl);
    const f = got['code:' + pageUrl];
    if (f && typeof f[file] === 'string') return f[file];
  } catch (e) { /* fall through */ }
  return /^https?:/i.test(file) ? fetchText(file) : null;
}

// ---------- AI: jobs, streaming ----------

const jobs = new Map();   // key -> job (queued or running)
const waiting = [];
let running = 0;
let keepTimer = null;

function startKeepAlive() {
  if (keepTimer) return;
  keepTimer = setInterval(() => { browser.runtime.getPlatformInfo().catch(() => {}); }, KEEPALIVE_MS);
}
function stopKeepAlive() {
  if (jobs.size) return;
  clearInterval(keepTimer);
  keepTimer = null;
}

let idxChain = Promise.resolve();
function updateIndex(fn) {
  idxChain = idxChain.then(async () => {
    const { aiIndex } = await sl.get('aiIndex');
    const idx = Object.assign({}, aiIndex);
    await fn(idx);
    await sl.set({ aiIndex: idx });
  }).catch(() => {});
  return idxChain;
}
const touchIndex = key => updateIndex(idx => { idx[key] = Date.now(); });

function pruneAi() {
  return updateIndex(async idx => {
    const now = Date.now(), busy = new Set(jobs.keys()), remove = [];
    for (const k of Object.keys(idx)) if (!busy.has(k) && now - idx[k] > AI_TTL) { remove.push(k); delete idx[k]; }
    const left = Object.keys(idx).sort((a, b) => idx[b] - idx[a]);
    for (const k of left.slice(AI_MAX)) if (!busy.has(k)) { remove.push(k); delete idx[k]; }
    if (remove.length) await sl.remove(remove.map(k => 'ai:' + k));
  });
}

function writeJob(job) {
  if (job.cancelled) return Promise.resolve();
  return sl.set({ ['ai:' + job.key]: { status: job.status, text: job.text, error: job.error, updatedAt: Date.now() } }).catch(() => {});
}

// jobs left over from a previous background instance can never finish: mark them
const recovered = (async () => {
  try {
    const { aiIndex } = await sl.get('aiIndex');
    const keys = Object.keys(aiIndex || {}).map(k => 'ai:' + k);
    if (!keys.length) return;
    const got = await sl.get(keys);
    const fix = {};
    for (const k of keys) {
      const e = got[k];
      if (e && (e.status === 'queued' || e.status === 'running')) fix[k] = Object.assign({}, e, { status: 'error', error: 'Interrupted (extension restarted). Press Retry.', updatedAt: Date.now() });
    }
    if (Object.keys(fix).length) await sl.set(fix);
  } catch (e) { /* ignore */ }
  pruneAi();
})();

async function aiStart({ key, kind, payload }) {
  await recovered;
  if (!key || !/^(?:finding|endpoint|summary)$/.test(kind || '')) return { ok: false, error: 'Bad AI request' };
  if (jobs.has(key)) return { ok: true };
  const job = { key, kind, payload: payload || {}, text: '', error: '', status: 'queued', ctl: null, cancelled: false, lastFlush: 0, timer: null };
  jobs.set(key, job);
  waiting.push(job);
  startKeepAlive();
  await writeJob(job);
  await touchIndex(key);
  pump();
  return { ok: true };
}

async function aiClear(key) {
  const job = jobs.get(key);
  if (job) {
    job.cancelled = true;
    if (job.ctl) job.ctl.abort();
    const i = waiting.indexOf(job);
    if (i >= 0) waiting.splice(i, 1);
    jobs.delete(key);
    stopKeepAlive();
  }
  await sl.remove('ai:' + key);
  await updateIndex(idx => { delete idx[key]; });
  return { ok: true };
}

function pump() {
  while (running < MAX_JOBS && waiting.length) {
    const job = waiting.shift();
    if (job.cancelled) continue;
    running++;
    runJob(job);
  }
}

async function runJob(job) {
  try {
    job.status = 'running';
    await writeJob(job);
    const prompt = await buildPrompt(job);
    await streamChat(prompt, job);
    if (job.cancelled) return;
    if (!job.text.trim()) throw new Error('The model returned an empty answer');
    job.status = 'done';
  } catch (e) {
    if (!job.cancelled) { job.status = 'error'; job.error = String((e && e.message) || e); }
  } finally {
    clearTimeout(job.timer);
    job.timer = null;
    if (!job.cancelled) { await writeJob(job); await touchIndex(job.key); }
    if (jobs.get(job.key) === job) jobs.delete(job.key);
    running--;
    stopKeepAlive();
    pump();
    pruneAi();
  }
}

// ---------- Numes API (OpenAI-compatible) ----------

function httpError(status, body) {
  if (status === 401) return new Error('Invalid API key. Check it in Settings.');
  if (status === 402) return new Error('Not enough credits. Add credits in your Numes dashboard.');
  if (status === 429) return new Error('Rate limited, try again shortly.');
  if (status === 403 && /cors_forbidden|origin is not allowed/i.test(String(body || ''))) return new Error('Numes blocked the request Origin (403 cors_forbidden). Reload the extension; the Origin header must be removed for api.numes.ai.');
  return new Error('HTTP ' + status + ': ' + String(body || '').slice(0, 200));
}
const NET_ERR = 'Cannot reach api.numes.ai (check internet)';
const NO_KEY = 'Set your Numes API key in Settings first.';

// one self-contained user message; the API key only goes into the Authorization header
async function streamChat(prompt, job) {
  const cfg = await getCfg();
  if (!cfg.token) throw new Error(NO_KEY);
  const ctl = new AbortController();
  job.ctl = ctl;
  let reason = '';
  const stop = r => { reason = r; ctl.abort(); };
  const absTimer = setTimeout(() => stop('Stopped after 6 minutes (absolute limit)'), ABS_MS);
  let idleTimer = null;
  const bump = () => { clearTimeout(idleTimer); idleTimer = setTimeout(() => stop('No data received for 90 seconds'), IDLE_MS); };
  const fail = e => {
    if (job.cancelled) return new Error('Cancelled');
    if (reason) return new Error(reason);
    if (e && e.name === 'AbortError') return new Error('Request aborted');
    return new Error(NET_ERR);
  };
  const flush = force => {
    const now = Date.now();
    if (!force && now - job.lastFlush < FLUSH_MS) return;
    job.lastFlush = now;
    writeJob(job);
  };

  let nonData = '', finished = false;
  const handleLine = line => {
    if (!line.startsWith('data:')) { if (nonData.length < 2000000) nonData += line + '\n'; return false; }
    const p = line.slice(5).trim();
    if (p === '[DONE]') return true;
    let j;
    try { j = JSON.parse(p); } catch (e) { return false; }
    if (j && j.error) throw new Error(typeof j.error === 'string' ? j.error.slice(0, 200) : String(j.error.message || JSON.stringify(j.error)).slice(0, 200));
    const piece = j && j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content;
    if (typeof piece === 'string' && piece) { job.text += piece; flush(false); }
    return false;
  };

  try {
    bump();
    let r;
    try {
      r = await fetch(NUMES_BASE + '/chat/completions', {
        method: 'POST', signal: ctl.signal,
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + cfg.token },
        body: JSON.stringify({ model: cfg.model, stream: true, max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
      });
    } catch (e) { throw fail(e); }
    if (!r.ok) {
      let body = '';
      try { body = await r.text(); } catch (e) { /* ignore */ }
      throw httpError(r.status, body);
    }
    bump();
    if (!r.body) throw new Error('The server sent no response body');
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    try {
      while (!finished) {
        const { done, value } = await reader.read();
        if (done) break;
        bump();
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).replace(/\r$/, '');
          buf = buf.slice(i + 1);
          if (handleLine(line)) { finished = true; break; }
        }
      }
      if (!finished && buf.trim()) handleLine(buf.replace(/\r$/, ''));
      if (finished) reader.cancel().catch(() => {});
    } catch (e) {
      if (e instanceof Error && !(e instanceof TypeError) && e.name !== 'AbortError') throw e; // server-reported error / our own message
      throw fail(e);
    }
    // a server that ignored stream:true answers with one plain JSON document
    if (!job.text && nonData.trim()) {
      try {
        const j = JSON.parse(nonData.trim());
        if (j && j.error) throw new Error(typeof j.error === 'string' ? j.error.slice(0, 200) : String(j.error.message || JSON.stringify(j.error)).slice(0, 200));
        const m = j && j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
        if (typeof m === 'string') job.text = m;
      } catch (e) { if (!(e instanceof SyntaxError)) throw e; }
    }
    flush(true);
  } finally {
    clearTimeout(absTimer);
    clearTimeout(idleTimer);
  }
}

// "Test connection" (message type kept as 'health')
async function health() {
  const cfg = await getCfg();
  if (!cfg.token) return { ok: false, error: NO_KEY };
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(NUMES_BASE + '/models', { signal: ctl.signal, headers: { Authorization: 'Bearer ' + cfg.token } });
    if (!r.ok) {
      let body = '';
      try { body = await r.text(); } catch (e) { /* ignore */ }
      return { ok: false, error: httpError(r.status, body).message };
    }
    return { ok: true, text: 'Connected' };
  } catch (e) {
    return { ok: false, error: NET_ERR };
  } finally {
    clearTimeout(t);
  }
}

// ---------- prompts ----------

function codeContext(code, f, radius, limit) {
  const render = (start, lines) => lines.map((l, i) => (start + i === f.line ? '>> ' : '   ') + (start + i) + ': ' + l).join('\n');
  if (!code) return f.ctx ? render(f.ctx.start, f.ctx.lines) : '';
  const starts = DPXAnalyzer.lineStarts(code);
  for (let r = radius; r >= 1; r--) {
    const c = DPXAnalyzer.contextFor(code, starts, f.line, f.column, r);
    const text = render(c.start, c.lines);
    if (text.length <= limit || r === 1) return text.slice(0, limit);
  }
  return '';
}

const TAIL = 'Answer in markdown, max 120 words, no preamble: verdict (likely real / likely false positive), one-sentence reason, one-line test idea.';
const TAIL_SUM = 'Answer in markdown, max 150 words, no preamble: a prioritized list of at most 5 lines. No long explanations.';

async function buildPrompt(job) {
  const p = job.payload;
  if (job.kind === 'finding') return findingPrompt(p.item, await getCode(p.pageUrl, p.item.file));
  if (job.kind === 'endpoint') {
    const e = p.item, loc = e.locs && e.locs[0];
    const code = loc ? await getCode(p.pageUrl, loc.file) : null;
    return endpointPrompt(e, loc, code);
  }
  return summaryPrompt(p.items || [], p.target || '');
}

function findingPrompt(f, code) {
  const secret = f.category === 'Secret' || f.category === 'Public Identifier';
  const asks = secret
    ? ['1. What service/key type is this, and is it meant to be public (e.g. a browser key) or a real leak?',
      '2. Is it likely a placeholder / false positive?',
      '3. How can I safely validate it (without abusing it) and what is the impact if valid?',
      '4. What should I verify manually?']
    : ['1. Is this a real exploitable issue or a false positive, and why?',
      '2. Explain the exact data flow (source -> sink).',
      '3. Give a minimal working PoC payload or test URL if it is exploitable.',
      '4. List what to verify manually.'];
  return [
    'You are a senior web application security researcher assisting with an authorized bug bounty test of client-side JavaScript.',
    '',
    'Category: ' + f.category + ' (' + f.desc + ')',
    'Severity: ' + f.severity + ' / confidence: ' + f.confidence,
    'File: ' + f.file,
    'Line: ' + f.line + ', column ' + f.column,
    'Taint chain: ' + (f.chain || 'none detected'),
    '',
    'Code context (>> marks the flagged line):',
    codeContext(code, f, 10, 3000),
    '',
    'Please answer:',
    ...asks,
    TAIL
  ].join('\n');
}

function endpointPrompt(e, loc, code) {
  const ctx = loc && code ? codeContext(code, { line: loc.line, column: loc.column || 1 }, 4, 1200) : '';
  return [
    'You are a senior web application security researcher assisting with an authorized bug bounty test.',
    '',
    'Endpoint: ' + e.url,
    'Kind: ' + e.kind + ', ' + (e.same ? 'same-origin' : 'third-party'),
    'Found in: ' + e.files.join(', ') + (loc ? ' (line ' + loc.line + ')' : ''),
    ctx ? '\nCode around its first use:\n' + ctx : '',
    '',
    'Please answer:',
    '1. What is its likely purpose?',
    '2. Which parameters look risky?',
    '3. What should I test (IDOR, auth bypass, injection, SSRF, open redirect)?',
    TAIL
  ].join('\n');
}

function summaryPrompt(items, target) {
  const lines = items.slice(0, 20).map((f, i) =>
    (i + 1) + '. [' + f.severity + '/' + f.confidence + '] ' + f.category + ' - ' + f.desc + ' @ ' + f.file + ':' + f.line +
    (f.chain ? ' | chain: ' + f.chain : '') + (f.category === 'Secret' ? '' : ' | ' + String(f.snippet || '').slice(0, 100)));
  return [
    'You are a senior web application security researcher assisting with an authorized bug bounty test of ' + target + '.',
    'These are the top static-analysis findings from client-side JavaScript:',
    '',
    ...lines,
    '',
    'Give a prioritized triage list: which to test first, which are likely false positives, and a one-line test idea for each real candidate.',
    TAIL_SUM
  ].join('\n');
}
