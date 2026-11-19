/* DPXJS v1 - Author: 0xdexblood - https://github.com/0xdexblood */
'use strict';

const params = new URLSearchParams(location.search);
const file = params.get('file') || '';
const page = params.get('page') || '';
let line = Math.max(1, parseInt(params.get('line'), 10) || 1);
let col = Math.max(1, parseInt(params.get('col'), 10) || 1);
let len = Math.max(0, parseInt(params.get('len'), 10) || 0);

const WINDOW = 400;        // chars shown around the column of a very long (minified) line
const LONG = 2000;         // a line longer than this is shown as a window
const CHUNK = 300;         // lines shown around the target in big files
const $ = s => document.querySelector(s);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

let lines = [], list = [], idx = -1;
let from = 0, to = 0; // rendered line range (0-based, to exclusive)
let minified = false;

function updateNote() {
  const note = $('#note');
  note.hidden = !minified;
  if (!minified) return;
  note.replaceChildren('Minified source: showing about ±' + WINDOW + ' characters around ', el('b', null, 'column ' + col), ' of line ' + line + '; the matched range is highlighted.');
}

async function loadSource() {
  if (/^https?:/i.test(file)) {
    const r = await fetch(file, { credentials: 'omit', cache: 'force-cache' });
    if (!r.ok) throw new Error('Could not load the file (HTTP ' + r.status + ')');
    return (await r.text()).slice(0, 3 * 1024 * 1024);
  }
  const key = 'code:' + page;
  const got = await browser.storage.session.get(key);
  const f = got[key];
  if (f && typeof f[file] === 'string') return f[file];
  throw new Error('This source is no longer stored. Scan the page again, then reopen the viewer.');
}

async function loadFindings() {
  try {
    const key = 'scan:' + page;
    const got = await browser.storage.local.get(key);
    const d = got[key];
    if (!d) return;
    list = d.findings.filter(f => f.file === file).sort((a, b) => a.line - b.line || a.column - b.column);
  } catch (e) { /* the viewer works without the list */ }
}

function syncIndex() {
  idx = list.findIndex(f => f.line === line && f.column === col);
  const pos = $('#pos');
  pos.textContent = list.length ? (idx >= 0 ? (idx + 1) + ' / ' + list.length : list.length + ' in this file') : 'no findings in this file';
  $('#prev').disabled = !list.length;
  $('#next').disabled = !list.length;
}

function go(step) {
  if (!list.length) return;
  let n;
  if (idx >= 0) n = (idx + step + list.length) % list.length;
  else if (step > 0) { n = list.findIndex(f => f.line > line || (f.line === line && f.column > col)); if (n < 0) n = 0; }
  else { n = -1; list.forEach((f, i) => { if (f.line < line || (f.line === line && f.column < col)) n = i; }); if (n < 0) n = list.length - 1; }
  const f = list[n];
  line = f.line; col = f.column; len = f.len || 0;
  const q = new URLSearchParams(location.search);
  q.set('line', line); q.set('col', col); q.set('len', len);
  try { history.replaceState(null, '', '?' + q.toString()); } catch (e) { /* the address bar is cosmetic */ }
  from = to = 0;
  render(true);
}

// one source line as DOM: plain text, a window for very long lines, optionally with the matched range marked
function lineNode(n, text) {
  const row = el('div', 'ln');
  row.append(el('span', 'num', String(n)));
  const txt = el('span', 'txt');
  const hit = n === line;
  let s = text, off = 0, pre = '', post = '';
  if (s.length > LONG) {
    if (hit) {
      off = Math.max(0, col - 1 - WINDOW);
      const end = Math.min(s.length, col - 1 + Math.max(len, 1) + WINDOW);
      pre = off > 0 ? '… ' : '';
      post = end < s.length ? ' …' : '';
      s = s.slice(off, end);
    } else {
      s = s.slice(0, 300);
      post = '  … (' + (text.length - 300) + ' more chars)';
    }
  }
  if (hit) {
    row.classList.add('hit');
    const a = Math.max(0, col - 1 - off), b = Math.min(s.length, a + Math.max(len, 1));
    txt.append(pre + s.slice(0, a));
    const m = el('mark', null, s.slice(a, b));
    txt.append(m, s.slice(b) + post);
  } else {
    txt.append(pre + s + post);
  }
  row.append(txt);
  return row;
}

function render(scroll) {
  const code = $('#code');
  code.replaceChildren();
  const total = lines.length;
  if (!from && !to) {
    if (total <= 4000) { from = 0; to = total; }
    else { from = Math.max(0, line - 1 - CHUNK); to = Math.min(total, line - 1 + CHUNK); }
  }
  if (from > 0) {
    const b = el('button', 'more', 'Show 500 earlier lines (' + from + ' above)');
    b.addEventListener('click', () => { from = Math.max(0, from - 500); render(false); });
    code.append(b);
  }
  let target = null;
  for (let i = from; i < to; i++) {
    const row = lineNode(i + 1, lines[i]);
    if (i + 1 === line) target = row;
    code.append(row);
  }
  if (to < total) {
    const b = el('button', 'more', 'Show 500 later lines (' + (total - to) + ' below)');
    b.addEventListener('click', () => { to = Math.min(total, to + 500); render(false); });
    code.append(b);
  }
  syncIndex();
  updateNote();
  document.title = 'DPXJS - ' + shortName(file) + ':' + line;
  if (scroll && target) target.scrollIntoView({ block: 'center' });
}

function shortName(f) {
  if (!/^https?:/i.test(f)) return f;
  try { const u = new URL(f); return u.pathname.split('/').filter(Boolean).pop() || u.host; } catch (e) { return f; }
}

async function init() {
  const logo = $('#logo');
  const hideLogo = () => { logo.style.display = 'none'; };
  logo.addEventListener('error', hideLogo);
  if (logo.complete && logo.naturalWidth === 0 && logo.getAttribute('src')) hideLogo();

  const fileBox = $('#file');
  if (/^https?:/i.test(file)) {
    const a = el('a', null, file);
    a.href = file; a.target = '_blank'; a.rel = 'noopener';
    fileBox.append(a);
  } else {
    fileBox.textContent = file + (page ? '  (page: ' + page + ')' : '');
  }
  $('#prev').addEventListener('click', () => go(-1));
  $('#next').addEventListener('click', () => go(1));

  let text;
  try {
    text = await loadSource();
  } catch (e) {
    const err = $('#err');
    err.hidden = false;
    err.textContent = String((e && e.message) || e);
    return;
  }
  lines = text.split('\n').map(l => l.replace(/\r$/, ''));
  await loadFindings();
  minified = lines.length <= 3 || lines.some(l => l.length > LONG);
  render(true);
}

init();
