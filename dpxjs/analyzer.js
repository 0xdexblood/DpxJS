/* DPXJS v1 - Author: 0xdexblood - https://github.com/0xdexblood */
(function (root) {
  'use strict';

  const MAX_FILE = 3 * 1024 * 1024;
  const AST_MAX = 1536 * 1024; // bigger files go straight to regex mode, parsing them costs seconds
  const CAP = 40;              // max hits per rule per file
  const RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  const NAMES = ['Info', 'Low', 'Medium', 'High', 'Critical'];
  const lower = s => NAMES[Math.max(0, RANK[s] - 1)];
  const tick = () => new Promise(r => setTimeout(r, 0));
  const XSS = 'DOM XSS Sink', NAV = 'Navigation / Redirect', OTH = 'Other Sink';
  const PP = 'Prototype Pollution', PM = 'postMessage', SEC = 'Secret', PUB = 'Public Identifier';
  const INFO = 'Client-side Info', LIB = 'Library';

  // ---------- helpers ----------

  function lineStarts(code) {
    const a = [0];
    let i = -1;
    while ((i = code.indexOf('\n', i + 1)) !== -1) a.push(i + 1);
    return a;
  }

  function lineOf(starts, pos) {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= pos) lo = mid; else hi = mid - 1;
    }
    return lo;
  }

  function contextFor(code, starts, line, col, radius) {
    const first = Math.max(1, line - radius), last = Math.min(starts.length, line + radius);
    const lines = [];
    for (let l = first; l <= last; l++) {
      let s = code.slice(starts[l - 1], l < starts.length ? starts[l] - 1 : code.length).replace(/\r$/, '');
      if (s.length > 200) {
        const from = l === line ? Math.max(0, col - 101) : 0;
        s = (from ? '…' : '') + s.slice(from, from + 200) + '…';
      }
      lines.push(s);
    }
    return { start: first, lines };
  }

  function entropy(s) {
    const f = {};
    for (const ch of s) f[ch] = (f[ch] || 0) + 1;
    let h = 0;
    for (const k in f) { const p = f[k] / s.length; h -= p * Math.log2(p); }
    return h;
  }

  const mask = v => (v.length > 12 ? v.slice(0, 4) + '…' + v.slice(-4) : v.slice(0, 2) + '…');
  const cmpVer = (a, b) => {
    const x = a.split('.').map(Number), y = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
    return 0;
  };

  function b64dec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    if (typeof atob === 'function') return atob(s);
    return Buffer.from(s, 'base64').toString('binary');
  }
  function jsonB64(s) {
    try { return JSON.parse(decodeURIComponent(escape(b64dec(s)))); } catch (e) { return null; }
  }

  function eachMatch(re, code, fn, max) {
    re.lastIndex = 0;
    let m, n = 0;
    max = max || CAP * 4;
    while ((m = re.exec(code))) {
      if (!m[0].length) { re.lastIndex++; continue; }
      fn(m);
      if (++n >= max) break;
    }
  }

  function collector(file, code) {
    const starts = lineStarts(code), out = [], seen = new Set(), count = new Map();
    function add(o) {
      const key = o.rule + '|' + o.pos;
      if (seen.has(key)) return;
      const n = count.get(o.rule) || 0;
      if (n >= CAP) return;
      seen.add(key);
      count.set(o.rule, n + 1);
      const li = lineOf(starts, o.pos), line = li + 1, column = o.pos - starts[li] + 1;
      const ctx = contextFor(code, starts, line, column, 3);
      let snippet = code.substr(o.pos, Math.min(o.len || 120, 160)).replace(/\s+/g, ' ');
      if (o.value) {
        const m = mask(o.value);
        snippet = snippet.split(o.value).join(m);
        ctx.lines = ctx.lines.map(l => l.split(o.value).join(m));
      }
      out.push({
        id: file + ':' + line + ':' + column + ':' + o.rule, rule: o.rule, desc: o.desc || o.rule,
        category: o.category, severity: o.severity, confidence: o.confidence || 'Medium',
        file, line, column, len: Math.min(o.len || 1, 400), snippet, chain: o.chain || '', value: o.value || '',
        lib: o.lib || '', why: o.why || '', ctx
      });
    }
    return { add, out, starts };
  }

  // skips matches on lines that start with a comment marker
  function commentTester(code, starts) {
    const cache = new Map();
    return pos => {
      const ls = starts[lineOf(starts, pos)];
      const m = /^\s*(\/\/|\/\*|\*)/.exec(code.substr(ls, 80));
      if (!m) return false;
      if (m[1] !== '/*') return true;
      let end = cache.get(ls);
      if (end === undefined) { end = code.indexOf('*/', ls); cache.set(ls, end); }
      return end === -1 || pos < end;
    };
  }

  // keep <script src> tags, blank inline bodies (those are scanned as their own files)
  const blankInline = html => html.replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi,
    (m, a, body, z) => a + body.replace(/[^\n]/g, ' ') + z);

  // ---------- well-known libraries / analytics: only version + secret checks ----------

  const LIB_FILE = /^(?:jquery(?:[-.](?:ui|migrate|slim|cookie|validate|mobile))*|react(?:[-.](?:dom|is))?|vue|angular|angular[-.](?:route|animate|sanitize|resource|cookies|touch|aria|messages|loader)|lodash|bootstrap|moment|moment[-.]with[-.]locales|core-js|polyfills?)(?:[-.](?:min|production|development|profiling|bundle|slim|runtime|global|esm-browser|esm-bundler|cjs|prod|core|fp|custom|es5|es6|es2015|legacy|modern|nomodule|compat|full|[0-9a-f]{6,}))*$/i;
  const LIB_BANNER = /jQuery(?: JavaScript Library)? v\d|@license React|\bReact v\d|Vue\.js v\d|AngularJS v\d|lodash\.com\/license|\bLodash\b[^\n]{0,60}\d|Bootstrap v\d|moment\.js|core-js@?\d|\/\*!?\s*\w*polyfills?\b/i;
  const LIB_HOST = /(?:^|\.)(?:google-analytics\.com|googletagmanager\.com|googletagservices\.com|googlesyndication\.com|doubleclick\.net|facebook\.net|facebook\.com|hotjar\.com|hotjar\.io|clarity\.ms|segment\.com|segment\.io|sentry-cdn\.com)$/i;

  function isKnownLib(name, code) {
    if (/^https?:/i.test(name)) {
      try {
        const u = new URL(name);
        if (LIB_HOST.test(u.hostname)) return true;
        let base = decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || '');
        base = base.replace(/\.m?js$/i, '').replace(/[-.@]v?\d+(?:\.\d+)+/g, '').replace(/[-.@]\d+$/, '');
        if (LIB_FILE.test(base)) return true;
      } catch (e) { /* not a URL */ }
    }
    return LIB_BANNER.test(code.slice(0, 2000));
  }

  // ---------- rule tables ----------

  const SOURCES = [
    ['location.hash', /\blocation\.hash\b/g], ['location.search', /\blocation\.search\b/g],
    ['location.href', /\blocation\.href\b(?!\s*=(?!=))/g], ['location.pathname', /\blocation\.pathname\b(?!\s*=(?!=))/g],
    ['document.URL', /\bdocument\.URL\b/g], ['document.documentURI', /\bdocument\.documentURI\b/g],
    ['document.baseURI', /\bdocument\.baseURI\b/g], ['document.referrer', /\bdocument\.referrer\b/g],
    ['document.cookie', /\bdocument\.cookie\b/g], ['window.name', /\bwindow\.name\b/g],
    ['window.opener', /\bwindow\.opener\b/g], ['localStorage', /\blocalStorage\b/g],
    ['sessionStorage', /\bsessionStorage\b/g], ['indexedDB', /\bindexedDB\b/g],
    ['URLSearchParams(location)', /new\s+URLSearchParams\(\s*(?:window\.|document\.)?location\b/g]
  ];
  const MSG_DATA_RE = /\b(?:event|evt|ev|e|msg|message)\.data\b/g;

  // name-only mentions: never findings, candidates at best
  const NAMED = [
    { id: 'dangerouslySetInnerHTML', cat: XSS, sev: 'Low', re: /\bdangerouslySetInnerHTML\b/g, desc: 'React dangerouslySetInnerHTML (no proven source)' },
    { id: 'v-html', cat: XSS, sev: 'Low', re: /\bv-html\b/g, desc: 'Vue v-html directive (no proven source)' },
    { id: 'ng-bind-html', cat: XSS, sev: 'Low', re: /\bng-bind-html\b|\bngBindHtml\b|\[innerHTML\]/g, desc: 'Angular HTML binding (no proven source)' },
    { id: 'bypassSecurityTrust', cat: XSS, sev: 'Low', re: /\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\b/g, desc: 'Angular bypassSecurityTrust* (no proven source)' }
  ];

  const PLACEHOLDER = /change.?me|your[_\-\s.]|<your|example|x{4,}|\*{4,}|1234|test|dummy|sample|placeholder|insert[_\-]?here|replace.?me|todo|fake|\$\{|\{\{|%\w+%/i;

  const SECRETS = [
    { id: 'aws', name: 'AWS access key', sev: 'High', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
    { id: 'gtoken', name: 'Google OAuth access token', sev: 'High', re: /\bya29\.[\w-]{30,}/g },
    { id: 'slack', name: 'Slack token', sev: 'High', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
    { id: 'slackhook', name: 'Slack webhook', sev: 'High', re: /https:\/\/hooks\.slack\.com\/services\/T\w+\/B\w+\/\w+/g },
    { id: 'github', name: 'GitHub token', sev: 'Critical', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g },
    { id: 'stripe', name: 'Stripe live secret key', sev: 'Critical', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g },
    { id: 'twilio', name: 'Twilio API key', sev: 'High', re: /\bSK[0-9a-f]{32}\b/g },
    { id: 'sendgrid', name: 'SendGrid API key', sev: 'High', re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/g },
    { id: 'mailgun', name: 'Mailgun API key', sev: 'High', re: /\bkey-[0-9a-f]{32}\b/g },
    { id: 'mapboxsk', name: 'Mapbox secret token', sev: 'High', re: /\bsk\.eyJ[\w-]{20,}\.[\w-]{20,}/g },
    {
      id: 'privkey', name: 'Private key block', sev: 'Critical',
      re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:\\n|\\r|\s){0,6}[A-Za-z0-9+/=]{40,}/g,
      val: m => m[0].slice(0, 40)
    },
    { id: 'jwt', name: 'JWT', sev: 'Medium', re: /\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{5,}/g, special: 'jwt' },
    { id: 'basic', name: 'Basic auth credentials', sev: 'Medium', re: /\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})/g, special: 'basic' },
    { id: 'generic', name: 'Hardcoded credential', sev: 'Medium', conf: 'Medium', special: 'generic',
      re: /(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|client[_-]?secret|access[_-]?key|private[_-]?key|auth[_-]?token)[\"']?\s*[:=]\s*[\"']([^\"'\s]{16,200})[\"']/gi }
  ];

  // public by design: never "Secret"
  const PUBLIC = [
    { id: 'firebase', name: 'Firebase web config', re: /\bauthDomain[\"']?\s*:\s*[\"'][\w.-]+\.firebaseapp\.com[\"']/g },
    { id: 'gapi', name: 'Google API key (AIza...)', re: /\bAIza[\w-]{35}\b/g },
    { id: 'sentry', name: 'Sentry DSN', re: /https:\/\/[0-9a-f]{32}@[\w.-]*sentry[\w.-]*\/\d+/g },
    { id: 'mapbox', name: 'Mapbox public token', re: /\bpk\.eyJ[\w-]{20,}\.[\w-]{20,}/g },
    { id: 'twiliosid', name: 'Twilio account SID', re: /\bAC[0-9a-f]{32}\b/g },
    { id: 'goauth', name: 'Google OAuth client ID', re: /\b\d{8,}-[a-z0-9_]{32}\.apps\.googleusercontent\.com\b/g },
    { id: 'stripepk', name: 'Stripe publishable key', re: /\bpk_live_[0-9a-zA-Z]{20,}\b/g }
  ];

  // facts about the code (kept in Info) vs. heuristics (candidates)
  const MISC = [
    { id: 'sourcemap', desc: 'Source map reference', re: /[#@]\s*sourceMappingURL=([^\s'\"*)]+)/g, test: v => !/^data:/.test(v), info: true },
    { id: 'internal-host', desc: 'Internal / staging host', re: /https?:\/\/[a-z0-9.-]*(?:[.-](?:staging|stage|stg|dev|internal|uat|preprod|sandbox|qa)(?=[.-]|\b)|(?:staging|stage|stg|dev|internal|uat|preprod|sandbox|qa)[.-])[a-z0-9.-]*[a-z0-9]/gi, info: true },
    { id: 'localhost', desc: 'localhost reference', re: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?[^\s\"'`)<]*/g },
    { id: 'private-ip', desc: 'Private IP address', re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, test: v => v.split('.').every(n => +n <= 255) },
    { id: 'cors', desc: 'CORS / credentials hint', re: /Access-Control-Allow-Origin|withCredentials\s*[:=]\s*(?:true|!0|1)\b|credentials\s*:\s*[\"']include[\"']/g },
    { id: 'jwt-handling', desc: 'JWT handling in client code', re: /\b(?:jwt[_-]?decode|jwtDecode|jsonwebtoken|jwt\.decode|parseJwt|decodeJwt)\b/gi },
    { id: 'token-storage', desc: 'Token stored in Web Storage', re: /(?:localStorage|sessionStorage)\.setItem\(\s*[\"'][^\"']*(?:token|jwt|auth|session|secret|passw|apikey|api_key)[^\"']*[\"']/gi }
  ];

  // version only from a banner comment or an exact file name match
  const LIBS = [
    {
      name: 'jQuery', key: 'jquery', banner: [/jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)/], file: [/jquery[.@-]v?(\d+\.\d+\.\d+)/i],
      issue: v => cmpVer(v, '3.5.0') < 0 && 'XSS in htmlPrefilter (CVE-2020-11022/11023), older: CVE-2019-11358 proto pollution'
    },
    { name: 'AngularJS', key: 'angularjs', banner: [/AngularJS v(\d+\.\d+\.\d+)/], file: [/angular(?:js)?[.@-]v?(1\.\d+\.\d+)/i], issue: () => 'AngularJS 1.x is EOL: check template injection / sandbox escapes' },
    { name: 'React', key: 'react', banner: [/@license React v(\d+\.\d+\.\d+)/, /\bReact v(\d+\.\d+\.\d+)/], file: [/react(?:-dom)?[.@-]v?(\d+\.\d+\.\d+)/i] },
    { name: 'Vue', key: 'vue', banner: [/Vue\.js v(\d+\.\d+\.\d+)/], file: [/vue[.@-]v?(\d+\.\d+\.\d+)/i] },
    {
      name: 'Lodash', key: 'lodash', banner: [/\bLodash\b[^\n]{0,40}?(\d+\.\d+\.\d+)/, /lodash\.com\/license[\s\S]{0,12000}?\bVERSION\s*=\s*['"](4\.\d+\.\d+)['"]/], file: [/lodash[.@-]v?(\d+\.\d+\.\d+)/i],
      issue: v => cmpVer(v, '4.17.21') < 0 && 'prototype pollution / command injection (CVE-2020-8203, CVE-2021-23337)'
    },
    {
      name: 'Moment', key: 'moment', banner: [/\/\/!\s*version\s*:\s*(\d+\.\d+\.\d+)/], file: [/moment[.@-]v?(\d+\.\d+\.\d+)/i],
      issue: v => cmpVer(v, '2.29.4') < 0 && 'ReDoS (CVE-2022-31129)'
    },
    {
      name: 'Bootstrap', key: 'bootstrap', banner: [/Bootstrap v(\d+\.\d+\.\d+)/], file: [/bootstrap[.@-]v?(\d+\.\d+\.\d+)/i],
      issue: v => (cmpVer(v, '3.4.1') < 0 || (v[0] === '4' && cmpVer(v, '4.3.1') < 0)) && 'XSS in tooltip/data-template (CVE-2019-8331)'
    }
  ];

  // ---------- secrets / public identifiers ----------

  function secretsPass(code, add, inComment) {
    const used = new Set();
    const firebasePos = [];
    for (const r of PUBLIC) {
      eachMatch(r.re, code, m => {
        const val = m[0];
        if (r.id === 'firebase') firebasePos.push(m.index);
        if (r.id === 'gapi' && firebasePos.some(p => Math.abs(p - m.index) < 700)) return;
        add({ rule: 'public-' + r.id, desc: 'Public identifier (check restrictions): ' + r.name, category: PUB, severity: 'Info', confidence: 'High', pos: m.index, len: val.length, value: r.id === 'firebase' ? '' : val });
        used.add(val);
      });
    }
    for (const r of SECRETS) {
      eachMatch(r.re, code, m => {
        const val = r.val ? r.val(m) : (m[1] || m[0]);
        if (PLACEHOLDER.test(val)) return;
        let desc = r.name, sev = r.sev, conf = r.conf || 'High';
        if (r.special === 'jwt') {
          const parts = m[0].split('.');
          const h = jsonB64(parts[0]), p = jsonB64(parts[1]);
          if (!h || typeof h.alg !== 'string' || !p || typeof p !== 'object') return;
          if (p.role === 'anon' || p.role === 'anon_key') {
            add({ rule: 'public-jwt-anon', desc: 'Public identifier (check restrictions): anon JWT (role=' + p.role + ')', category: PUB, severity: 'Info', confidence: 'High', pos: m.index, len: m[0].length, value: m[0] });
            return;
          }
          if (typeof p.exp === 'number') desc += ' (exp ' + new Date(p.exp * 1000).toISOString().slice(0, 10) + (p.exp * 1000 < Date.now() ? ', expired' : '') + ')';
        } else if (r.special === 'basic') {
          let dec = '';
          try { dec = b64dec(m[1]); } catch (e) { return; }
          const i = dec.indexOf(':');
          if (i < 1 || !/^[\x20-\x7e]+$/.test(dec) || PLACEHOLDER.test(dec) || i === dec.length - 1) return;
        } else if (r.special === 'generic') {
          if (used.has(val) || inComment(m.index)) return;
          if (/^(?:https?:|\/|\.)/.test(val) || /^[A-Za-z]+(?:[._\- ][A-Za-z]+)+$/.test(val) || /^[a-z]+(?:[A-Z][a-z]+)+$/.test(val)) return;
          if (/[{}$]/.test(val) || /^(?:true|false|null|undefined|function|object|string)$/.test(val)) return;
          if (entropy(val) < 3.5) return;
          const classes = (/[a-z]/.test(val) ? 1 : 0) + (/[A-Z]/.test(val) ? 1 : 0) + (/\d/.test(val) ? 1 : 0) + (/[^A-Za-z0-9]/.test(val) ? 1 : 0);
          if (classes < 2) return;
        }
        used.add(val);
        add({ rule: 'secret-' + r.id, desc, category: SEC, severity: sev, confidence: conf, pos: m.index, len: m[0].length, value: val });
      });
    }
  }

  // ---------- AST helpers ----------

  const isFn = n => n && (n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression');
  const isFnAny = n => n && (isFn(n) || n.type === 'FunctionDeclaration');

  function dotted(n) {
    if (!n) return null;
    if (n.type === 'Identifier') return n.name;
    if (n.type === 'ThisExpression') return 'this';
    if (n.type === 'MemberExpression') {
      const o = dotted(n.object);
      if (o === null) return null;
      if (!n.computed) return o + '.' + n.property.name;
      if (n.property.type === 'Literal' && typeof n.property.value === 'string') return o + '.' + n.property.value;
    }
    return null;
  }

  function propName(m) {
    if (!m.computed) return m.property.name;
    return m.property.type === 'Literal' && typeof m.property.value === 'string' ? m.property.value : null;
  }

  function isConst(n) {
    switch (n.type) {
      case 'Literal': return true;
      case 'TemplateLiteral': return n.expressions.length === 0;
      case 'BinaryExpression': case 'LogicalExpression': return isConst(n.left) && isConst(n.right);
      case 'UnaryExpression': return isConst(n.argument);
      case 'ConditionalExpression': return isConst(n.consequent) && isConst(n.alternate);
    }
    return false;
  }
  const isDynamic = n => !(isConst(n) || isFn(n) || (n.type === 'Identifier' && n.name === 'undefined'));

  function constStr(n) {
    if (n.type === 'Literal' && (typeof n.value === 'string' || typeof n.value === 'number')) return String(n.value);
    if (n.type === 'TemplateLiteral' && n.expressions.length === 0) return n.quasis[0].value.cooked || '';
    return null;
  }

  // flatten a + b + (c + d) into its operands, in order, without recursion
  function flatPlus(n) {
    const out = [], stack = [n];
    while (stack.length) {
      const x = stack.pop();
      if (x.type === 'BinaryExpression' && x.operator === '+') { stack.push(x.right); stack.push(x.left); } else out.push(x);
    }
    return out;
  }
  function tplParts(n) {
    const out = [];
    n.quasis.forEach((q, i) => {
      if (q.value.cooked) out.push({ s: q.value.cooked });
      if (i < n.expressions.length) out.push(n.expressions[i]);
    });
    return out;
  }

  function bindNames(p, out) {
    if (!p) return;
    switch (p.type) {
      case 'Identifier': out.push(p.name); break;
      case 'ObjectPattern': for (const q of p.properties) bindNames(q.type === 'RestElement' ? q.argument : q.value, out); break;
      case 'ArrayPattern': for (const q of p.elements) bindNames(q, out); break;
      case 'AssignmentPattern': bindNames(p.left, out); break;
      case 'RestElement': bindNames(p.argument, out); break;
    }
  }

  function each(n, fn) {
    for (const k in n) {
      if (k === 'type' || k === 'start' || k === 'end') continue;
      const v = n[k];
      if (!v || typeof v !== 'object') continue;
      if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === 'string') fn(c); }
      else if (typeof v.type === 'string') fn(v);
    }
  }
  function walk(n, fn) { fn(n); each(n, c => walk(c, fn)); }
  function walkP(n, parent, fn) { fn(n, parent); each(n, c => walkP(c, n, fn)); }

  const isCreateScript = n => n && n.type === 'CallExpression' && n.callee.type === 'MemberExpression' &&
    propName(n.callee) === 'createElement' && n.arguments[0] && n.arguments[0].type === 'Literal' && n.arguments[0].value === 'script';

  // ---------- taint model ----------
  // T = { c: chain text, p: cannot be proven to start with "<", us: start (scheme/host) is attacker controlled, x: crossed a function }
  const T = (c, p, us) => ({ c, p: !!p, us: !!us, x: false });
  const chainTo = (t, name) => (t === name || t.endsWith(' -> ' + name) ? t : t + ' -> ' + name);
  const ext = (t, name) => ({ c: chainTo(t.c, name), p: t.p, us: t.us, x: t.x });
  const mod = (t, o) => Object.assign({}, t, o);

  const SANITIZE_EXACT = /^(?:encodeURIComponent|encodeURI|escape|parseInt|parseFloat|Number|Boolean|isNaN|btoa|toFixed|abs|floor|ceil|round)$/;
  const SANITIZE_FUZZY = /(?<!un)escape|sanitiz|purif|encodeHTML|encodeHtml|htmlEncode|stripTags|stripHtml|textContent/i;
  const isSanitizer = nm => SANITIZE_EXACT.test(nm) || SANITIZE_FUZZY.test(nm);
  const DECODE_KEEP = new Set(['decodeURIComponent', 'decodeURI', 'unescape']);
  const PASS = new Set(['slice', 'substring', 'substr', 'split', 'replace', 'replaceAll', 'trim', 'trimStart', 'trimEnd', 'trimLeft', 'trimRight',
    'toLowerCase', 'toUpperCase', 'toLocaleLowerCase', 'toLocaleUpperCase', 'concat', 'join', 'match', 'matchAll', 'toString', 'valueOf', 'at',
    'charAt', 'padStart', 'padEnd', 'repeat', 'normalize', 'get', 'getAll', 'pop', 'shift', 'flat', 'filter', 'reverse', 'sort', 'find', 'values',
    'entries', 'keys', 'toJSON', 'item']);
  const KEEP_METHODS = new Set(['toString', 'valueOf']);
  const GLOBAL_FNS = { JSON: ['parse', 'stringify'], Object: ['assign', 'keys', 'values', 'entries', 'fromEntries'], Array: ['from', 'of'],
    $: ['extend', 'parseJSON', 'param', 'deparam', 'parseParams'], jQuery: ['extend', 'parseJSON', 'param', 'deparam'], _: ['merge', 'cloneDeep', 'clone', 'toString'],
    lodash: ['merge', 'cloneDeep', 'clone'], qs: ['parse'], Qs: ['parse'], queryString: ['parse'], querystring: ['parse'] };
  const JQ_NAME = /^(?:\$|jQuery|jquery|\$[\w$]*)$/;
  const CB_METHODS = new Set(['map', 'flatMap', 'reduce', 'reduceRight', 'forEach']);
  const GUARD_METHODS = new Set(['test', 'match', 'includes', 'indexOf', 'lastIndexOf', 'startsWith', 'endsWith', 'has', 'exec', 'search']);
  const SENSITIVE = /token|cookie|session|auth|secret|passw|jwt|credential|csrf|location/i;

  // true if the constant prefix pins the request/navigation target (scheme+host or same-origin path)
  function pinnedPrefix(pre) {
    if (!pre) return false;
    if (/^https?:\/\/[^\/?#\\]+[\/?#]/i.test(pre)) return true;
    if (/^\/[^\/\\]/.test(pre)) return true;
    if (/^[?#]/.test(pre)) return true;
    if (/^[A-Za-z0-9_.~-]+[\/?#]/.test(pre)) return true;
    return false;
  }

  function astScan(ast, env) {
    const code = env.code;
    const AMBIG = {};
    const reg = new Map();      // key -> fn node | AMBIG
    const infos = new Map();    // fn node -> { name, paramT, ret }
    const msgFns = new Map();   // handler fn -> { checked, dataNames }
    const mergeFns = new Map(); // fn node -> display name
    const calledTainted = new Set();
    const globals = new Map();  // window.x -> T (persistent over rounds)
    let seeds = new Map(), nextSeeds = new Map();
    let out = [], cout = [], changed = false;
    let done = new WeakSet();
    let guardStack = [];
    let root = null;

    const info = f => { let i = infos.get(f); if (!i) { i = { name: '', paramT: [], ret: null }; infos.set(f, i); } return i; };
    const regGet = k => { const v = k ? reg.get(k) : null; return v && v !== AMBIG ? v : null; };

    // ----- pre-pass: function registry, message handlers, merge functions -----
    function register(key, f) {
      if (!key) return;
      reg.set(key, reg.has(key) ? AMBIG : f);
      const i = info(f);
      if (!i.name) i.name = key.split('.').pop();
    }
    walk(ast, n => {
      switch (n.type) {
        case 'FunctionDeclaration': if (n.id) register(n.id.name, n); break;
        case 'VariableDeclarator':
          if (n.id.type === 'Identifier' && n.init) {
            if (isFn(n.init)) register(n.id.name, n.init);
            else if (n.init.type === 'ObjectExpression') {
              for (const p of n.init.properties) {
                const k = p.type === 'Property' && !p.computed && p.key && (p.key.name || p.key.value);
                if (k && isFn(p.value)) register(n.id.name + '.' + k, p.value);
              }
            }
          }
          break;
        case 'AssignmentExpression': if (isFn(n.right)) { const d = dotted(n.left); if (d) register(d, n.right); } break;
        case 'MethodDefinition': {
          const k = !n.computed && n.key && (n.key.name || n.key.value);
          if (k && n.kind === 'method') register('this.' + k, n.value);
          break;
        }
      }
    });

    function fnRef(x) {
      if (!x) return null;
      if (isFn(x)) return x;
      if (x.type === 'Identifier') return regGet(x.name);
      if (x.type === 'MemberExpression') return regGet(dotted(x));
      if (x.type === 'CallExpression' && x.callee.type === 'MemberExpression' && propName(x.callee) === 'bind') return fnRef(x.callee.object);
      return null;
    }

    function analyzeHandler(f) {
      const res = { checked: false, dataNames: [] };
      const p0 = f.params[0];
      if (!p0) { res.checked = true; return res; }
      if (p0.type === 'ObjectPattern') {
        for (const q of p0.properties) {
          if (q.type !== 'Property' || q.computed || !q.key) continue;
          const k = q.key.name || q.key.value;
          if (k === 'origin' || k === 'source') res.checked = true;
          if (k === 'data' && q.value.type === 'Identifier') res.dataNames.push(q.value.name);
        }
        return res;
      }
      if (p0.type !== 'Identifier') { res.checked = true; return res; }
      const ev = p0.name;
      res.ev = ev;
      walkP(f.body, null, (n, parent) => {
        if (n.type === 'MemberExpression') {
          const d = dotted(n);
          if (d && new RegExp('^' + ev.replace(/\$/g, '\\$') + '(?:\\.originalEvent)?\\.(?:origin|source)$').test(d)) res.checked = true;
        }
        if (n.type === 'Identifier' && n.name === ev && parent) {
          if (parent.type === 'MemberExpression' && parent.object === n) return;
          if (parent.type === 'VariableDeclarator' && parent.init === n && parent.id.type === 'ObjectPattern') {
            for (const q of parent.id.properties) {
              if (q.type !== 'Property' || q.computed || !q.key) continue;
              const k = q.key.name || q.key.value;
              if (k === 'origin' || k === 'source') res.checked = true;
              if (k === 'data' && q.value.type === 'Identifier') res.dataNames.push(q.value.name);
            }
            return;
          }
          if (parent.type === 'Property' && parent.key === n && !parent.computed) return;
          res.checked = true; // the event escapes (passed on / stored): origin may be checked elsewhere
        }
      });
      return res;
    }

    walk(ast, n => {
      if (n.type === 'CallExpression') {
        const c = n.callee, a = n.arguments;
        const nm = c.type === 'Identifier' ? c.name : c.type === 'MemberExpression' ? propName(c) : null;
        if ((nm === 'addEventListener' || nm === 'on') && a[0] && a[0].type === 'Literal' && a[0].value === 'message' && a[1]) {
          const f = fnRef(a[1]);
          if (f && !msgFns.has(f)) msgFns.set(f, analyzeHandler(f));
        }
      } else if (n.type === 'AssignmentExpression') {
        const L = n.left;
        if ((L.type === 'Identifier' && L.name === 'onmessage') || (L.type === 'MemberExpression' && propName(L) === 'onmessage')) {
          const f = fnRef(n.right);
          if (f && !msgFns.has(f)) msgFns.set(f, analyzeHandler(f));
        }
      }
    });

    function isMergeFn(f) {
      if (f.params.length < 2) return false;
      const names = new Set();
      const nm = info(f).name;
      if (nm) names.add(nm);
      if (f.id) names.add(f.id.name);
      if (!names.size) return false;
      let loop = false, keyAssign = false, selfCall = false, guard = false;
      walk(f.body, n => {
        switch (n.type) {
          case 'ForInStatement': case 'ForOfStatement': case 'ForStatement': case 'WhileStatement': loop = true; break;
          case 'AssignmentExpression':
            if (n.left.type === 'MemberExpression' && n.left.computed && n.left.property.type !== 'Literal') keyAssign = true;
            break;
          case 'CallExpression': {
            const c = n.callee;
            if (c.type === 'Identifier' && names.has(c.name)) selfCall = true;
            else if (c.type === 'MemberExpression') {
              const pn = propName(c);
              if (pn && names.has(pn)) selfCall = true;
              if (pn === 'keys' || pn === 'entries' || pn === 'forEach') loop = true;
              if (dotted(c) === 'arguments.callee') selfCall = true;
            }
            break;
          }
          case 'Literal': if (typeof n.value === 'string' && /^(?:__proto__|constructor|prototype)$/.test(n.value)) guard = true; break;
          case 'Identifier': if (n.name === '__proto__') guard = true; break;
        }
      });
      return loop && keyAssign && selfCall && !guard;
    }
    walk(ast, n => {
      if (isFnAny(n) && !mergeFns.has(n) && isMergeFn(n)) mergeFns.set(n, info(n).name || (n.id && n.id.name) || 'merge');
    });

    // ----- scopes -----
    const newScope = (parent, fnode) => ({ vars: new Map(), props: new Map(), parent, scripts: new Set(), jq: new Set(), msg: new Map(), fnNames: new Set(), fnode, isRoot: !parent });
    const lookupVar = (sc, name) => { for (let s = sc; s; s = s.parent) if (s.vars.has(name)) return s.vars.get(name); return null; };
    const scopeOf = (sc, name) => { for (let s = sc; s; s = s.parent) if (s.vars.has(name)) return s; return null; };
    const lookupMsg = (sc, name) => { for (let s = sc; s; s = s.parent) { if (s.msg.has(name)) return s.msg.get(name); if (s.vars.has(name)) return null; } return null; };
    const hasSet = (sc, key, n) => { for (let s = sc; s; s = s.parent) if (s[key].has(n)) return true; return false; };
    function setVar(sc, name, v) {
      const s = scopeOf(sc, name) || root;
      s.vars.set(name, v);
      s.props.delete(name);
    }
    function shadowed(sc, name) {
      for (let s = sc; s && !s.isRoot; s = s.parent) if (s.vars.has(name) && !s.fnNames.has(name)) return true;
      return false;
    }
    function resolveFn(callee, sc) {
      if (callee.type === 'Identifier') return shadowed(sc, callee.name) ? null : regGet(callee.name);
      if (callee.type === 'MemberExpression') return regGet(dotted(callee));
      return null;
    }

    // ----- taint evaluation -----
    function srcOf(n, sc) {
      const d = dotted(n);
      if (!d) return null;
      const s = d.replace(/^(?:window|self|top|parent|globalThis)\./, '').replace(/^document\.location\./, 'location.');
      const win = s !== d;
      let m = /^location\.(hash|search|href|pathname)$/.exec(s);
      if (m) return T(s, true, m[1] === 'pathname');
      if (/^document\.(?:URL|documentURI|baseURI)$/.test(s)) return T(s, true, false);
      if (s === 'document.referrer') return T(s, true, true);
      if (s === 'document.cookie') return T(s, false, true);
      if (/^(?:local|session)Storage\.(?!getItem$|setItem$|removeItem$|clear$|key$|length$)\w+$/.test(s)) return T(s, false, true);
      if (win && s === 'name') return T('window.name', false, true);
      if (win && /^opener(?:\.|$)/.test(s)) return T('window.opener', false, true);
      const parts = s.split('.');
      if ((parts.length === 2 && parts[1] === 'data') || (parts.length === 3 && parts[1] === 'originalEvent' && parts[2] === 'data')) {
        const h = lookupMsg(sc, parts[0]);
        if (h && !h.checked) return T('postMessage.data', false, true);
      }
      return null;
    }

    function concatInfo(parts, sc) {
      let pre = '', decided = false, startKind = 'const', startT = null, anyT = null;
      for (const part of parts) {
        const cs = part.s !== undefined ? part.s : constStr(part);
        if (cs !== null) { if (!decided) pre += cs; continue; }
        const t = taintOf(part, sc);
        if (t && !anyT) anyT = t;
        if (!decided) { decided = true; startKind = t ? 'taint' : 'unknown'; startT = t; }
      }
      return { pre, startKind, startT, anyT };
    }
    function concatTaint(parts, sc) {
      const ci = concatInfo(parts, sc);
      if (!ci.anyT) return null;
      const lt = (ci.pre === '' && ci.startKind === 'taint' && !ci.startT.p) || (/^\s*</.test(ci.pre) && !!ci.anyT);
      const us = ci.startKind === 'taint' && !pinnedPrefix(ci.pre) && ci.startT.us;
      return { c: ci.anyT.c, p: !lt, us, x: ci.anyT.x };
    }

    function taintOf(n, sc) {
      if (!n) return null;
      switch (n.type) {
        case 'Identifier': {
          const v = lookupVar(sc, n.name);
          if (v) return v;
          const s = scopeOf(sc, n.name);
          const pm = s && s.props.get(n.name);
          if (pm && pm.size) return pm.values().next().value;
          return null;
        }
        case 'MemberExpression': {
          const s = srcOf(n, sc);
          if (s) return s;
          const d = dotted(n);
          if (d && /^window\./.test(d) && globals.has(d)) return globals.get(d);
          const pn = propName(n);
          if (!n.computed && pn === 'length') return null;
          if (!n.computed && n.object.type === 'Identifier') {
            const sco = scopeOf(sc, n.object.name);
            const pm = sco && sco.props.get(n.object.name);
            if (pm) return pm.has(pn) ? pm.get(pn) : null;
          }
          return taintOf(n.object, sc);
        }
        case 'TemplateLiteral': return n.expressions.length ? concatTaint(tplParts(n), sc) : null;
        case 'BinaryExpression': return n.operator === '+' ? concatTaint(flatPlus(n), sc) : null;
        case 'LogicalExpression': return taintOf(n.left, sc) || taintOf(n.right, sc);
        case 'ConditionalExpression': {
          const a = taintOf(n.consequent, sc), b = taintOf(n.alternate, sc);
          if (a && b) return { c: a.c, p: a.p && b.p, us: a.us || b.us, x: a.x || b.x };
          return a || b;
        }
        case 'AssignmentExpression': return n.operator === '=' ? taintOf(n.right, sc) : null;
        case 'SequenceExpression': return taintOf(n.expressions[n.expressions.length - 1], sc);
        case 'AwaitExpression': case 'SpreadElement': return taintOf(n.argument, sc);
        case 'ChainExpression': return taintOf(n.expression, sc);
        case 'ArrayExpression': for (const e of n.elements) { const t = e && taintOf(e, sc); if (t) return mod(t, { p: false }); } return null;
        case 'ObjectExpression': for (const p of n.properties) { const t = taintOf(p.value || p.argument, sc); if (t) return mod(t, { p: false }); } return null;
        case 'CallExpression': case 'NewExpression': return callTaint(n, sc);
      }
      return null;
    }

    function fnOfArg(x, sc) { return isFn(x) ? x : x && x.type === 'Identifier' ? (shadowed(sc, x.name) ? null : regGet(x.name)) : null; }
    function retOf(F) {
      const r = info(F).ret;
      return r ? { c: chainTo(r.c, (info(F).name || 'fn') + '()'), p: r.p, us: r.us, x: true } : null;
    }

    function callTaint(n, sc) {
      const c = n.callee, a = n.arguments, isNew = n.type === 'NewExpression';
      const nm = c.type === 'Identifier' ? c.name : c.type === 'MemberExpression' ? propName(c) : null;
      if (nm && isSanitizer(nm)) return null;
      if (c.type === 'Identifier') {
        if (isNew) {
          if (/^(?:URL|URLSearchParams|String|Array|FormData)$/.test(nm)) { for (const x of a) { const t = taintOf(x, sc); if (t) return mod(t, { p: false, us: nm === 'String' ? t.us : true }); } }
          return null;
        }
        if (DECODE_KEEP.has(nm)) return taintOf(a[0], sc);
        if (nm === 'atob' || nm === 'String') { const t = taintOf(a[0], sc); return t && mod(t, { p: false, us: true }); }
        const F = resolveFn(c, sc);
        return F ? retOf(F) : null;
      }
      if (c.type !== 'MemberExpression') return null;
      const od = dotted(c.object) || '';
      if (nm === 'getItem' && /^(?:window\.)?(?:local|session)Storage$/.test(od)) return T(od.replace(/^window\./, '') + '.getItem()', false, true);
      if (Object.prototype.hasOwnProperty.call(GLOBAL_FNS, od) && GLOBAL_FNS[od].includes(nm)) {
        for (const x of a) { const t = taintOf(x, sc); if (t) return mod(t, { p: false, us: true }); }
        return null;
      }
      const F = resolveFn(c, sc);
      if (F) return retOf(F);
      if ((nm === 'map' || nm === 'flatMap' || nm === 'reduce') && a[0]) {
        const cb = fnOfArg(a[0], sc);
        return cb ? (retOf(cb) && mod(retOf(cb), { p: false })) : null;
      }
      const to = taintOf(c.object, sc);
      if (to && PASS.has(nm)) return KEEP_METHODS.has(nm) ? to : mod(to, { p: false, us: true });
      if (nm === 'replace' || nm === 'replaceAll' || nm === 'padStart' || nm === 'padEnd') { const t = a[1] && taintOf(a[1], sc); if (t) return mod(t, { p: false, us: false }); }
      if (nm === 'concat') for (const x of a) { const t = taintOf(x, sc); if (t) return mod(t, { p: false, us: false }); }
      if (nm === 'exec') { const t = a[0] && taintOf(a[0], sc); if (t) return mod(t, { p: false, us: true }); }
      return null;
    }

    // taint whose beginning (scheme/host) is attacker controlled and not pinned by a constant prefix
    function urlHit(n, sc) {
      switch (n.type) {
        case 'BinaryExpression': {
          if (n.operator !== '+') return null;
          const ci = concatInfo(flatPlus(n), sc);
          return ci.startKind === 'taint' && ci.startT.us && !pinnedPrefix(ci.pre) ? ci.startT : null;
        }
        case 'TemplateLiteral': {
          if (!n.expressions.length) return null;
          const ci = concatInfo(tplParts(n), sc);
          return ci.startKind === 'taint' && ci.startT.us && !pinnedPrefix(ci.pre) ? ci.startT : null;
        }
        case 'ConditionalExpression': return urlHit(n.consequent, sc) || urlHit(n.alternate, sc);
        case 'LogicalExpression': return urlHit(n.left, sc) || urlHit(n.right, sc);
        case 'AssignmentExpression': return urlHit(n.right, sc);
        case 'SequenceExpression': return urlHit(n.expressions[n.expressions.length - 1], sc);
        default: { const t = taintOf(n, sc); return t && t.us ? t : null; }
      }
    }
    const ltHit = (n, sc) => { const t = taintOf(n, sc); return t && !t.p ? t : null; };

    // ----- guards (validation checks around a sink demote it to a candidate) -----
    function collectNames(n, outSet) {
      if (!n) return;
      if (n.type === 'Identifier') { outSet.add(n.name); return; }
      if (n.type === 'MemberExpression') { const d = dotted(n); if (d) outSet.add(d); }
      each(n, c => collectNames(c, outSet));
    }
    function guardNames(test, outSet) {
      walk(test, n => {
        if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && GUARD_METHODS.has(propName(n.callee))) {
          collectNames(n.callee.object, outSet);
          for (const x of n.arguments) collectNames(x, outSet);
        } else if (n.type === 'BinaryExpression' && /^(?:===|!==|==|!=)$/.test(n.operator)) {
          if (isConst(n.right)) collectNames(n.left, outSet);
          else if (isConst(n.left)) collectNames(n.right, outSet);
        }
      });
    }
    const exits = s => !!s && (s.type === 'ReturnStatement' || s.type === 'ThrowStatement' || s.type === 'ContinueStatement' || s.type === 'BreakStatement' ||
      (s.type === 'BlockStatement' && s.body.length && exits(s.body[s.body.length - 1])));
    function isGuarded(arg) {
      if (!arg || !guardStack.length) return false;
      const names = new Set();
      collectNames(arg, names);
      for (const g of guardStack) for (const nm of names) if (g.has(nm)) return true;
      return false;
    }

    // ----- emitting -----
    function hit(cat, sev, at, label, t, arg, opt) {
      opt = opt || {};
      const pm = /^postMessage/.test(t.c);
      const o = {
        rule: (pm ? 'pm-' : '') + label, desc: opt.desc || (pm ? 'Message listener without origin check: data reaches ' + label : label + ' sink'),
        category: pm ? PM : cat, severity: sev, confidence: t.x ? 'Medium' : 'High', pos: at.start,
        len: Math.min(at.end - at.start, 160), chain: t.c + ' -> ' + label, lib: opt.lib || ''
      };
      if (arg && isGuarded(arg)) { o.confidence = 'Low'; o.desc += ' (guarded by a validation check)'; o.why = 'guarded'; cout.push(o); } else out.push(o);
    }
    function sinkHtml(cat, sev, at, arg, sc, label) {
      if (!arg) return;
      const t = taintOf(arg, sc);
      if (t) return hit(cat, sev, at, label, t, arg);
      if (isDynamic(arg)) cout.push({ rule: 'dyn-' + label, desc: 'Dynamic ' + label + ' (no proven source)', category: cat, severity: lower(sev), confidence: 'Low', pos: at.start, len: 80, why: 'untainted-dynamic' });
    }
    function sinkUrl(cat, sev, at, arg, sc, label) {
      if (!arg) return;
      const t = urlHit(arg, sc);
      if (t) hit(cat, sev, at, label, t, arg);
    }
    function pmState(t, at, label) { if (t && /^postMessage/.test(t.c)) hit(PM, 'Medium', at, label, t, null); }

    // ----- jQuery receiver -----
    function isJq(n, sc) {
      while (n) {
        if (n.type === 'CallExpression') {
          const c = n.callee;
          if (c.type === 'Identifier') return JQ_NAME.test(c.name) || hasSet(sc, 'jq', c.name);
          if (c.type === 'MemberExpression') { n = c.object; continue; }
          return false;
        }
        if (n.type === 'MemberExpression') {
          if (!n.computed && n.property.name && n.property.name[0] === '$') return true;
          n = n.object; continue;
        }
        if (n.type === 'Identifier') return JQ_NAME.test(n.name) || hasSet(sc, 'jq', n.name);
        return false;
      }
      return false;
    }

    // ----- visiting -----
    function visitFn(f, sc) {
      if (done.has(f)) return;
      done.add(f);
      const inf = info(f), s = newScope(sc, f);
      const sd = seeds.get(f);
      if (sd) for (const [k, v] of sd) s.vars.set(k, v);
      if (f.body && f.body.type === 'BlockStatement') for (const st of f.body.body) if (st.type === 'FunctionDeclaration' && st.id) s.fnNames.add(st.id.name);
      const h = msgFns.get(f);
      f.params.forEach((p, i) => {
        const names = [];
        bindNames(p, names);
        const pt = inf.paramT[i];
        for (const nm of names) {
          s.vars.set(nm, pt ? { c: chainTo(pt.c, (inf.name || 'fn') + '(' + nm + ')'), p: pt.p, us: pt.us, x: true } : null);
          if (h && i === 0 && p.type === 'Identifier') s.msg.set(nm, { checked: h.checked });
        }
      });
      if (h && !h.checked) for (const nm of h.dataNames) s.vars.set(nm, T('postMessage.data', false, true));
      if (f.body.type !== 'BlockStatement') {
        visit(f.body, s);
        const t = taintOf(f.body, s);
        if (t && !inf.ret) { inf.ret = mod(t, { x: true }); changed = true; }
      } else visit(f.body, s);
      saveSeeds(f, s);
    }
    function saveSeeds(key, s) {
      let m = null;
      for (const [k, v] of s.vars) if (v) { (m = m || new Map()).set(k, v); }
      if (m) {
        nextSeeds.set(key, m);
        const old = seeds.get(key);
        if (!old || old.size !== m.size) changed = true;
        else for (const k of m.keys()) if (!old.has(k)) { changed = true; break; }
      }
    }

    function bind(p, t, sc) {
      const names = [];
      bindNames(p, names);
      for (const nm of names) sc.vars.set(nm, t ? ext(t, nm) : null);
    }

    function setProps(sc, name, objExpr) {
      let pm = null;
      for (const p of objExpr.properties) {
        if (p.type === 'SpreadElement') { const t = taintOf(p.argument, sc); if (t) { sc.vars.set(name, ext(t, name)); return; } continue; }
        const k = p.type === 'Property' && !p.computed && p.key && (p.key.name !== undefined ? p.key.name : p.key.value);
        if (k === false || k === null || k === undefined) continue;
        const t = taintOf(p.value, sc);
        if (t) (pm = pm || new Map()).set(String(k), ext(t, name + '.' + k));
      }
      sc.vars.set(name, null);
      if (pm) sc.props.set(name, pm);
    }

    function storeMember(L, t, sc) {
      const d = dotted(L);
      if (d && /^window\./.test(d) && !/^window\.location/.test(d)) { if (t) globals.set(d, t); else globals.delete(d); return; }
      if (L.object.type !== 'Identifier') return;
      const name = L.object.name, p = propName(L);
      const s = scopeOf(sc, name) || root;
      if (!L.computed && p) {
        let pm = s.props.get(name);
        if (t) { if (!pm) { pm = new Map(); s.props.set(name, pm); } pm.set(p, ext(t, name + '.' + p)); }
        else if (pm) pm.delete(p);
      } else if (t) { s.vars.set(name, ext(t, name)); }
    }

    function sinkAssign(L, R, sc) {
      const p = propName(L);
      if (!p) return;
      const full = (dotted(L) || '').replace(/^(?:window|self|top|parent)\./, '').replace(/^document\.location/, 'location');
      const at = L.property;
      if (full === 'location' || full === 'location.href') return sinkUrl(NAV, 'High', at, R, sc, full);
      if (full === 'document.cookie') { pmState(taintOf(R, sc), at, 'document.cookie'); return; }
      if (/^(?:local|session)Storage\./.test(full)) { pmState(taintOf(R, sc), at, full); return; }
      switch (p) {
        case 'innerHTML': case 'outerHTML': return sinkHtml(XSS, 'High', at, R, sc, p);
        case 'srcdoc': return sinkHtml(XSS, 'High', at, R, sc, 'iframe.srcdoc');
        case 'src': case 'text': case 'textContent': case 'innerText': {
          const o = L.object;
          const script = o.type === 'Identifier' && (hasSet(sc, 'scripts', o.name) || /script/i.test(o.name));
          if (script) return p === 'src' ? sinkUrl(XSS, 'High', at, R, sc, 'script.src') : sinkHtml(XSS, 'High', at, R, sc, 'script.' + p);
          if (p === 'src') return sinkUrl(OTH, 'Medium', at, R, sc, 'element.src');
          return;
        }
        case 'href': return sinkUrl(OTH, 'Medium', at, R, sc, 'element.href');
        case 'action': case 'formAction': case 'formaction': return sinkUrl(NAV, 'Medium', at, R, sc, 'form.' + p);
      }
      if (/^window\./.test(dotted(L) || '')) pmState(taintOf(R, sc), at, dotted(L));
    }

    function assign(n, sc) {
      const L = n.left, R = n.right;
      if (L.type === 'Identifier') {
        if (L.name === 'location' && n.operator === '=') sinkUrl(NAV, 'High', L, R, sc, 'location');
        let t = n.operator === '=' || n.operator === '+=' ? taintOf(R, sc) : null;
        if (!t && n.operator === '+=') t = lookupVar(sc, L.name);
        setVar(sc, L.name, t ? ext(t, L.name) : null);
        if (isCreateScript(R)) sc.scripts.add(L.name);
        if (isJq(R, sc) && R.type === 'CallExpression') sc.jq.add(L.name);
        if (R.type === 'ObjectExpression' && n.operator === '=') { const s = scopeOf(sc, L.name) || root; setProps(s, L.name, R); }
      } else if (L.type === 'MemberExpression') {
        sinkAssign(L, R, sc);
        storeMember(L, n.operator === '=' || n.operator === '+=' ? taintOf(R, sc) : null, sc);
      } else if (L.type === 'ObjectPattern' || L.type === 'ArrayPattern') {
        bind(L, taintOf(R, sc), sc);
      }
    }

    function setParam(F, idx, t) {
      const inf = info(F);
      if (idx >= F.params.length) {
        const last = F.params[F.params.length - 1];
        if (last && last.type === 'RestElement') idx = F.params.length - 1; else return;
      }
      if (!inf.paramT[idx]) { inf.paramT[idx] = t; changed = true; }
    }

    function ppLib(n, p, od, a, sc) {
      const isJqObj = od === '$' || od === 'jQuery';
      if (p === 'extend' && isJqObj && a[0] && a[0].type === 'Literal' && a[0].value === true) {
        for (let i = 1; i < a.length; i++) { const t = taintOf(a[i], sc); if (t) return hit(PP, 'Medium', n, od + '.extend(deep)', t, null, { lib: 'jquery', desc: 'Prototype pollution: deep ' + od + '.extend() merges tainted data' }); }
      }
      if ((od === '_' || od === 'lodash') && /^(?:merge|mergeWith|defaultsDeep)$/.test(p)) {
        for (let i = 1; i < a.length; i++) { const t = taintOf(a[i], sc); if (t) return hit(PP, 'Medium', n, od + '.' + p + '()', t, null, { lib: 'lodash', desc: 'Prototype pollution: ' + od + '.' + p + '() merges tainted data' }); }
      }
      if ((od === '_' || od === 'lodash') && p === 'set' && a[1]) {
        const t = taintOf(a[1], sc);
        if (t) hit(PP, 'Medium', n, od + '.set()', t, null, { lib: 'lodash', desc: 'Prototype pollution: ' + od + '.set() with a tainted path' });
      }
    }

    function call(n, sc) {
      const c = n.callee, a = n.arguments;
      // interprocedural: tainted arguments make parameters tainted
      const F = resolveFn(c, sc);
      if (F) {
        a.forEach((x, j) => { const t = taintOf(x, sc); if (t) setParam(F, j, t); });
        if (mergeFns.has(F)) {
          for (const x of a) {
            const t = taintOf(x, sc);
            if (t) { calledTainted.add(F); hit(PP, 'Medium', n, mergeFns.get(F) + '()', t, null, { desc: 'Prototype pollution: recursive merge "' + mergeFns.get(F) + '" has no __proto__/constructor guard and receives tainted data' }); break; }
          }
        }
      }
      if (c.type === 'Identifier') {
        switch (c.name) {
          case 'eval': case 'execScript': return sinkHtml(XSS, 'Critical', n, a[0], sc, c.name + '()');
          case 'Function': for (const x of a) { const t = taintOf(x, sc); if (t) return hit(XSS, 'Critical', n, 'Function()', t, x); } return;
          case 'setTimeout': case 'setInterval': {
            const x = a[0];
            if (!x || isFn(x) || (x.type === 'Identifier' && fnOfArg(x, sc))) return;
            const t = taintOf(x, sc);
            if (t) hit(XSS, 'Critical', n, c.name + '()', t, x);
            return;
          }
          case 'fetch': return sinkUrl(OTH, 'Medium', n, a[0], sc, 'fetch()');
          case '$': case 'jQuery': { const t = a[0] && ltHit(a[0], sc); if (t) hit(XSS, 'High', n, '$()', t, a[0]); return; }
          case 'open': return sinkUrl(NAV, 'Medium', n, a[0], sc, 'window.open()');
          case 'importScripts': return sinkUrl(XSS, 'Critical', n, a[0], sc, 'importScripts()');
        }
        return;
      }
      if (c.type !== 'MemberExpression') return;
      const p = propName(c), obj = c.object, od = dotted(obj) || '';
      if (!p) return;
      if (CB_METHODS.has(p) && a[0]) {
        const cb = fnOfArg(a[0], sc), to = taintOf(obj, sc);
        if (cb && to) setParam(cb, p === 'reduce' || p === 'reduceRight' ? 1 : 0, to);
      }
      ppLib(n, p, od, a, sc);
      switch (p) {
        case 'insertAdjacentHTML': return sinkHtml(XSS, 'High', n, a[1], sc, 'insertAdjacentHTML');
        case 'createContextualFragment': return sinkHtml(XSS, 'High', n, a[0], sc, 'createContextualFragment');
        case 'write': case 'writeln':
          if (/(?:^|\.)document$/.test(od)) {
            for (const x of a) { const t = taintOf(x, sc); if (t) return hit(XSS, 'High', n, 'document.' + p, t, x); }
            if (a[0]) sinkHtml(XSS, 'High', n, a[0], sc, 'document.' + p);
          }
          return;
        case 'setAttribute': {
          const k = a[0] && a[0].type === 'Literal' && typeof a[0].value === 'string' ? a[0].value.toLowerCase() : '';
          if (/^on/.test(k) || k === 'srcdoc') sinkHtml(XSS, 'High', n, a[1], sc, 'setAttribute(' + k + ')');
          else if (/^(?:href|src|action|formaction|data|xlink:href)$/.test(k)) sinkUrl(OTH, 'Medium', n, a[1], sc, 'setAttribute(' + k + ')');
          return;
        }
        case 'replace': case 'assign':
          if (od === 'location' || /^(?:window|self|top|parent|document)\.location$/.test(od)) sinkUrl(NAV, 'High', n, a[0], sc, 'location.' + p + '()');
          return;
        case 'open':
          if (/^(?:window|self|top|parent)$/.test(od)) sinkUrl(NAV, 'Medium', n, a[0], sc, 'window.open()');
          else if (a.length >= 2 && a[0].type === 'Literal' && /^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/i.test(a[0].value)) sinkUrl(OTH, 'Medium', n, a[1], sc, 'XMLHttpRequest.open');
          return;
        case 'setItem':
          if (/^(?:window\.)?(?:local|session)Storage$/.test(od) && a[1]) pmState(taintOf(a[1], sc), n, 'storage.setItem()');
          return;
        case 'postMessage': {
          const o = a[1];
          if (o && o.type === 'Literal' && o.value === '*' && a[0]) {
            const t = taintOf(a[0], sc);
            const txt = code.slice(a[0].start, Math.min(a[0].end, a[0].start + 300));
            if (t) hit(OTH, 'Medium', n, 'postMessage(*)', t, null, { desc: 'postMessage with "*" target origin sends tainted data' });
            else if (SENSITIVE.test(txt)) out.push({ rule: 'postmessage-star-sensitive', desc: 'postMessage with "*" target origin sends sensitive data', category: OTH, severity: 'Medium', confidence: 'Medium', pos: n.start, len: Math.min(n.end - n.start, 160), chain: 'sensitive data -> postMessage(*)' });
          }
          return;
        }
        case 'globalEval': if (isJq(obj, sc)) sinkHtml(XSS, 'Critical', n, a[0], sc, 'jQuery.globalEval()'); return;
        case 'parseHTML': if (isJq(obj, sc)) sinkHtml(XSS, 'High', n, a[0], sc, 'jQuery.parseHTML()'); return;
        case 'getScript': if (isJq(obj, sc)) sinkUrl(XSS, 'Critical', n, a[0], sc, 'jQuery.getScript()'); return;
        case 'load': if (isJq(obj, sc) && a[0] && !isFn(a[0])) sinkUrl(OTH, 'Medium', n, a[0], sc, 'jQuery.load()'); return;
        case 'get': case 'post': case 'getJSON': case 'ajax':
          if (od === '$' || od === 'jQuery') {
            const x = a[0];
            if (x && x.type === 'ObjectExpression') {
              const up = x.properties.find(q => q.type === 'Property' && !q.computed && q.key && (q.key.name === 'url' || q.key.value === 'url'));
              if (up) sinkUrl(OTH, 'Medium', n, up.value, sc, '$.' + p + '()');
            } else sinkUrl(OTH, 'Medium', n, x, sc, '$.' + p + '()');
          }
          return;
        case 'html': case 'append': case 'prepend': case 'before': case 'after': case 'replaceWith': case 'wrap': case 'wrapAll': case 'wrapInner': {
          if (!a.length || isFn(a[0]) || !isJq(obj, sc)) return;
          sinkHtml(XSS, 'High', n, a[0], sc, 'jQuery.' + p + '()');
          return;
        }
      }
      if (/^bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)$/.test(p)) sinkHtml(XSS, 'High', n, a[0], sc, p);
    }

    function block(n, sc) {
      const gs = new Set();
      guardStack.push(gs);
      for (const st of n.body) if (st.type === 'FunctionDeclaration' && st.id) sc.fnNames.add(st.id.name);
      for (const st of n.body) {
        visit(st, sc);
        if (st.type === 'IfStatement') {
          const g = new Set();
          guardNames(st.test, g);
          if (g.size && (exits(st.consequent) || (st.alternate && exits(st.alternate)))) for (const x of g) gs.add(x);
        }
      }
      guardStack.pop();
    }
    function guarded(test, fn) {
      const g = new Set();
      guardNames(test, g);
      guardStack.push(g);
      try { fn(); } finally { guardStack.pop(); }
    }

    function visit(n, sc) {
      switch (n.type) {
        case 'FunctionDeclaration': if (n.id) sc.fnNames.add(n.id.name); return visitFn(n, sc);
        case 'FunctionExpression': case 'ArrowFunctionExpression': return visitFn(n, sc);
        case 'Program': case 'BlockStatement': return block(n, sc);
        case 'IfStatement':
          visit(n.test, sc);
          guarded(n.test, () => { visit(n.consequent, sc); if (n.alternate) visit(n.alternate, sc); });
          return;
        case 'ConditionalExpression':
          visit(n.test, sc);
          guarded(n.test, () => { visit(n.consequent, sc); visit(n.alternate, sc); });
          return;
        case 'LogicalExpression':
          visit(n.left, sc);
          guarded(n.left, () => visit(n.right, sc));
          return;
        case 'VariableDeclarator': {
          if (!n.init) return;
          visit(n.init, sc);
          const id = n.id;
          if (id.type === 'Identifier') {
            if (isFn(n.init)) sc.fnNames.add(id.name);
            const t = taintOf(n.init, sc);
            sc.vars.set(id.name, t ? ext(t, id.name) : null);
            sc.props.delete(id.name);
            if (n.init.type === 'ObjectExpression') setProps(sc, id.name, n.init);
            if (isCreateScript(n.init)) sc.scripts.add(id.name);
            if (n.init.type === 'CallExpression' && isJq(n.init, sc)) sc.jq.add(id.name);
          } else if (id.type === 'ObjectPattern' && n.init.type === 'Identifier' && lookupMsg(sc, n.init.name)) {
            const h = lookupMsg(sc, n.init.name);
            bind(id, null, sc);
            for (const q of id.properties) {
              if (q.type === 'Property' && !q.computed && q.key && (q.key.name === 'data') && q.value.type === 'Identifier' && !h.checked) sc.vars.set(q.value.name, T('postMessage.data', false, true));
            }
          } else bind(id, taintOf(n.init, sc), sc);
          return;
        }
        case 'AssignmentExpression': {
          const L = n.left;
          visit(n.right, sc);
          if (L.type === 'MemberExpression') visit(L, sc);
          assign(n, sc);
          return;
        }
        case 'ReturnStatement':
          if (n.argument) {
            visit(n.argument, sc);
            const f = sc.fnode;
            if (f) { const t = taintOf(n.argument, sc); if (t && !info(f).ret) { info(f).ret = mod(t, { x: true }); changed = true; } }
          }
          return;
        case 'ForInStatement': case 'ForOfStatement': {
          visit(n.right, sc);
          const t = taintOf(n.right, sc), L = n.left;
          if (L.type === 'VariableDeclaration') bind(L.declarations[0].id, t, sc);
          else if (L.type === 'Identifier') setVar(sc, L.name, t ? ext(t, L.name) : null);
          visit(n.body, sc);
          return;
        }
        case 'CallExpression': call(n, sc); break;
        case 'NewExpression':
          if (n.callee.type === 'Identifier') {
            if (n.callee.name === 'Function') { for (const x of n.arguments) { const t = taintOf(x, sc); if (t) { hit(XSS, 'Critical', n, 'Function()', t, x); break; } } }
            else if (n.callee.name === 'Worker' && n.arguments[0]) sinkUrl(XSS, 'High', n, n.arguments[0], sc, 'new Worker()');
          }
          break;
        case 'ImportExpression': sinkUrl(XSS, 'Critical', n, n.source, sc, 'import()'); break;
        case 'Property':
          if (!n.computed && n.key && (n.key.name === 'dangerouslySetInnerHTML' || n.key.value === 'dangerouslySetInnerHTML') && n.value.type === 'ObjectExpression') {
            const h = n.value.properties.find(q => q.type === 'Property' && q.key && (q.key.name === '__html' || q.key.value === '__html'));
            if (h) sinkHtml(XSS, 'High', n.key, h.value, sc, 'dangerouslySetInnerHTML');
          }
          break;
      }
      each(n, c => visit(c, sc));
    }

    // ----- rounds (interprocedural fixed point, max 3) -----
    const deadline = Date.now() + 5000;
    for (let round = 0; round < 3; round++) {
      changed = false;
      out = []; cout = [];
      done = new WeakSet();
      guardStack = [];
      nextSeeds = new Map();
      root = newScope(null, null);
      const sd = seeds.get('root');
      if (sd) for (const [k, v] of sd) root.vars.set(k, v);
      visit(ast, root);
      saveSeeds('root', root);
      seeds = nextSeeds;
      if (!changed || Date.now() > deadline) break;
    }

    for (const o of out) env.push(o);
    for (const o of cout) env.cand(o);
    for (const [f, name] of mergeFns) {
      if (!calledTainted.has(f)) env.cand({ rule: 'proto-merge', desc: 'Recursive merge/extend "' + name + '" without __proto__ guard (not called with tainted data)', category: PP, severity: 'Low', confidence: 'Low', pos: f.start, len: 80, why: 'merge-not-tainted' });
    }
    for (const [f, h] of msgFns) {
      if (!h.checked) env.cand({ rule: 'pm-no-origin', desc: 'message listener without origin check (data does not reach a proven sink)', category: PM, severity: 'Low', confidence: 'Low', pos: f.start, len: 80, why: 'listener-only' });
    }
  }

  function tryParse(acorn, code) {
    for (const sourceType of ['script', 'module']) {
      try {
        return acorn.parse(code, {
          ecmaVersion: 'latest', sourceType, allowHashBang: true, allowReturnOutsideFunction: true,
          allowAwaitOutsideFunction: true, allowImportExportEverywhere: true
        });
      } catch (e) { /* try next mode, then regex fallback */ }
    }
    return null;
  }

  // ---------- regex fallback (acorn could not parse): same-statement matches only ----------

  const DSRC_BODY = '(?:(?:window|self|top|parent|document)\\.)?location\\.(?:hash|search|href|pathname)|document\\.(?:URL|documentURI|baseURI|referrer|cookie)|window\\.name|(?:local|session)Storage\\.getItem\\s*\\(|new\\s+URLSearchParams\\(\\s*(?:window\\.)?location(?:\\.search)?\\s*\\)';
  const DSRC = new RegExp('(?<![\\w$])(?:' + DSRC_BODY + ')');
  const SAN_RE = /encodeURI(?:Component)?\(|\bescape\(|DOMPurify|sanitiz|escapeHtml|\.text\(|parseInt\(|Number\(/i;
  const URL_START = new RegExp('^\\s*(?:(?:decodeURIComponent|decodeURI|unescape)\\s*\\(\\s*)?(new\\s+URLSearchParams\\(\\s*(?:window\\.)?location(?:\\.search)?\\s*\\)\\.get\\s*\\(|(?:(?:window|self|top|parent|document)\\.)?location\\.(hash|search|href)\\b|document\\.(URL|documentURI|baseURI)\\b|(?:(?:window|self|top|parent|document)\\.)?location\\.pathname\\b|document\\.(?:referrer|cookie)\\b|window\\.name\\b|(?:local|session)Storage\\.getItem\\s*\\()(.{0,40})', 's');
  const LISTENER_RE = /addEventListener\(\s*["']message["']|\bonmessage\s*=|\.on\(\s*["']message["']/g;

  const RSINKS = [
    { id: 'innerHTML', cat: XSS, sev: 'High', re: /\.innerHTML\s*\+?=(?!=)/g, kind: 'assign', mode: 'html' },
    { id: 'outerHTML', cat: XSS, sev: 'High', re: /\.outerHTML\s*\+?=(?!=)/g, kind: 'assign', mode: 'html' },
    { id: 'insertAdjacentHTML', cat: XSS, sev: 'High', re: /\.insertAdjacentHTML\s*\(/g, kind: 'call', mode: 'html', arg: 1 },
    { id: 'document.write', cat: XSS, sev: 'High', re: /\bdocument\.write(?:ln)?\s*\(/g, kind: 'call', mode: 'html' },
    { id: 'eval()', cat: XSS, sev: 'Critical', re: /(?<![.\w$])eval\s*\(/g, kind: 'call', mode: 'html' },
    { id: 'Function()', cat: XSS, sev: 'Critical', re: /(?<![.\w$])(?:new\s+)?Function\s*\(/g, kind: 'call', mode: 'html' },
    { id: 'setTimeout/setInterval', cat: XSS, sev: 'Critical', re: /(?<![.\w$])set(?:Timeout|Interval)\s*\(/g, kind: 'call', mode: 'timer' },
    { id: 'jQuery.html()', cat: XSS, sev: 'High', re: /\.(?:html|append|prepend|before|after|replaceWith)\s*\(/g, kind: 'call', mode: 'jq' },
    { id: '$()', cat: XSS, sev: 'High', re: /(?<![\w$.])(?:\$|jQuery)\s*\(/g, kind: 'call', mode: 'dollar' },
    { id: 'location', cat: NAV, sev: 'High', re: /(?<![\w$.])(?:(?:window|document|top|self|parent)\.)?location(?:\.href)?\s*=(?!=)/g, kind: 'assign', mode: 'url' },
    { id: 'location.replace/assign', cat: NAV, sev: 'High', re: /(?<![\w$.])(?:(?:window|document|top|self|parent)\.)?location\.(?:replace|assign)\s*\(/g, kind: 'call', mode: 'url' },
    { id: 'window.open()', cat: NAV, sev: 'Medium', re: /\bwindow\.open\s*\(/g, kind: 'call', mode: 'url' }
  ];

  // text of the call arguments (balanced parentheses), or the right-hand side of an assignment
  function argText(code, open) {
    let depth = 0, q = '';
    const lim = Math.min(code.length, open + 600);
    for (let i = open; i < lim; i++) {
      const ch = code[i];
      if (q) { if (ch === '\\') i++; else if (ch === q) q = ''; continue; }
      if (ch === '"' || ch === '\'' || ch === '`') { q = ch; continue; }
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') { depth--; if (depth === 0) return code.slice(open + 1, i); }
    }
    return code.slice(open + 1, lim);
  }
  function rhsText(code, from) {
    let depth = 0, q = '';
    const lim = Math.min(code.length, from + 400);
    for (let i = from; i < lim; i++) {
      const ch = code[i];
      if (q) { if (ch === '\\') i++; else if (ch === q) q = ''; continue; }
      if (ch === '"' || ch === '\'' || ch === '`') { q = ch; continue; }
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') { if (depth === 0) return code.slice(from, i); depth--; }
      else if (depth === 0 && (ch === ';' || ch === ',' || ch === '\n')) return code.slice(from, i);
    }
    return code.slice(from, lim);
  }

  function regexSinks(code, add, inComment) {
    const ranges = [];
    eachMatch(LISTENER_RE, code, m => {
      if (inComment(m.index)) return;
      const body = code.substr(m.index + m[0].length, 1500);
      if (!/\b(?:origin|source)\b/.test(body)) ranges.push([m.index, m.index + m[0].length + 1500]);
    });
    const inMsg = pos => ranges.some(r => pos >= r[0] && pos <= r[1]);
    const MSG = /\b(?:event|evt|ev|e|msg|message)(?:\.originalEvent)?\.data\b/;

    for (const s of RSINKS) {
      eachMatch(s.re, code, m => {
        if (inComment(m.index)) return;
        const end = m.index + m[0].length;
        let txt = s.kind === 'call' ? argText(code, end - 1) : rhsText(code, end);
        if (s.arg) txt = txt.replace(/^[^,]*,/, '');
        if (!txt.trim() || SAN_RE.test(txt)) return;
        let src = '';
        if (s.mode === 'html') {
          const d = DSRC.exec(txt);
          if (d) src = d[0].replace(/\s*\($/, '');
          else if (MSG.test(txt) && inMsg(m.index)) src = 'postMessage.data';
        } else if (s.mode === 'timer') {
          if (!/^\s*["'`]/.test(txt) && !/^\s*(?:decodeURIComponent|unescape)?\(?\s*(?:location|document)/.test(txt)) return;
          const d = DSRC.exec(txt);
          if (d) src = d[0].replace(/\s*\($/, '');
        } else if (s.mode === 'jq') {
          const before = code.slice(Math.max(0, m.index - 220), m.index);
          const stmt = before.slice(Math.max(before.lastIndexOf(';'), before.lastIndexOf('{'), before.lastIndexOf('}')) + 1);
          if (!/(?:\$|jQuery)\s*\(|\$\w+\b/.test(stmt)) return;
          const d = DSRC.exec(txt);
          if (d) src = d[0].replace(/\s*\($/, ''); else if (MSG.test(txt) && inMsg(m.index)) src = 'postMessage.data';
        } else {
          const u = URL_START.exec(txt);
          if (s.mode === 'dollar') {
            if (u) { const tail = u[5] || ''; if (u[1] && /URLSearchParams/.test(u[1])) src = 'location.search'; else if (/^\s*\.(?:slice|substring|substr|replace|split|match)\b/.test(tail) || /^(?:referrer|cookie)/.test(u[1].replace(/^document\./, '')) || /window\.name|Storage/.test(u[1])) src = u[1].replace(/\s*\($/, ''); }
            else { const lt = new RegExp('^\\s*["\'`]\\s*<[^"\'`]*["\'`]\\s*\\+\\s*(?:(?:decodeURIComponent|unescape)\\s*\\(\\s*)?(' + DSRC_BODY + ')').exec(txt); if (lt) src = lt[1].replace(/\s*\($/, ''); }
          } else if (u) {
            const tail = u[5] || '';
            const pinned = u[2] || u[3];
            if (/URLSearchParams/.test(u[1]) || !pinned || /^\s*\.(?:slice|substring|substr|replace|split|match)\b/.test(tail)) src = u[1].replace(/\s*\($/, '').replace(/\.get$/, '');
            if (/URLSearchParams/.test(u[1])) src = 'location.search';
          }
        }
        if (!src) return;
        const pm = src === 'postMessage.data';
        add({ rule: s.id, desc: s.id + ' sink', category: pm ? PM : s.cat, severity: s.sev, confidence: 'Medium', pos: m.index, len: m[0].length + 60, chain: src + ' -> ' + s.id });
      });
    }
    eachMatch(/\.postMessage\s*\(/g, code, m => {
      if (inComment(m.index)) return;
      const txt = argText(code, m.index + m[0].length - 1);
      const mm = /,\s*["']\*["']\s*(?:,[^)]*)?$/.exec(txt);
      if (!mm) return;
      const x = txt.slice(0, mm.index);
      if (DSRC.test(x) || SENSITIVE.test(x)) add({ rule: 'postmessage-star', desc: 'postMessage with "*" target origin sends tainted/sensitive data', category: OTH, severity: 'Medium', confidence: 'Medium', pos: m.index, len: 80, chain: (DSRC.exec(x) || ['sensitive data'])[0] + ' -> postMessage(*)' });
    });
  }

  // ---------- endpoints ----------

  const STRING_RE = /(["'`])((?:https?:|wss?:)?\/\/[^\s"'`\\<>]{3,400}|\.{0,2}\/[^\s"'`\\<>]{2,400})\1/g;
  const CALL_RE = /(?:\bfetch|\baxios(?:\.(?:get|post|put|delete|patch|head|options|request))?|\$\.(?:ajax|get|post|getJSON)|\bjQuery\.(?:ajax|get|post|getJSON)|\.(?:get|post|put|patch|delete|open|request|ajax))\s*\(\s*(?:["'][A-Za-z]+["']\s*,\s*)?(["'`])([^"'`\s\\]{2,300})\1/g;
  const KEY_RE = /\b(url|endpoint|path|baseURL|baseUrl|base_url|uri|api(?:Url|URL|Path)?|href|route|wsUrl|websocket)["']?\s*[:=]\s*(["'`])([^"'`\s\\]{2,300})\2/gi;
  const ROUTE_RE = /\b(?:app|router|route|api|server)\.(?:get|post|put|patch|delete|all|use|route)\s*\(\s*["'`](\/[^"'`\s\\]*)["'`]|\.when\(\s*["'](\/[^"']*)["']/g;
  const STATIC_EXT = /\.(?:png|jpe?g|gif|svg|ico|webp|bmp|avif|woff2?|ttf|eot|otf|css|map|mp[34]|webm|ogg|wav|pdf|zip|scss|less|vue|tsx?|jsx)(?:[?#]|$)/i;
  const NOISE_HOST = /^(?:https?:)?\/\/(?:www\.w3\.org|schemas?\.|purl\.org|ns\.adobe\.com|xmlns|json-schema\.org|example\.(?:com|org))/i;
  const MIME_RE = /^(?:application|text|image|audio|video|font|multipart|message|model|chemical)\/[\w.+*-]+(?:\s*[;,].*)?$/i;
  const DATEFMT_RE = /^(?:[YyMmDdHhSsAaZzWwEeGgQqKkXx]{1,5}[\/.:-]){1,3}[YyMmDdHhSsAaZzWwEeGgQqKkXx]{1,5}$/;
  const SINGLE_OK = /\.(?:php|aspx?|jsp|do|action|cgi|json|xml|ashx|svc)(?:[?#]|$)/i;

  function keepEndpoint(raw, kind) {
    if (/\$\{|\{\{|<%|%\{|#\{|\\/.test(raw) || /[()[\]^|*$]/.test(raw) || /\{\d+(?:,\d*)?\}/.test(raw)) return false;
    if (!/[A-Za-z0-9]/.test(raw) || /^\.{0,2}\/?$/.test(raw) || /^data:/i.test(raw)) return false;
    if (STATIC_EXT.test(raw) || NOISE_HOST.test(raw) || /node_modules/.test(raw)) return false;
    const bare = raw.replace(/^\.{0,2}\/+/, '');
    if (MIME_RE.test(bare) || DATEFMT_RE.test(bare)) return false;
    if (/^[.\w-]+\/(?:g|i|m|u|y|gi|gm|im|gim)$/.test(bare) && !/^https?:/i.test(raw)) return false; // regex literal + flags
    if (kind === 'path') {
      const path = raw.split(/[?#]/)[0];
      const segs = path.split('/').filter(s => s && s !== '.' && s !== '..');
      if (segs.length < 2 && !/[?]/.test(raw) && !SINGLE_OK.test(raw)) return false; // single segment without call context
    }
    return true;
  }

  function extractEndpoints(code, file, pageUrl, starts) {
    const found = new Map(); // raw -> {kind, pos}
    const put = (raw, kind, pos) => {
      if (found.size >= 1000 || !raw || !keepEndpoint(raw, kind)) return;
      const cur = found.get(raw);
      if (!cur) found.set(raw, { kind, pos });
      else if (kind !== 'url' && kind !== 'path') cur.kind = kind;
    };
    eachMatch(STRING_RE, code, m => put(m[2], /^wss?:/i.test(m[2]) ? 'websocket' : /^(?:https?:)?\/\//i.test(m[2]) ? 'url' : 'path', m.index), 4000);
    eachMatch(KEY_RE, code, m => { if (/[/]/.test(m[3]) || /^(?:https?|wss?):/i.test(m[3])) put(m[3], 'key:' + m[1].toLowerCase(), m.index); }, 2000);
    eachMatch(CALL_RE, code, m => {
      if (!/\//.test(m[2])) return;
      const k = /fetch/.test(m[0]) ? 'fetch' : /axios/.test(m[0]) ? 'axios' : /open/.test(m[0]) ? 'xhr' : /ajax|\$|jQuery/.test(m[0]) ? 'jquery' : 'call';
      put(m[2], k, m.index);
    }, 2000);
    eachMatch(ROUTE_RE, code, m => put(m[1] || m[2], 'route', m.index), 1000);

    let base;
    try { base = new URL(pageUrl); } catch (e) { return []; }
    const out = [], seen = new Set();
    for (const [raw, info] of found) {
      let u;
      try { u = new URL(raw, base); } catch (e) { continue; }
      if (!/^(?:https?|wss?):$/.test(u.protocol)) continue;
      u.hash = '';
      const url = u.href;
      if (seen.has(url)) continue;
      seen.add(url);
      let kind = info.kind;
      if (u.protocol === 'ws:' || u.protocol === 'wss:') kind = 'websocket';
      else if (/graphql/i.test(u.pathname)) kind = 'graphql';
      const li = lineOf(starts, info.pos), col = info.pos - starts[li] + 1;
      out.push({ url, kind, same: u.host === base.host, file, line: li + 1, column: col, len: Math.min(raw.length, 200), ctx: contextFor(code, starts, li + 1, col, 3) });
    }
    return out;
  }

  // ---------- main ----------

  async function analyze(file, opts) {
    opts = opts || {};
    const isHtml = file.type === 'html';
    let code = file.code || '';
    if (code.length > MAX_FILE) code = code.slice(0, MAX_FILE);
    if (isHtml) code = blankInline(code);

    const c = collector(file.name, code), add = c.add;
    const cc = collector(file.name, code), addCand = o => cc.add(o);
    const lib = !isHtml && isKnownLib(file.name, code);
    const result = { findings: c.out, candidates: cc.out, sources: [], endpoints: [], mode: 'regex', size: code.length, lib, libs: {} };
    const big = code.length > 400000;
    const pause = () => (big ? tick() : null);
    const safe = fn => { try { fn(); } catch (e) { /* one bad rule must not kill the file */ } };
    const acorn = opts.acorn || root.acorn;
    const inComment = commentTester(code, c.starts);

    // 1. proven flows
    if (!isHtml && !lib) {
      let ast = false;
      if (acorn && code.length <= AST_MAX) {
        const tree = tryParse(acorn, code);
        if (tree) {
          try {
            const rawF = [], rawC = [];
            astScan(tree, { code, push: o => rawF.push(o), cand: o => rawC.push(o) });
            rawF.forEach(add);
            rawC.forEach(addCand);
            ast = true;
            result.mode = 'ast';
          } catch (e) { result.astError = String((e && e.message) || e); }
        }
      }
      if (!ast) { safe(() => regexSinks(code, add, inComment)); await pause(); }

      // sources are an inventory, never findings
      safe(() => {
        const inv = new Map();
        const note = (name, index, len) => {
          let e = inv.get(name);
          if (!e) { e = { name, count: 0, locs: [] }; inv.set(name, e); }
          e.count++;
          if (e.locs.length < 8) { const li = lineOf(c.starts, index); e.locs.push({ line: li + 1, column: index - c.starts[li] + 1, len }); }
        };
        for (const [name, re] of SOURCES) eachMatch(re, code, m => { if (!inComment(m.index)) note(name, m.index, m[0].length); }, 400);
        if (/addEventListener\(\s*["']message["']|\bonmessage\b/.test(code)) eachMatch(MSG_DATA_RE, code, m => note('postMessage data (' + m[0] + ')', m.index, m[0].length), 200);
        result.sources = [...inv.values()];
      });
      await pause();

      // name-only mentions are candidates at best
      safe(() => {
        for (const r of NAMED) eachMatch(r.re, code, m => { if (!inComment(m.index)) addCand({ rule: r.id, desc: r.desc, category: r.cat, severity: r.sev, confidence: 'Low', pos: m.index, len: m[0].length, why: 'name-only' }); });
      });
      if (!ast) {
        safe(() => eachMatch(LISTENER_RE, code, m => {
          if (inComment(m.index)) return;
          if (!/\b(?:origin|source)\b/.test(code.substr(m.index + m[0].length, 1500))) addCand({ rule: 'pm-no-origin', desc: 'message listener without origin check (data flow not proven)', category: PM, severity: 'Low', confidence: 'Low', pos: m.index, len: 80, why: 'listener-only' });
        }));
      }
    } else if (isHtml) {
      safe(() => {
        for (const r of NAMED) eachMatch(r.re, code, m => addCand({ rule: r.id, desc: r.desc, category: r.cat, severity: r.sev, confidence: 'Low', pos: m.index, len: m[0].length, why: 'name-only' }));
      });
    }

    // 2. secrets (validated) and public identifiers: also for well-known libraries
    safe(() => secretsPass(code, add, inComment));
    await pause();

    safe(() => {
      for (const r of MISC) {
        eachMatch(r.re, code, m => {
          const val = m[1] || m[0];
          if (r.test && !r.test(val)) return;
          if (r.info) add({ rule: r.id, desc: r.desc + ': ' + val.slice(0, 80), category: INFO, severity: 'Info', confidence: 'High', pos: m.index, len: m[0].length });
          else if (!lib && !isHtml) addCand({ rule: r.id, desc: r.desc + ': ' + val.slice(0, 80), category: INFO, severity: 'Low', confidence: 'Low', pos: m.index, len: m[0].length, why: 'heuristic' });
        });
      }
    });

    // 3. library versions: banner comment or exact file name only
    if (!isHtml) {
      safe(() => {
        const base = /^https?:/i.test(file.name) ? decodeURIComponent((file.name.split(/[?#]/)[0].split('/').pop()) || '') : '';
        for (const l of LIBS) {
          let ver = null, pos = 0;
          for (const re of l.banner) { const m = re.exec(code.slice(0, 40000)); if (m) { ver = m[1]; pos = m.index; break; } }
          if (!ver && base) for (const re of l.file) { const m = re.exec(base); if (m) { ver = m[1]; break; } }
          if (!ver) continue;
          result.libs[l.key] = ver;
          const issue = l.issue && l.issue(ver);
          add({ rule: 'lib-' + l.key, desc: l.name + ' ' + ver + (issue ? ' - ' + issue : ''), category: LIB, severity: issue ? 'Low' : 'Info', confidence: 'High', pos, len: 80 });
        }
      });
    }

    if (!lib) safe(() => { result.endpoints = extractEndpoints(code, file.name, opts.pageUrl || '', c.starts); });
    return result;
  }

  // ---------- self test ----------

  const TESTS = [
    // must detect
    { name: 'hash -> var -> innerHTML', code: 'var h=location.hash.slice(1); el.innerHTML=h;', detect: f => f.find(x => x.chain === 'location.hash -> h -> innerHTML') },
    { name: 'document.write(location.search)', code: 'document.write(location.search);', detect: f => f.find(x => /^location\.search -> document\.write$/.test(x.chain)) },
    { name: 'location.href = URLSearchParams.get', code: "location.href=new URLSearchParams(location.search).get('next');", detect: f => f.find(x => x.category === 'Navigation / Redirect' && /^location\.search -> location\.href$/.test(x.chain)) },
    { name: 'message handler without origin check', code: "addEventListener('message',e=>{el.innerHTML=e.data})", detect: f => f.find(x => x.category === 'postMessage' && x.chain === 'postMessage.data -> innerHTML') },
    { name: 'eval(decodeURIComponent(hash))', code: 'eval(decodeURIComponent(location.hash.slice(1)));', detect: f => f.find(x => /^location\.hash -> eval\(\)$/.test(x.chain)) },
    { name: 'interprocedural: param + return', code: 'function g(){return location.hash.slice(1)} function r(s){document.getElementById("a").innerHTML=s} r(g());', detect: f => f.find(x => /innerHTML$/.test(x.chain) && /g\(\)/.test(x.chain)) },
    { name: 'jQuery $() with tainted HTML', code: "$('<div>'+location.hash.slice(1)+'</div>');", detect: f => f.find(x => /\$\(\)$/.test(x.chain)) },
    { name: 'jQuery .html() with source', code: "$('#a').html(location.search.slice(1));", detect: f => f.find(x => /jQuery\.html\(\)$/.test(x.chain)) },
    { name: 'prototype pollution: unguarded merge + tainted', code: 'function merge(t,s){for(var k in s){if(typeof s[k]==="object"){t[k]=t[k]||{};merge(t[k],s[k])}else t[k]=s[k]}return t} merge({},JSON.parse(location.hash.slice(1)));', detect: f => f.find(x => x.category === 'Prototype Pollution') },
    { name: 'regex fallback: same statement', code: 'var broken = ;;; ]] \nel.innerHTML = location.hash;', detect: f => f.find(x => x.chain === 'location.hash -> innerHTML' && x.confidence !== 'High') },
    { name: 'AWS key is a Secret', code: 'var k="AKIAQ3EGRTYUIOPASDFG";', detect: (f, all) => all.find(x => x.category === 'Secret' && /AWS/.test(x.desc)) },
    { name: 'valid JWT is a Secret', code: 'var t="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.c2lnbmF0dXJlMTIzNDU2";', detect: (f, all) => all.find(x => x.category === 'Secret' && /JWT/.test(x.desc)) },
    // must NOT report
    { name: 'IGNORE map/join, empty, textContent', code: "el.innerHTML=items.map(f).join(''); el.innerHTML=''; el.textContent=location.hash;", ignore: true },
    { name: 'IGNORE DOMPurify + encoded redirect', code: "el.innerHTML=DOMPurify.sanitize(location.hash); location.href='/login?next='+encodeURIComponent(location.pathname);", ignore: true },
    { name: 'IGNORE untainted fetch/href/src/append', code: "fetch('/api/users/'+id); a.href=url; img.src=base+'/i.png'; arr.append(x); $('#a').append(x);", ignore: true },
    { name: 'IGNORE lone localStorage / cookie / hasOwnProperty / __proto__', code: "var s=localStorage; var c=document.cookie; Object.prototype.hasOwnProperty.call(a,b); var p=o.__proto__;", ignore: true },
    { name: 'IGNORE Firebase web config as Secret', code: 'var cfg={apiKey:"AIzaSyA1234567890abcdefghijklmnopqrstuv",authDomain:"x.firebaseapp.com"};', noSecret: true },
    { name: 'IGNORE handler that checks e.origin', code: "addEventListener('message',function(e){if(e.origin!=='https://a.com')return;el.innerHTML=e.data})", ignore: true },
    { name: 'IGNORE placeholder password', code: 'var c={password:"your_password_here"};', noSecret: true },
    { name: 'IGNORE constant-prefix navigation / fetch', code: "location.href='/login?next='+location.hash.slice(1); fetch('/api/'+location.hash.slice(1)); a.href='https://host/'+location.hash.slice(1);", ignore: true },
    { name: 'IGNORE $(location.hash) and $("#"+x)', code: "$(location.hash); $('#'+location.hash.slice(1)); $('#a').append(x);", ignore: true },
    { name: 'IGNORE DOM append with source (text insertion)', code: 'el.append(location.hash); document.body.prepend(location.search);', ignore: true },
    { name: 'IGNORE guarded flow', code: 'var h=location.hash.slice(1); if(/^\\d+$/.test(h)){el.innerHTML=h}', ignore: true },
    { name: 'IGNORE setTimeout with function', code: 'setTimeout(function(){x(location.hash)},10); setTimeout(fn,10);', ignore: true },
    { name: 'IGNORE merge with __proto__ guard', code: 'function merge(t,s){for(var k in s){if(k==="__proto__")continue;if(typeof s[k]==="object")merge(t[k],s[k]);else t[k]=s[k]}} merge({},JSON.parse(location.hash.slice(1)));', ignore: true },
    { name: 'IGNORE inherited names (constructor/toString) never crash AST mode', code: 'var x=a.constructor.parse(b); var y=toString.call(z); hasOwnProperty.assign(1);', ignore: true, needAst: true },
    { name: 'IGNORE invalid JWT / basic', code: 'var a="eyJhbGciOiJIUzI1NiJ9xxxx.eyJ1c2VyIjoiYWRtaW4ifQxxxx.sig123456"; var b="Basic QUFBQUFBQUFBQUFBQUFBQQ==";', noSecret: true }
  ];

  async function selfTest(acornOpt) {
    const results = [];
    for (const t of TESTS) {
      let pass = false, detail = '';
      try {
        const r = await analyze({ name: 't.js', type: 'js', code: t.code }, { pageUrl: 'https://example.com/', acorn: acornOpt || root.acorn });
        const bad = r.findings.filter(f => f.category !== LIB && f.category !== PUB && f.category !== INFO);
        if (t.needAst && r.mode !== 'ast') { pass = false; detail = 'fell back to regex mode: ' + r.astError; }
        else if (t.ignore) { pass = bad.length === 0; detail = pass ? 'no findings' : 'unexpected: ' + bad.map(f => f.rule + ' [' + f.chain + ']').join('; '); }
        else if (t.noSecret) { const s = r.findings.filter(f => f.category === SEC); pass = s.length === 0; detail = pass ? 'no Secret' : 'unexpected Secret: ' + s.map(f => f.desc).join('; '); }
        else { const f = t.detect(bad, r.findings); pass = !!f; detail = pass ? (f.chain || f.desc) + ' (' + r.mode + ')' : 'missing; got: ' + (r.findings.map(x => x.rule + ' [' + x.chain + ']').join('; ') || 'nothing'); }
      } catch (e) { detail = 'exception: ' + e.message; }
      results.push({ name: t.name, expect: t.ignore || t.noSecret ? 'ignore' : 'detect', pass, detail });
    }
    return results;
  }

  const api = { analyze, contextFor, lineStarts, lineOf, mask, RANK, selfTest, isKnownLib };
  root.DPXAnalyzer = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
