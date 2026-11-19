/* DPXJS v1 - Author: 0xdexblood - https://github.com/0xdexblood */
'use strict';
// Optional: only runs while DevTools is open. Sends extra script URLs to the background; the extension works without it.
(function () {
  const dt = browser.devtools;
  if (!dt || !dt.inspectedWindow) return;
  const iw = dt.inspectedWindow, tabId = iw.tabId;
  const seen = new Set();
  let queue = [], timer = null;

  function flush() {
    timer = null;
    if (!queue.length) return;
    const urls = queue;
    queue = [];
    browser.runtime.sendMessage({ type: 'devtools-urls', tabId, urls }).catch(() => {});
  }
  function push(u) {
    if (typeof u !== 'string' || !/^https?:/i.test(u) || seen.has(u)) return;
    seen.add(u);
    queue.push(u);
    if (!timer) timer = setTimeout(flush, 500);
  }
  const isJs = (url, mime) => /javascript|ecmascript/i.test(mime || '') || /\.m?js(?:[?#]|$)/i.test(url);

  if (typeof iw.getResources === 'function') {
    const take = list => (list || []).forEach(r => { if (r && r.type === 'script') push(r.url); });
    const p = iw.getResources(take);
    if (p && typeof p.then === 'function') p.then(take, () => {});
    if (iw.onResourceAdded) iw.onResourceAdded.addListener(r => { if (r && r.type === 'script') push(r.url); });
  } else if (dt.network) {
    // Firefox has no inspectedWindow.getResources(): the network panel gives the same script list
    const fromEntry = e => {
      const url = e && e.request && e.request.url;
      const mime = e && e.response && e.response.content && e.response.content.mimeType;
      if (url && isJs(url, mime)) push(url);
    };
    if (dt.network.getHAR) dt.network.getHAR().then(har => ((har && har.entries) || []).forEach(fromEntry), () => {});
    if (dt.network.onRequestFinished) dt.network.onRequestFinished.addListener(fromEntry);
  }
})();
