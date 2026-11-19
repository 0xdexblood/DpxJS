<div align="center">

<img src="Logo.png" alt="DPXJS Logo" width="140" />

# DPXJS

**Client-side JavaScript security analyzer for Firefox.**
Proven XSS flows, leaked secrets and hidden endpoints, with one-click AI triage.

<p>
  <img src="https://img.shields.io/badge/version-1.0.3-8b5cf6?style=for-the-badge" alt="version" />
  <img src="https://img.shields.io/badge/Firefox-115%2B-ff7a1a?style=for-the-badge&logo=firefoxbrowser&logoColor=white" alt="firefox" />
  <img src="https://img.shields.io/badge/Manifest-V3-6d28d9?style=for-the-badge" alt="mv3" />
  <img src="https://img.shields.io/badge/AST-Acorn-0b0b0f?style=for-the-badge" alt="acorn" />
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" alt="license" />
</p>

<p>
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-ai-triage-numes">AI Triage</a> •
  <a href="#-how-it-works">How it works</a> •
  <a href="#-contributing">Contributing</a>
</p>

</div>

---

## 📖 About

**DPXJS** is a browser extension for bug bounty hunters, pentesters and developers who need to audit the JavaScript a page ships to the client, fast.

It collects every script a page loads (inline, external, dynamic and the HTML itself), parses them with a real **AST parser (Acorn)**, and runs **taint analysis** from attacker-controlled sources (`location.hash`, `location.search`, `postMessage`, `document.referrer`...) to dangerous sinks (`innerHTML`, `eval`, `document.write`, `location`...).

Unlike noisy regex-only scanners, DPXJS focuses on **proven flows**: untainted, sanitized and guarded values and placeholder secrets are filtered out.

> 🔒 Everything runs **locally in your browser**. Nothing leaves your machine unless you press an AI button.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🎯 | **DOM XSS** | Source → sink taint tracking with variable propagation and interprocedural flows. |
| 🔀 | **Open Redirect** | `location`, `location.replace/assign`, `window.open()` and `javascript:` sinks. |
| 🧬 | **Prototype Pollution** | Unguarded recursive merges fed by tainted input. |
| 📨 | **postMessage** | Handlers with no `event.origin` validation. |
| 🔑 | **Secrets** | AWS, GitHub, Stripe, Slack, Twilio, SendGrid, Mailgun, Google OAuth, private keys, JWT, Basic auth and more, with validation to cut false positives. |
| 🪪 | **Public IDs** | Firebase config, Google API keys, Sentry DSN, Mapbox tokens, Stripe publishable keys. |
| 🌐 | **Endpoints** | API URLs, paths, routes and WebSocket endpoints. |
| 🧰 | **Libraries** | jQuery, AngularJS, React, Vue, Lodash, Moment, Bootstrap, plus framework sinks (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`). |
| ℹ️ | **Client info** | Source maps, internal hosts, private IPs, permissive CORS, token storage. |
| 🤖 | **AI triage** | One-click summary and per-finding verdicts via Numes. |
| 🖥️ | **Code viewer** | Jump to the exact line with highlighted context. |
| 🛠️ | **DevTools** | Picks up extra script URLs from the Network panel. |
| 📤 | **JSON export** | Full results for reports or other tooling. |
| ⚡ | **Fast & safe** | Files over 1.5 MB fall back to regex mode; per-rule caps; parsing never crashes a scan. |

---

## 📦 Installation

DPXJS is a **Firefox (Manifest V3)** extension, minimum Firefox **115**.

### Option 1: Temporary install (quickest)

1. Clone the repository:
   ```bash
   git clone https://github.com/0xdexblood/DpxJS.git
   cd DpxJS/dpxjs
   ```
2. Open Firefox and go to `about:debugging#/runtime/this-firefox`.
3. Click **Load Temporary Add-on...**
4. Select `manifest.json` inside the `DpxJS/dpxjs` folder.
5. Pin the DPXJS icon to the toolbar.

> ⚠️ Temporary add-ons are removed when Firefox restarts. Repeat the steps after a restart.

### Option 2: Chromium-based browsers

The manifest targets Firefox (`browser_specific_settings`, background `scripts`). Chrome, Edge and Brave need a small port (service worker instead of background scripts). Contributions for an official Chromium build are welcome.

### Permissions

| Permission | Why |
|---|---|
| `activeTab`, `tabs` | Identify the page being scanned. |
| `scripting` | Read inline scripts and the page DOM. |
| `webRequest`, `webNavigation` | Track loaded JavaScript files, including dynamic ones. |
| `webRequestBlocking`, `declarativeNetRequest` | Strip the `Origin` header on requests to the Numes API. |
| `storage` | Save settings and temporary scan state. |
| `<all_urls>` | Fetch and analyze scripts from any domain. |

---

## 🚀 Usage

1. Open the page you want to audit.
2. Click the **DPXJS** toolbar icon and press **Scan**.
3. Browse results by tab; **filter**, **sort** by severity or file, and **hide low confidence** items.
4. Click a finding to open it in the **viewer** at the exact line.
5. Press **Export** for JSON, or **Open in tab** to keep the UI open.

**Tips**

- Enable **Auto-scan after navigation** in Settings for SPAs.
- Open **DevTools** before scanning to include Network-panel scripts.
- Turn on **Show unverified candidates** to see lower-confidence items in the *Info* tab.
- `view-source:` tabs can't be scripted, so DPXJS fetches the source and reads its `<script>` tags.

---

## 🤖 AI Triage (Numes)

DPXJS can send findings to an LLM through the [Numes](https://numes.ai) API (OpenAI-compatible).

1. Generate an API key on Numes.
2. In DPXJS open ⚙️ **Settings** and paste it into **API key**.
3. Optionally set a **Model** (placeholder: `deepseek/deepseek-v4.1-flash`).
4. Click **Save**, then **Test connection**.
5. Use **AI Summary** for the whole scan or the **AI** button next to a finding.

**Privacy:** only the findings and snippets you choose are sent; the key is used only in the `Authorization` header; AI is opt-in and the extension works fully offline without it.

---

## 🧠 How it works

```
 Page ──► Script collector ──► Acorn AST ──► Taint engine ──► Verified findings
          (inline, external,    (regex for    sources → sinks    + secrets
           dynamic, HTML)        >1.5 MB)     + sanitizer/guard  + endpoints
                                                awareness        + libraries
                                                    │
                                                    ▼
                                         Popup UI / Viewer / JSON / AI
```

- **Sources:** `location.*`, `document.URL`, `document.referrer`, `window.name`, `URLSearchParams`, `postMessage` data
- **Sinks:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`, string `setTimeout/setInterval`, jQuery `.html()` / `$()`, navigation APIs
- **False-positive filters:** `textContent`, DOMPurify, constant-prefix URLs, guarded flows, origin-checked handlers, placeholder credentials, invalid JWTs

---

## 🗂️ Project structure

```
DpxJS/
├── Logo.png
├── README.md
├── LICENSE
└── dpxjs/
    ├── manifest.json       # MV3 manifest (Firefox)
    ├── background.js       # Script tracking, scanning, AI jobs
    ├── analyzer.js         # AST + taint engine, secret/endpoint/library rules
    ├── popup.html / .js    # Main UI
    ├── viewer.html / .js   # Code viewer with line highlighting
    ├── devtools.html / .js # DevTools script discovery
    ├── vendor/acorn.js     # JavaScript parser
    └── icons/logo.png
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit: `git commit -m "Add my feature"`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

Ideas: Chromium port, more secret signatures, new sink/source rules, Markdown/SARIF export.

---

## 📜 License

Released under the [MIT License](LICENSE).

<div align="center">

**Built with 💜 by [0xdexblood](https://github.com/0xdexblood)**

If DPXJS helps you find a bug, consider leaving a ⭐

</div>
