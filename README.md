<div align="center">

<img src="Logo.png" alt="DPXJS Logo" width="160" />

# DPXJS

**Client-side JavaScript security analyzer for your browser.**
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

**DPXJS** is a browser extension built for bug bounty hunters, pentesters and developers who need to audit the JavaScript that a web page ships to the client, fast.

It collects every script a page loads (inline, external, dynamically injected and the HTML itself), parses them with a real **AST parser (Acorn)**, and performs **taint analysis** from attacker-controlled sources (`location.hash`, `location.search`, `postMessage`, `document.referrer`, ...) to dangerous sinks (`innerHTML`, `eval`, `document.write`, `location`, ...).

Unlike noisy regex-only scanners, DPXJS focuses on **proven flows**: untainted values, sanitized values, guarded handlers and placeholder secrets are filtered out, so what you see is worth your time.

> Everything runs **locally in your browser**. No code leaves your machine unless you explicitly press an AI button.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🎯 | **DOM XSS detection** | Source → sink taint tracking, including variable propagation and interprocedural flows (parameter + return value). |
| 🔀 | **Navigation / Redirect** | Open redirects and `javascript:` sinks via `location`, `location.replace/assign`, `window.open()`. |
| 🧬 | **Prototype Pollution** | Unguarded recursive merges fed by tainted input. Guarded merges (`__proto__` checks) are ignored. |
| 📨 | **postMessage** | Message handlers with no `event.origin` validation. Handlers that check origin are skipped. |
| 🔑 | **Secrets** | AWS, GitHub, Stripe, Slack, Twilio, SendGrid, Mailgun, Google OAuth, private keys, JWT, Basic auth, hardcoded credentials and more. Validated (e.g. real JWT structure) to cut false positives. |
| 🪪 | **Public identifiers** | Firebase config, Google API keys, Sentry DSN, Mapbox public tokens, Stripe publishable keys, Twilio SIDs. |
| 🌐 | **Endpoint extraction** | Pulls API URLs, paths, routes and WebSocket endpoints out of the JavaScript. |
| 🧰 | **Library fingerprinting** | Detects jQuery, AngularJS, React, Vue, Lodash, Moment, Bootstrap and flags framework-specific sinks (`dangerouslySetInnerHTML`, `v-html`, `ng-bind-html`, `bypassSecurityTrust*`). |
| ℹ️ | **Client-side info** | Source maps, internal hosts, localhost / private IPs, permissive CORS, JWT handling, token storage. |
| 🤖 | **AI triage (Numes)** | One-click AI summary and per-finding verdicts to separate real bugs from noise. |
| 🖥️ | **Built-in code viewer** | Jump to the exact line with context and highlighted matches. |
| 🛠️ | **DevTools integration** | Optional: picks up extra script URLs from the Network panel while DevTools is open. |
| 📤 | **JSON export** | Export the full result set for reports or other tooling. |
| ⚡ | **Fast & safe** | Large files (>1.5 MB) fall back to regex mode, hit caps per rule, and AST parsing never crashes the scan. |

---

## 📦 Installation

DPXJS is a **Firefox (Manifest V3)** extension, minimum Firefox **115**.

### Option 1: Temporary install (quickest, for testing)

1. Clone the repository:
   ```bash
   git clone https://github.com/0xdexblood/DpxJS.git
   cd DpxJS/dpxjs
   ```
2. Open Firefox and go to:
   ```
   about:debugging#/runtime/this-firefox
   ```
3. Click **Load Temporary Add-on...**
4. Select the `manifest.json` file inside the `DpxJS/dpxjs` folder.
5. The DPXJS icon appears in the toolbar. Pin it for quick access.

> ⚠️ Temporary add-ons are removed when Firefox restarts. Repeat the steps after a restart, or use Option 2.

### Option 2: Permanent install (Firefox Developer Edition / Nightly / ESR)

Release builds of Firefox only accept signed add-ons. Use **Developer Edition**, **Nightly** or **ESR**:

1. Open `about:config` and set `xpinstall.signatures.required` to `false`.
2. Zip the **contents** of the extension folder (`manifest.json` must be at the root of the ZIP):
   ```bash
   cd DpxJS/dpxjs
   zip -r ../../dpxjs.xpi . -x "*.git*"
   ```
3. Open `about:addons` → ⚙️ → **Install Add-on From File...** → choose `dpxjs.xpi`.

### Option 3: Chromium-based browsers

The manifest is written for Firefox (`browser_specific_settings`, background `scripts`). Chrome/Edge/Brave need a small port (service worker instead of background scripts). Contributions for an official Chromium build are welcome.

### Permissions explained

| Permission | Why it is needed |
|---|---|
| `activeTab`, `tabs` | Identify the page you are scanning. |
| `scripting` | Read inline scripts and the DOM of the scanned page. |
| `webRequest`, `webNavigation` | Track which JavaScript files the page loads (including dynamic ones). |
| `webRequestBlocking`, `declarativeNetRequest` | Strip the `Origin` header on requests to the Numes API (it rejects browser origins). |
| `storage` | Save your settings and temporary scan state. |
| `<all_urls>` | Fetch and analyze scripts hosted on any domain. |

---

## 🚀 Usage

1. Browse to the page you want to audit.
2. Click the **DPXJS** toolbar icon.
3. Press **Scan**. A progress bar shows scripts being fetched and analyzed.
4. Review the results by tab/category. Use the toolbar to:
   - **Filter** findings by text
   - **Sort** by severity or file
   - **Hide low confidence** results
5. Click any finding to open it in the **viewer** at the exact line, with surrounding code.
6. Press **Export** to save everything as JSON.
7. Press **Open in tab** to keep the interface open (a popup closes when it loses focus).

### Tips

- Enable **Auto-scan after navigation** in Settings to scan every page as you browse (handy for SPAs; route changes keep the script list).
- Open **DevTools** before scanning to include scripts found by the Network panel.
- Turn on **Show unverified candidates** to see lower-confidence items in the *Info* tab.
- `view-source:` tabs can't be scripted, so DPXJS fetches the source and reads its `<script>` tags instead.

---

## 🤖 AI Triage (Numes)

DPXJS can send findings to an LLM through the [Numes](https://numes.ai) API (OpenAI-compatible) to help you triage faster.

1. Create an account and generate an API key on Numes.
2. In DPXJS click ⚙️ **Settings**.
3. Paste your key into **API key**.
4. Optionally set a **Model** (default placeholder: `deepseek/deepseek-v4.1-flash`).
5. Click **Save**, then **Test connection**.
6. Use **AI Summary** for the whole scan, or the small **AI** button next to a finding.

**Privacy notes**

- Only the findings and code snippets you choose to analyze are sent, never your browsing history.
- Your API key is only used in the `Authorization` header.
- AI is **opt-in**. Without a key, the extension works fully offline.

---

## 🧠 How it works

```
 Page ──► Script collector ──► Acorn AST ──► Taint engine ──► Verified findings
          (inline, external,    (regex mode    sources → sinks    + secrets
           dynamic, HTML)        for >1.5 MB)  + sanitizer/guard   + endpoints
                                               awareness          + libraries
                                                    │
                                                    ▼
                                          Popup UI  /  Viewer  /  JSON  /  AI
```

- **Sources:** `location.*`, `document.URL`, `document.referrer`, `window.name`, `URLSearchParams`, `postMessage` data...
- **Sinks:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`, string `setTimeout/setInterval`, jQuery `.html()` / `$()`, navigation APIs.
- **False-positive filters:** `textContent`, DOMPurify, constant-prefix URLs, guarded flows, origin-checked handlers, placeholder credentials, invalid JWTs.

---

## 🗂️ Project structure

```
DpxJS/
├── Logo.png
├── README.md
├── LICENSE
└── dpxjs/             # the extension
    ├── manifest.json      # Extension manifest (MV3, Firefox)
    ├── background.js      # Script tracking, scanning, AI jobs, Numes API
    ├── analyzer.js        # AST + taint engine, secret/endpoint/library rules
    ├── popup.html / .js   # Main UI
    ├── viewer.html / .js  # Source code viewer with line highlighting
    ├── devtools.html / .js# Optional DevTools script discovery
    ├── vendor/acorn.js    # JavaScript parser
    └── icons/logo.png
```

---


## 🤝 Contributing

Contributions, issues and feature requests are welcome!

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

Ideas: Chromium port, more secret signatures, new sink/source rules, report export (Markdown/SARIF).

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

**Built with 💜 by [0xdexblood](https://github.com/0xdexblood)**

If DPXJS helps you find a bug, consider leaving a ⭐

</div>
