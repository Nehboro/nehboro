<p align="center">
  <img src="icons/icon128.png" alt="Nehboro" width="100" height="100" />
</p>

<h1 align="center">Nehboro</h1>
<p align="center"><strong>The browser shield your grandma deserves.</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version 1.0.0" />
  <img src="https://img.shields.io/badge/manifest-v3-green?style=flat-square&logo=googlechrome&logoColor=white" alt="Manifest V3" />
  <img src="https://img.shields.io/badge/detections-97-red?style=flat-square" alt="97 detections" />
  <img src="https://img.shields.io/badge/engines-3-orange?style=flat-square" alt="3 engines" />
</p>


<p align="center">
  <a href="https://nehboro.github.io">Website</a> ·
  <a href="https://nehboro.github.io/scan/">URL Scanner</a> ·
  <a href="https://nehboro.github.io/reports/">Community Reports</a> ·
  <a href="#install">Install</a>
</p>

---

## What is Nehboro?

Nehboro is a **community-powered Chrome extension** that protects non-technical users from phishing, ClickFix attacks, tech support scams, malware delivery, and social engineering - in real time, on every page load.

It runs **three detection engines** simultaneously:

| Engine | What it does | Speed |
|---|---|---|
| **Static IOC** | Blocks known-bad domains, URLs, IPs (+ bad AS IP ranges), and ports from community-maintained threat feeds. Fires **before** the page loads. | Instant |
| **Dynamic Heuristic** | Runs 97 pattern-matching detections on every page after load. Catches brand-new threats not in any feed. | ~50ms |
| **Claude AI** *(optional)* | Sends page metadata to Anthropic Claude for a second opinion on ambiguous pages. Requires your own API key. | ~2s |

The heuristic engine is the heart of Nehboro. It doesn't need signatures, feeds, or cloud lookups - it reads the page like a human analyst would and scores what it sees.

screenshots:

<img width="391" height="611" alt="Capture d&#39;écran 2026-04-17 091004" src="https://github.com/user-attachments/assets/fd31f6f0-92ef-4a42-9b02-a29c40f05298" />
<img width="383" height="609" alt="Capture d&#39;écran 2026-04-17 091056" src="https://github.com/user-attachments/assets/9fc96658-99ed-4ea2-b8f7-8da7fc1e5faf" />
<img width="391" height="602" alt="Capture d&#39;écran 2026-04-17 091214" src="https://github.com/user-attachments/assets/43a5842a-f7b3-4e7e-9ef0-770c838242ec" />

<img width="386" height="600" alt="Capture d&#39;écran 2026-04-17 091246" src="https://github.com/user-attachments/assets/3538cae8-c535-4cc2-8f9b-f699c119aee1" />
<img width="391" height="622" alt="Capture d&#39;écran 2026-04-17 091259" src="https://github.com/user-attachments/assets/5702e6d5-6c20-4233-8e8e-7db59dd935f4" />
<img width="385" height="628" alt="Capture d&#39;écran 2026-04-17 091315" src="https://github.com/user-attachments/assets/2a2cc795-405c-407c-8e14-ab4fbca40984" />
<img width="384" height="633" alt="Capture d&#39;écran 2026-04-17 091331" src="https://github.com/user-attachments/assets/e263bda5-f194-452c-9024-d5631ac6b8b2" />


---

## Detections

 
97 heuristic detections across 12 threat categories:
 
| Category | Detections | Examples |
|---|---|---|
| **ClickFix** | `CLICKFIX_FULL_SEQUENCE` `CLICKFIX_PRETEXT` `CLICKFIX_MULTILANG` `FILEFIX` `DNS_CLICKFIX` `CONSENTFIX` | Win+R → Ctrl+V → Enter instruction chains, multilingual variants (FR/ES/DE/IT/PT) |
| **Fake verification** | `FAKE_CLOUDFLARE_TEXT` `FAKE_CLOUDFLARE_DOMAIN` `FAKE_VERIFICATION_ID` `FAKE_URL_BAR` | Fake Cloudflare turnstiles, CAPTCHA lures, browser-in-browser windows |
| **Phishing** | `LOOKALIKE_HOMOGRAPH` `LOOKALIKE_TYPOSQUAT` `PUNYCODE_DOMAIN` `DEVICE_CODE_PHISH` `INSECURE_LOGIN` `VISUAL_BRAND_IMPERSONATION` | Typosquat domains, homograph attacks, OAuth device code phishing, brand impersonation (Google, Microsoft, Apple, PayPal, Amazon, Netflix, GitHub, Coinbase, Binance) |
| **Tech support scams** | `FAKE_ANTIVIRUS` `FAKE_ERROR_PAGE` `FAKE_ERROR_CODE` `FAKE_OS_UI` `SCAM_PHONE_PROMINENT` `SCAM_MULTILANG` `AV_DISMISSAL_PRETEXT` `IP_GEOLOCATION_SCARE` `DATA_THEFT_SCARE` | Fake virus scans, fake Windows dialogs, toll-free scam numbers, "your IP has been compromised" |
| **Malware delivery** | `POWERSHELL_ENCODED` `LOLBIN_COMMAND` `LOLBIN_IN_CONTEXT` `BASE64_PAYLOAD` `MACOS_SHELL` `WEBDAV_MOUNT` `WINHTTP_FULL` | Encoded PowerShell, LOLBins (mshta, certutil, bitsadmin, regsvr32...), base64 payloads, macOS osascript |
| **Social engineering** | `URGENCY` `FAKE_COUNTDOWN` `FAKE_SOCIAL_PROOF` `FAKE_SOFTWARE_DL` `FAKE_UPDATE` `FAKE_DOWNLOAD_BUTTON` `FAKE_MEETING` `FAKE_BROWSER_ERROR` | Countdown timers, fake user counts, cracked-software lures, fake browser updates |
| **Browser hijacking** | `BROWSER_LOCK` `FULLSCREEN_SPAM` `PRINT_LOOP` `HISTORY_LOOP` `NOTIFICATION_SPAM` `DIALOG_SPAM` `URL_CREATE_LOOP` | Fullscreen abuse, back-button traps, print spam, alert loops |
| **Clipboard attacks** | `CLIPBOARD_HIJACK` `CLIPBOARD_SOURCE` | Silent clipboard overwrite with malicious commands |
| **Crypto threats** | `CRYPTO_ADDRESS_SWAP` `CRYPTO_ADDRESSES_LISTED` `CRYPTO_WALLET` `CRYPTO_WALLET_PHISHING` | Wallet address swapping, connect-wallet drainers, seed phrase harvesting |
| **Data theft** | `CARD_SKIMMER_ENHANCED` `FORMJACKING` `KEYLOGGER_PATTERN` `CREDENTIAL_EXFIL_FETCH` | Magecart-style skimmers, keyloggers, form data exfiltration |
| **Obfuscation / evasion** | `OBFUSCATION` `OBFUSCATION_HEAVY` `EVAL_DYNAMIC` `STEGANOGRAPHY` `HIDDEN_CONTENT` `HEX_IP` | _0x variable mangling, eval(atob(...)), anti-debug traps, pixel-encoded payloads |
| **Combo signals** | `BONUS_SCAM_FULLKIT` `BONUS_PS_CLIPBOARD` `BONUS_VISUAL_PHISH` `BONUS_LOLBIN_INSTRUCTION` `BONUS_CAPTCHA_INSTRUCTION` `BONUS_CRYPTO_LOOKALIKE` | Score multipliers when multiple threat signals appear on the same page |
  
Every detection returns **matched keywords** - the specific strings, commands, or patterns that triggered it, so you can see exactly what Nehboro found.

---

## How scoring works

Each detection has a base score. Scores from all triggered detections are summed:

| Total score | Verdict | Action |
|---|---|---|
| **0 – 44** | Clean | No action. Badge shows ✅. |
| **45 – 78** | ⚠️ Warning | Yellow banner with expandable details. User can dismiss or report. |
| **79 – 109** | 🚨 Block | Page is replaced with a block screen. Full detection breakdown shown. |
| **≥ 110** | 🚨 Block + Auto-report | Blocked AND automatically reported to community threat intelligence. |

All thresholds are configurable in the Config tab.

---

## Silent Mode

For the person in your life who should never see a "PowerShell" warning:

**Silent Mode** raises the block threshold to 99 and removes all warning banners. Dangerous pages (score ≥ 99) are silently closed - no scary dialogs, no choices to make, no "are you sure?" The tab just disappears.

Enable it in **Config → Silent Mode**.

---

## Community reports

When a user reports a page (or a page hits the auto-report threshold of 110), a report is sent to `ntfy.sh/nehboro-reports` containing:

- The URL and hostname
- All detections that fired, with scores
- **Every matched keyword/pattern** per detection (so analysts can see exactly what triggered)
- **All URLs extracted from the page** (links, script sources, form actions, iframes)
- Page metadata (title, forms, scripts, referrer)

Reports are aggregated by a GitHub Action and displayed at [nehboro.github.io/reports](https://nehboro.github.io/reports/) - browsable, filterable, with permalinks for each report.

---

## Threat feeds

The Static IOC engine blocks known-bad infrastructure **before** the page loads, using `chrome.declarativeNetRequest`. Feeds are fetched from [nehboro.github.io/feeds](https://github.com/Nehboro/nehboro.github.io/tree/main/feeds) regularly:

| Feed | Format | Content |
|---|---|---|
| `domains.csv` | Domains, wildcards | `evil.com`, `*.evil.com` |
| `urls.csv` | Full URLs, wildcards | `https://evil.com/gate.php` |
| `ips.csv` | IPs, CIDR, wildcards | `1.2.3.4`, `10.0.0.0/24` |
| `ports.csv` | Ports, ranges | `4444`, `8080-8085` |

You can add your own custom feeds in the **IOC Feeds** tab.

note: a huge list of bad AS IP range, urlhaus clickfix reports, some ports, and a huge list of domains related to phishing are included by default!

---

## Languages

Nehboro is **fully multilingual** (currently English and French).

- **Automatic:** The extension automatically detects your browser language.
- **Configurable:** You can manually switch languages in the **Config** tab.
- **Scam Detection:** Our heuristic patterns cover: 🇬🇧 English · 🇫🇷 French · 🇪🇸 Spanish · 🇩🇪 German · 🇮🇹 Italian · 🇧🇷 Portuguese.

> [!TIP]
> Community translations are more than welcome! If you'd like to help localize Nehboro to your language, please open a PR.

---

## CI/CD

Nehboro uses GitHub Actions for quality assurance and automated delivery:
- **Linting:** Every code change is automatically checked for errors and adherence to extension best practices using `web-ext lint`.
- **Automated Builds:** The extension is compiled and packaged into a ZIP file on every push to the main branch.
- **Auto-Releases:** When the `version` in `manifest.json` is incremented on the main branch, a new GitHub Release is automatically created with the compiled extension attached.
- **Chrome Web Store:** Preparation for automated publication to the Chrome Web Store is in place, enabling seamless updates once API keys are configured.

---

## Install

> [!IMPORTANT]
> **Download the Latest Version**: You can always find the latest ready-to-use ZIP file in the [GitHub Releases](https://github.com/Nehboro/nehboro/releases).

### Manual install (developer mode)

```bash
# 1. Clone or download
git clone https://github.com/Nehboro/nehboro.git

# 2. Load in Chrome / Edge
#    → chrome://extensions
#    → Enable "Developer mode" (top right)
#    → Click "Load unpacked"
#    → Select the nehboro/ folder

# 3. (Optional) Add Claude AI
#    → Click Nehboro icon → Config tab
#    → Paste your Anthropic API key (sk-ant-...)

# 4. (Optional) Enable Silent Mode
#    → Config tab → Enable Silent Mode ☑
```

---

## Architecture

```
nehboro/
├── manifest.json              # Chrome MV3 manifest
├── background.js              # Service worker: feeds, ntfy reporting, badge, context menu
├── content/
│   ├── detector.js            # Detection orchestrator: scoring, banners, blocking, enrichment
│   └── runtime-interceptor.js # MAIN world: intercepts clipboard, print, fullscreen, history
├── detections/                # 78 detection modules (97 detection IDs)
│   ├── _registry.js           # Central NW_register() registry
│   ├── clickfix-sequence.js   # ClickFix full/partial sequence
│   ├── visual-phishing.js     # Brand impersonation (colors, logos, favicon)
│   ├── powershell.js          # Encoded PowerShell detection
│   ├── lolbin.js              # LOLBin commands (standalone + in-context)
│   ├── bonus-combos.js        # Score multipliers for multi-signal pages
│   └── ...                    # 72 more modules
├── utils/
│   ├── patterns.js            # Regex patterns, thresholds, safe domains (1100+)
│   ├── helpers.js             # testAny, countMatches, allMatches, extractUrls, buildContext
│   └── feeds.js               # CSV feed parser
├── popup/
│   ├── popup.html             # Extension popup UI (4 tabs: Shield, IOC Feeds, Dynamic, Config)
│   └── popup.js               # Popup logic: scan results, matched keywords, extracted URLs
├── blocked/
│   ├── blocked.html           # Block page with expandable detection details
│   └── blocked.js             # Block page logic
├── icons/                     # Extension icons (16, 48, 128px)
└── rules/
    └── static_rules.json      # declarativeNetRequest base rules
```

### Detection module anatomy

Every detection is a self-contained IIFE that registers itself:

```javascript
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'CLICKFIX_FULL_SEQUENCE',
    name: 'ClickFix Full Sequence',
    description: 'Complete open-paste-execute instruction sequence',
    defaultScore: 45,
    tags: ['clickfix', 'critical'],
    detect(ctx) {
      const hasOpen    = H.testAny(P.CF_OPEN, ctx.rawText);
      const hasPaste   = H.testAny(P.CF_PASTE, ctx.rawText);
      const hasExecute = H.testAny(P.CF_EXECUTE, ctx.rawText);
      if (hasOpen && hasPaste && hasExecute) {
        return {
          description: 'Complete ClickFix execution sequence detected',
          evidence: H.firstMatch(P.CF_OPEN, ctx.rawText)
        };
      }
      return null;
    }
  });
})();
```

To add a new detection: create a file in `detections/`, call `NW_register()`, and it's automatically picked up. No imports, no config changes.

---

## URL Scanner

The [web-based URL scanner](https://nehboro.github.io/scan/) runs Nehboro's **static** detection engine client-side:

- Detection modules loaded from `cdn.jsdelivr.net/gh/Nehboro/nehboro@main/`
- Target HTML fetched via `api.allorigins.win` (public CORS proxy)
- No backend, no signup, no data stored server-side
- Reports to the same `ntfy.sh/nehboro-reports` community feed

> **Note:** The web scanner only runs pattern-matching detections on raw HTML. Runtime detections (clipboard hijack, print loops, notification spam, history traps, fullscreen abuse) require the browser extension.

---

## Privacy

- **No telemetry.** Nehboro never phones home, never tracks browsing, never sends analytics, only reported sites data are sent for the community to improve the feed for everyone.
- **No remote servers.** All detection happens locally in your browser. Feed CSVs are fetched from GitHub Pages (static files).
- **Reports are opt-in.** Manual reports require clicking a button. Auto-reports only fire at score ≥ 110 and are rate-limited (24h dedup per URL).
- **Claude AI is optional.** Disabled by default. When enabled, only page metadata (URL, title, forms, scripts) is sent - never cookies, passwords, or page content.
- **1100+ trusted domains** are whitelisted and never scanned (Google, Microsoft, banking, social media, etc.)

---

## Contributing

### Report a threat
Use the 🚩 **Report Page** button in the extension, or [scan a URL](https://nehboro.github.io/scan/) on the website.

### Add a detection
1. Create a new `.js` file in `detections/`
2. Call `NW_register()` with your detection logic
3. Test against real threat pages
4. Open a PR

### Add to feeds
Open a PR on [nehboro.github.io](https://github.com/Nehboro/nehboro.github.io) modifying the CSV files in `/feeds/`.

### Report a false positive
Open an [issue](https://github.com/Nehboro/nehboro/issues) with the URL that was incorrectly flagged.

---

## Credits

Built by [mthcht](https://github.com/mthcht)

Inspired by real-world ClickFix campaigns, tech support scam infrastructure, and the people who fall for them - because everyone deserves a safer browser, especially your grandma.

---

<p align="center">
  <img src="https://img.shields.io/badge/made_with-♥-red?style=flat-square" alt="Made with love" />
  <img src="https://img.shields.io/badge/grandma-protected-green?style=flat-square" alt="Grandma protected" />
</p>
