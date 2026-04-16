// ============================================================
// Nehboro - content/detector.js
// Orchestrator - runs all registered detections, scores, alerts
// ============================================================

(function () {
  'use strict';

  const PATTERNS    = window.NW_PATTERNS;
  const HELPERS     = window.NW_HELPERS;
  const DETECTIONS  = window.NW_DETECTIONS;
  if (!PATTERNS || !HELPERS || !DETECTIONS) return;

  // Guard against re-injection (scripts loaded twice)
  if (window.__nehboro_detector_loaded) return;
  window.__nehboro_detector_loaded = true;

  if (location.href.startsWith('chrome-extension://') || location.href.startsWith('moz-extension://')) return;
  if (HELPERS.isOnSafeDomain()) return;

  // ── State ──────────────────────────────────────────────────
  let allFindings   = [];
  let totalScore    = 0;
  let warningShown  = false;
  let scanComplete  = false;
  let autoReported  = false;   // prevent report spam
  let blockPending  = false;   // prevent re-scans after block decision
  let bgReported    = false;   // prevent duplicate NW_PAGE_SCAN
  let domObserver   = null;    // reference to disconnect later

  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  function addFindings(newFindings) {
    for (const f of newFindings) {
      if (!allFindings.find(e => e.category === f.category)) {
        allFindings.push(f);
        totalScore += f.score;
      }
    }
  }

  // Map detection IDs to pattern groups in PATTERNS to extract ALL matched keywords
  const PATTERN_GROUPS_BY_DETECTION = {
    'CLICKFIX_FULL_SEQUENCE': ['CF_OPEN', 'CF_PASTE', 'CF_EXECUTE'],
    'CLICKFIX_PARTIAL': ['CF_OPEN', 'CF_PASTE', 'CF_EXECUTE'],
    'CLICKFIX_PRETEXT': ['CF_PRETEXT', 'CF_OPEN'],
    'CLICKFIX_MULTILANG': ['CF_MULTILANG_FR', 'CF_MULTILANG_ES', 'CF_MULTILANG_DE', 'CF_MULTILANG_IT', 'CF_MULTILANG_PT'],
    'POWERSHELL_ENCODED': ['PS_ENCODED'],
    'POWERSHELL_PARTIAL': ['PS_ENCODED', 'PS_PARTIAL'],
    'LOLBIN_IN_CONTEXT': ['LOLBIN_ALL'],
    'LOLBIN_COMMAND': ['LOLBIN_ALL'],
    'CAPTCHA_TEXT': ['CAPTCHA_TEXT'],
    'FAKE_VERIFICATION_ID': ['VERIFICATION_ID'],
    'FAKE_CLOUDFLARE_TEXT': ['CLOUDFLARE_TEXT', 'CAPTCHA_TEXT'],
    'FAKE_CLOUDFLARE_DOMAIN': ['CF_DOMAINS'],
    'URGENCY': ['URGENCY'],
    'FAKE_SOFTWARE_DL': ['FAKE_SOFTWARE'],
    'OBFUSCATION': ['OBFUSCATION'],
    'OBFUSCATION_HEAVY': ['OBFUSCATION'],
    'SUSPICIOUS_TLD': ['SUSPICIOUS_TLDS'],
    'SUSPICIOUS_TERMS': ['SUSPICIOUS_TERMS'],
  };

  function enrichFinding(finding, ctx) {
    const groupNames = PATTERN_GROUPS_BY_DETECTION[finding.category];
    if (!groupNames) return finding;
    const text = (ctx.rawText || '') + '\n' + (ctx.pageHTML || '');
    const matched = [];
    const seen = new Set();
    for (const groupName of groupNames) {
      const group = PATTERNS[groupName];
      if (!group) continue;
      // SUSPICIOUS_TERMS is a Set of strings, others are arrays of regexes
      if (group instanceof Set) {
        const lowerText = text.toLowerCase();
        for (const term of group) {
          if (lowerText.includes(term.toLowerCase())) {
            const k = term.toLowerCase();
            if (!seen.has(k)) { seen.add(k); matched.push(term); }
          }
        }
      } else if (Array.isArray(group)) {
        const items = HELPERS.allMatches ? HELPERS.allMatches(group, text, 30) : [];
        for (const m of items) {
          const k = m.toLowerCase().substring(0, 80);
          if (!seen.has(k)) { seen.add(k); matched.push(m); }
        }
      }
    }
    if (matched.length > 0) finding.matches = matched.slice(0, 30);
    return finding;
  }

  function runDetection(det, ctx, customScores, existingFindings) {
    try {
      const result = det._postProcess ? det.detect(ctx, existingFindings) : det.detect(ctx);
      if (!result) return [];
      const results = Array.isArray(result) ? result : [result];
      return results.map(r => {
        let score;
        if (customScores[det.id] !== undefined) score = customScores[det.id];
        else if (r.scoreOverride !== undefined)  score = r.scoreOverride;
        else score = det.defaultScore;
        if (r.scoreMultiplier) score *= r.scoreMultiplier;
        if (r.scoreCap) score = Math.min(score, r.scoreCap);
        if (r.scoreBonus) score += r.scoreBonus;
        const finding = {
          category: det.id,
          name: det.name,
          description: r.description,
          evidence: r.evidence || '',
          // If detection itself returned matches, use those; otherwise we'll enrich after
          matches: r.matches || undefined,
          score: Math.round(score),
          tags: det.tags
        };
        return enrichFinding(finding, ctx);
      });
    } catch (e) {
      console.warn(`[Nehboro] Detection ${det.id} error:`, e);
      return [];
    }
  }

  function reportToBackground(findings, score, blocked) {
    if (bgReported && !blocked) return; // only send once unless it's a block upgrade
    bgReported = true;
    let meta = {};
    try { meta = collectMeta(); } catch {}
    chrome.runtime.sendMessage({ type: 'NW_PAGE_SCAN', url: window.location.href, hostname: window.location.hostname, findings, score, blocked, meta, timestamp: Date.now() }).catch(() => {});
  }

  // ── Warning banner with expandable details ─────────────────
  function showWarningBanner(findings, score) {
    if (warningShown || document.getElementById('__nw_warning_banner__')) return;
    warningShown = true;
    const topCategories = findings.slice(0, 3).map(f => (f.name || f.category).replace(/_/g, ' ')).join(', ');
    const isBlock = score >= PATTERNS.THRESHOLD.BLOCK;
    const accent = isBlock ? '#e74c3c' : '#f39c12';

    const wrapper = document.createElement('div');
    wrapper.id = '__nw_warning_banner__';
    wrapper.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;font-family:system-ui,-apple-system,sans-serif;box-shadow:0 2px 16px rgba(0,0,0,0.5);';

    const rows = findings.map((f, i) => {
      const name = esc((f.name || f.category || '').replace(/_/g, ' '));
      const desc = esc(f.description || '');
      const ev = esc(f.evidence || '');
      const tags = (f.tags || []).map(t => `<span style="all:initial;font-size:9px;background:#2a2a4a;padding:1px 5px;border-radius:3px;color:#7a7a9a;font-family:inherit;${t==='critical'?'color:#e74c3c;border:1px solid #3d1010;':''}">${esc(t)}</span>`).join(' ');
      const scoreColor = f.score >= 30 ? '#e74c3c' : f.score >= 15 ? '#f39c12' : '#2980b9';
      return `<div style="all:initial;display:block;font-family:inherit;">
        <div data-nw-row="${i}" style="all:initial;display:flex;align-items:center;gap:8px;padding:7px 16px;cursor:pointer;font-family:inherit;border-bottom:1px solid #2a2a4a;background:#12121e;">
          <span data-nw-arrow="${i}" style="all:initial;font-size:10px;color:#555;font-family:monospace;">▶</span>
          <span style="all:initial;flex:1;font-size:12px;color:#ddd;font-weight:600;font-family:inherit;">${name}</span>
          <span style="all:initial;font-size:11px;font-weight:700;color:${scoreColor};font-family:inherit;">+${f.score}</span>
        </div>
        <div data-nw-detail="${i}" style="all:initial;display:none;padding:6px 16px 10px 34px;background:#0f0f1a;border-bottom:1px solid #2a2a4a;font-family:inherit;">
          <div style="all:initial;font-size:11px;color:#aaa;margin-bottom:4px;font-family:inherit;">${desc}</div>
          ${ev ? `<div style="all:initial;font-size:9px;color:#555;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px;font-family:inherit;">Matched content</div><div style="all:initial;font-size:10px;color:#7a7a9a;font-family:monospace;word-break:break-all;background:#0a0a14;padding:6px 8px;border-radius:4px;margin-bottom:4px;max-height:100px;overflow-y:auto;display:block;line-height:1.4;">${ev}</div>` : ''}
          ${tags ? `<div style="all:initial;display:flex;gap:4px;flex-wrap:wrap;font-family:inherit;margin-top:3px;">${tags}</div>` : ''}
        </div>
      </div>`;
    }).join('');

    wrapper.innerHTML = `
      <div style="all:initial;display:flex;align-items:center;justify-content:space-between;gap:12px;background:#1a1a2e;padding:10px 16px;border-bottom:3px solid ${accent};font-family:inherit;">
        <div style="all:initial;display:flex;align-items:center;gap:10px;font-family:inherit;">
          <div>
            <div style="all:initial;font-weight:700;color:${accent};font-family:inherit;font-size:14px;display:flex;align-items:center;gap:6px;"><img src="${chrome.runtime.getURL('icons/icon48.png')}" style="width:22px;height:22px;"> Nehboro - ${isBlock?'DANGER':'WARNING'} (Score: ${score})</div>
            <div style="all:initial;color:#ccc;font-size:12px;font-family:inherit;margin-top:2px;">${topCategories}</div>
          </div>
        </div>
        <div style="all:initial;display:flex;gap:8px;font-family:inherit;">
          <button data-nw-action="report" style="all:initial;background:#e74c3c;color:#fff;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-family:inherit;display:flex;align-items:center;gap:4px;"><img src="${chrome.runtime.getURL('icons/report-flag.png')}" style="width:20px;height:20px;vertical-align:middle;"> Report</button>
          <button data-nw-action="trust" style="all:initial;background:#27ae60;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-family:inherit;">✓ Trust</button>
          <button data-nw-action="toggle" style="all:initial;background:#2980b9;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-family:inherit;">▼ Details (${findings.length})</button>
          <button data-nw-action="dismiss" style="all:initial;background:transparent;color:#999;border:1px solid #555;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-family:inherit;">✕</button>
        </div>
      </div>
      <div data-nw-panel style="all:initial;display:none;max-height:300px;overflow-y:auto;background:#12121e;font-family:inherit;">${rows}</div>`;

    document.documentElement.appendChild(wrapper);

    let panelOpen = false;
    wrapper.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-nw-action]');
      if (btn) {
        const action = btn.dataset.nwAction;
        if (action === 'toggle') {
          panelOpen = !panelOpen;
          wrapper.querySelector('[data-nw-panel]').style.display = panelOpen ? 'block' : 'none';
          btn.textContent = panelOpen ? `▲ Hide (${findings.length})` : `▼ Details (${findings.length})`;
        } else if (action === 'report') {
          chrome.runtime.sendMessage({ type: 'NW_COMMUNITY_REPORT', url: window.location.href, findings, score, meta: collectMeta() });
          btn.textContent = '✓ Reported'; btn.disabled = true;
        } else if (action === 'trust') {
          chrome.runtime.sendMessage({ type: 'NW_WHITELIST_DOMAIN', domain: window.location.hostname });
          const note = document.createElement('div');
          note.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#0a2e1e;color:#00ff88;font-family:system-ui;font-size:13px;padding:10px 16px;text-align:center;border-bottom:2px solid #00ff88;';
          note.textContent = `✅ ${window.location.hostname} added to trusted domains.`;
          document.documentElement.appendChild(note);
          setTimeout(() => note.remove(), 3000);
          wrapper.remove();
        } else if (action === 'dismiss') {
          recordDismiss(window.location.hostname).then(info => {
            if (info.count >= 3) {
              // Show auto-trusted notification inline before removing
              const note = document.createElement('div');
              note.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#0a2e1e;color:#00ff88;font-family:system-ui;font-size:13px;padding:10px 16px;text-align:center;border-bottom:2px solid #00ff88;';
              note.textContent = `✅ ${window.location.hostname} auto-trusted after 3 dismissals. No more warnings for this site.`;
              document.documentElement.appendChild(note);
              setTimeout(() => note.remove(), 4000);
            }
          });
          wrapper.remove();
        }
        return;
      }
      const row = e.target.closest('[data-nw-row]');
      if (row) {
        const i = row.dataset.nwRow;
        const detail = wrapper.querySelector(`[data-nw-detail="${i}"]`);
        const arrow = wrapper.querySelector(`[data-nw-arrow="${i}"]`);
        const open = detail.style.display === 'none';
        detail.style.display = open ? 'block' : 'none';
        if (arrow) arrow.textContent = open ? '▼' : '▶';
      }
    });
  }

  // ── Block page ─────────────────────────────────────────────
  function blockPage(findings, score) {
    blockPending = true;
    // Disconnect observer to stop any further re-scans
    if (domObserver) { domObserver.disconnect(); domObserver = null; }
    clearTimeout(window._nwMutationTimer);
    // Store full findings for the blocked page
    chrome.storage.local.set({ nehboro_block_details: { findings, score, url: window.location.href, ts: Date.now() } });
    const params = new URLSearchParams({ url: window.location.href, score: String(score), reasons: findings.slice(0, 5).map(f => f.category).join(',') });
    window.location.replace(chrome.runtime.getURL('blocked/blocked.html') + '?' + params.toString());
  }

  function checkBypass(hostname) {
    return new Promise(resolve => {
      try { chrome.runtime.sendMessage({ type: 'NW_CHECK_BYPASS', hostname }, r => resolve(!!(r && r.bypassed))); }
      catch { resolve(false); }
    });
  }

  function collectMeta() {
    let extractedUrls = [];
    try {
      const ctx = HELPERS?.buildContext?.();
      if (HELPERS?.extractUrls && ctx) extractedUrls = HELPERS.extractUrls(ctx);
    } catch {}
    return {
      title: document.title || '', lang: document.documentElement.lang || '',
      description: (document.querySelector('meta[name="description"]')?.content || '').substring(0, 200),
      forms: document.forms.length,
      inputs: document.querySelectorAll('input[type="password"], input[type="text"], input[type="email"]').length,
      externalScripts: [...document.querySelectorAll('script[src]')].filter(s => { try { return new URL(s.src).hostname !== location.hostname; } catch { return false; } }).length,
      iframes: document.querySelectorAll('iframe').length, links: document.links.length,
      referrer: document.referrer || '', protocol: location.protocol, port: location.port || '',
      extractedUrls: extractedUrls.slice(0, 100),
    };
  }

  // ── Dismiss tracking helpers ─────────────────────────────
  async function getDismissInfo(hostname) {
    const key = `nehboro_dismiss_${hostname}`;
    const data = await chrome.storage.local.get(key);
    return data[key] || { count: 0, lastDismiss: 0 };
  }

  async function recordDismiss(hostname) {
    const key = `nehboro_dismiss_${hostname}`;
    const info = await getDismissInfo(hostname);
    info.count++;
    info.lastDismiss = Date.now();
    await chrome.storage.local.set({ [key]: info });

    // Auto-whitelist after 3 dismissals
    if (info.count >= 3) {
      const { nehboro_whitelist: wl = [] } = await chrome.storage.local.get('nehboro_whitelist');
      if (!wl.includes(hostname)) {
        wl.push(hostname);
        await chrome.storage.local.set({ nehboro_whitelist: wl });
        // Inform user via notification
        chrome.runtime.sendMessage({ type: 'NW_NOTIFY', title: 'Nehboro', message: `${hostname} auto-trusted after 3 dismissals.` }).catch(() => {});
      }
    }
    return info;
  }

  async function isWhitelisted(hostname) {
    const { nehboro_whitelist: wl = [] } = await chrome.storage.local.get('nehboro_whitelist');
    return wl.some(w => hostname === w || hostname.endsWith('.' + w));
  }

  // ── Main scan ──────────────────────────────────────────────
  async function runScan() {
    if (scanComplete || blockPending) return;

    // Check whitelist - trusted domains get no scanning, no warnings, no reports
    if (await isWhitelisted(window.location.hostname)) return;

    const stored = await chrome.storage.local.get(['nehboro_thresholds', 'nehboro_custom_scores']);
    if (blockPending) return;

    const t = stored.nehboro_thresholds || {};
    const customScores = stored.nehboro_custom_scores || {};
    const silentMode = !!t.silentMode;

    // Silent mode overrides: threshold 99, no banners
    const WARN_THRESHOLD  = silentMode ? 9999 : (t.warn  ?? PATTERNS.THRESHOLD.WARN);
    const BLOCK_THRESHOLD = silentMode ? 99   : (t.block ?? PATTERNS.THRESHOLD.BLOCK);
    const showBanners     = silentMode ? false : (t.showBanners !== false);
    const autoReport      = t.autoReport  !== false;

    const ctx = HELPERS.buildContext();

    // Phase 1: Normal detections
    for (const det of DETECTIONS.filter(d => !d._postProcess)) addFindings(runDetection(det, ctx, customScores, []));
    // Phase 2: Combo detections
    for (const det of DETECTIONS.filter(d => d._postProcess)) addFindings(runDetection(det, ctx, customScores, allFindings));

    scanComplete = true;
    if (totalScore === 0) return;
    reportToBackground(allFindings, totalScore, totalScore >= BLOCK_THRESHOLD);

    // Auto-report only at score >= 100 (high confidence threats only)
    if (autoReport && !autoReported && totalScore >= 110) {
      autoReported = true;
      chrome.runtime.sendMessage({ type: 'NW_COMMUNITY_REPORT', url: window.location.href, findings: allFindings, score: totalScore, meta: collectMeta() }).catch(() => {});
    }

    if (totalScore >= BLOCK_THRESHOLD) {
      blockPending = true;

      if (silentMode) {
        // Silent mode: close tab quietly and open a new empty tab
        chrome.runtime.sendMessage({ type: 'NW_SILENT_BLOCK', url: window.location.href, score: totalScore }).catch(() => {});
        return;
      }

      const hostname = window.location.hostname;
      const bypassed = await checkBypass(hostname);
      if (bypassed) {
        blockPending = false;
        if (showBanners) {
          const dismissInfo = await getDismissInfo(hostname);
          const dismissedRecently = (Date.now() - dismissInfo.lastDismiss) < 60 * 60 * 1000;
          if (!dismissedRecently) showWarningBanner(allFindings, totalScore);
        }
        return;
      }
      blockPage(allFindings, totalScore);
    } else if (showBanners && totalScore >= WARN_THRESHOLD) {
      const hostname = window.location.hostname;
      const dismissInfo = await getDismissInfo(hostname);
      const dismissedRecently = (Date.now() - dismissInfo.lastDismiss) < 60 * 60 * 1000;
      if (!dismissedRecently) showWarningBanner(allFindings, totalScore);
    }
  }

  // ── Runtime findings from MAIN world (postMessage bridge) ───
  window.addEventListener('message', async function (event) {
    if (event.source !== window) return;
    if (!event.data || !event.data.__nehboro || event.data.type !== '__NW_FINDING__') return;
    if (blockPending) return;

    const finding = event.data.detail;
    if (!finding || !finding.category) return;

    addFindings([finding]);
    const stored = await chrome.storage.local.get('nehboro_thresholds');
    const t = stored.nehboro_thresholds || {};
    const silentMode = !!t.silentMode;

    // Silent mode: auto-close if score hits 99
    if (silentMode && totalScore >= 99) {
      blockPending = true;
      chrome.runtime.sendMessage({ type: 'NW_SILENT_BLOCK', url: window.location.href, score: totalScore }).catch(() => {});
      return;
    }

    if (!silentMode && (t.showBanners !== false) && (finding.critical || totalScore >= (t.warn ?? PATTERNS.THRESHOLD.WARN)))
      showWarningBanner(allFindings, totalScore);
    reportToBackground(allFindings, totalScore, false);
  });

  // Also keep CustomEvent listener for backward compatibility
  window.addEventListener('__NW_FINDING__', async function (event) {
    if (blockPending) return;
    addFindings([event.detail]);
    const stored = await chrome.storage.local.get('nehboro_thresholds');
    const t = stored.nehboro_thresholds || {};
    const silentMode = !!t.silentMode;

    if (silentMode && totalScore >= 99) {
      blockPending = true;
      chrome.runtime.sendMessage({ type: 'NW_SILENT_BLOCK', url: window.location.href, score: totalScore }).catch(() => {});
      return;
    }

    if (!silentMode && (t.showBanners !== false) && (event.detail.critical || totalScore >= (t.warn ?? PATTERNS.THRESHOLD.WARN)))
      showWarningBanner(allFindings, totalScore);
    reportToBackground(allFindings, totalScore, false);
  });

  // ── Messages from popup / background ───────────────────────
  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.type === 'NW_MANUAL_SCAN') {
      allFindings = []; totalScore = 0; scanComplete = false;
      blockPending = false; autoReported = false; bgReported = false;
      runScan().then(() => {
        const result = { findings: allFindings, score: totalScore };
        // Store result for reliable retrieval by background
        chrome.storage.local.set({
          nehboro_manual_scan: { ...result, hostname: window.location.hostname, url: window.location.href, ts: Date.now() }
        });
        try { sendResponse(result); } catch {}
      });
      return true;
    }
    if (msg.type === 'NW_FEED_MATCH') {
      addFindings([{ category: 'FEED_MATCH', name: 'Threat Feed Match', description: `URL matched threat feed: ${msg.feedName}`, evidence: msg.matchedEntry || window.location.href, score: PATTERNS.SCORES.FEED_MATCH }]);
      blockPage(allFindings, totalScore);
    }
    if (msg.type === 'NW_GET_DETECTIONS') {
      const list = DETECTIONS.map(d => ({ id: d.id, name: d.name, description: d.description, defaultScore: d.defaultScore, tags: d.tags || [] }));
      sendResponse({ detections: list, count: list.length });
      return;
    }
  });

  // ── Run scan at the right moment ───────────────────────────
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', runScan);
  else runScan();

  // Delayed re-scan for JS-heavy pages (only if first scan found nothing)
  setTimeout(() => { if (totalScore === 0 && !blockPending) { scanComplete = false; runScan(); } }, 2000);

  // ── DOM mutation observer for SPAs ─────────────────────────
  // Only re-scans if no block is pending and score was previously 0
  // This prevents infinite re-scan loops on pages with timers/animations
  if (document.body) {
    domObserver = new MutationObserver(() => {
      if (blockPending) return;
      clearTimeout(window._nwMutationTimer);
      window._nwMutationTimer = setTimeout(async () => {
        if (blockPending || !scanComplete) return;
        // Only re-scan if we haven't found threats yet
        // Pages with active threats don't need re-scanning - they're already flagged
        if (totalScore > 0) return;
        scanComplete = false;
        allFindings = allFindings.filter(f => f.category === 'FEED_MATCH');
        totalScore = allFindings.reduce((s, f) => s + f.score, 0);
        bgReported = false;
        await runScan();
      }, 600);
    });
    domObserver.observe(document.body, { childList: true, subtree: true, characterData: true });
  }

})();
