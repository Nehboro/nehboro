// ============================================================
// Nehboro - background.js
// Service Worker: GitHub Pages feeds, CIDR/wildcard/port rules
// ============================================================

// ── Config ───────────────────────────────────────────────
const FEEDS_BASE = 'https://nehboro.github.io/feeds';
const DEFAULT_FEEDS = {
  domains: `${FEEDS_BASE}/domains.csv`,
  urls:    `${FEEDS_BASE}/urls.csv`,
  ips:     `${FEEDS_BASE}/ips.csv`,
  ports:   `${FEEDS_BASE}/ports.csv`,
};

// ── ntfy.sh reporting config ─────────────────────────────
// Replace NTFY_TOPIC with your own secret topic name.
// Reports auto-delete after 12h (free tier).
// Read at: https://ntfy.sh/YOUR_TOPIC  or  curl https://ntfy.sh/YOUR_TOPIC/json?poll=1
const NTFY_TOPIC = 'nehboro-reports';
const NTFY_URL   = `https://ntfy.sh/${NTFY_TOPIC}`;

// Bypass rule IDs - higher priority (100) than block rules (10)
// so an "allow" action overrides a "block" for consciously bypassed sites
const BYPASS_RULE_ID_BASE = 90000;
const BYPASS_DURATION_MS  = 30 * 60 * 1000; // 30 minutes

// DNR budget split across types
const DNR_BUDGET = {
  domains: 2000,
  urls:    1000,
  ips:     1000,   // individual IPs + expanded CIDRs + aligned CIDR wildcards
  ports:    500,
};
const RULE_ID_BASE = 100000;
const FEED_REFRESH_MINUTES = 360; // 6 hours

// ── Storage keys ─────────────────────────────────────────
const STORE = {
  CUSTOM_FEEDS:  'nehboro_custom_feeds',
  BLOCKED:       'nehboro_blocked',
  STATS:         'nehboro_stats',
  WHITELIST:     'nehboro_whitelist',
  LAST_REFRESH:  'nehboro_last_refresh',
  THRESHOLDS:    'nehboro_thresholds',
};

// ── Inline feed utilities (mirror of utils/feeds.js) ─────
// We duplicate the critical parts here because the service worker
// scope cannot import content-script utilities directly.

function parseFeed(rawText, type) {
  const text = (rawText || '').trim();
  if (!text) return [];

  if (text.startsWith('[') || text.startsWith('{')) {
    try {
      const p = JSON.parse(text);
      const arr = Array.isArray(p) ? p : (p.data || p.iocs || p[type] || []);
      return arr.map(i => typeof i === 'string' ? i : (i.ioc || i.indicator || '')).filter(Boolean);
    } catch {}
  }

  const SAFE = new Set(['google.com','bing.com','duckduckgo.com','cloudflare.com',
    'github.com','githubusercontent.com','nehboro.github.io',
    'microsoft.com','office.com','apple.com','icloud.com','facebook.com',
    'twitter.com','x.com','youtube.com','reddit.com','amazon.com','wikipedia.org']);

  const lines  = text.split('\n');
  let   start  = 0;
  // Skip header row if first non-empty line looks like column names
  const first  = (lines[0] || '').replace(/["']/g, '').trim();
  if (lines.length > 1 && /^[a-z ,_-]+$/i.test(first) && !looksLikeIOC(first, type)) start = 1;

  const entries = [];
  for (let i = start; i < lines.length; i++) {
    let line = lines[i].trim();
    if (!line || '#//;'.includes(line[0])) continue;

    // Hosts-file format
    if (/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+/.test(line)) {
      line = line.replace(/^[^\s]+\s+/, '').split(/\s/)[0].toLowerCase();
    } else {
      line = line.split(',')[0].replace(/^["']|["']$/g, '').trim();
    }

    if (type === 'domains') {
      line = line.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
    } else if (type === 'ports') {
      const m = line.match(/(\d{1,5}(?:-\d{1,5})?)/);
      if (!m) continue;
      line = m[1];
    }

    if (!line) continue;

    // Safety filter for domains
    if (type === 'domains') {
      const bare = line.replace(/^\*\./, '');
      const tld2 = bare.split('.').slice(-2).join('.');
      if (SAFE.has(bare) || SAFE.has(tld2)) continue;
    }

    entries.push(line);
  }
  return [...new Set(entries)];
}

function looksLikeIOC(str, type) {
  if (type === 'domains') return /[a-z0-9*][a-z0-9.*-]*\.[a-z]{2,}/i.test(str);
  if (type === 'ips')     return /\d+\.\d+/.test(str);
  if (type === 'urls')    return /^https?:\/\//i.test(str);
  if (type === 'ports')   return /^\d{1,5}/.test(str);
  return false;
}

// ── CIDR helpers ─────────────────────────────────────────
function isCIDR(str)     { return /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(str); }
function isWildcard(str) { return str.includes('*') || str.includes('?'); }

function ipToInt(ip) {
  return ip.split('.').reduce((a, o) => ((a << 8) + parseInt(o, 10)) >>> 0, 0) >>> 0;
}
function intToIP(n) {
  return `${(n>>>24)&255}.${(n>>>16)&255}.${(n>>>8)&255}.${n&255}`;
}

// Aligned CIDRs (/8,/16,/24,/32) → single DNR urlFilter pattern
function cidrToUrlFilter(cidr) {
  const [ip, bstr] = cidr.split('/');
  const bits = parseInt(bstr, 10);
  const o    = ip.split('.').map(Number);
  if (bits === 32) return `*://${ip}/*`;
  if (bits === 24) return `*://${o[0]}.${o[1]}.${o[2]}.*/*`;
  if (bits === 16) return `*://${o[0]}.${o[1]}.*.*/*`;
  if (bits === 8)  return `*://${o[0]}.*.*.*/*`;
  return null; // non-aligned → webRequest
}

// Expand tiny CIDRs (/28–/32, ≤ 16 IPs) to individual IP strings
function expandSmallCIDR(cidr) {
  const [ip, bstr] = cidr.split('/');
  const bits  = parseInt(bstr, 10);
  if (bits < 28) return null;
  const count   = 1 << (32 - bits);
  const mask    = (~0 << (32 - bits)) >>> 0;
  const network = (ipToInt(ip) & mask) >>> 0;
  return Array.from({ length: count }, (_, i) => intToIP(network + i));
}

// Convert wildcard IOC to DNR urlFilter
function wildcardToFilter(ioc, type) {
  const safe = ioc.replace(/\?/g, '*');
  if (/^https?:\/\//i.test(safe)) return safe;
  if (type === 'domains' || type === 'ips') return `*://${safe}/*`;
  return safe;
}

// CIDR membership check (for webRequest fallback)
function cidrContains(cidr, ip) {
  try {
    const [net, bstr] = cidr.split('/');
    const bits = parseInt(bstr, 10);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipToInt(net) & mask) === (ipToInt(ip) & mask);
  } catch { return false; }
}

// Expand port entry to array of port numbers
function expandPort(entry) {
  entry = String(entry).trim();
  if (/^\d+$/.test(entry)) {
    const p = parseInt(entry, 10);
    return (p > 0 && p <= 65535) ? [p] : [];
  }
  const m = entry.match(/^(\d+)-(\d+)$/);
  if (m) {
    const lo = parseInt(m[1], 10), hi = parseInt(m[2], 10);
    if (lo > hi || hi - lo > 500) return [];
    return Array.from({ length: hi - lo + 1 }, (_, i) => lo + i);
  }
  return [];
}

// ── Install / startup ─────────────────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    await chrome.storage.local.set({
      [STORE.CUSTOM_FEEDS]: [],
      [STORE.STATS]:         { blocked: 0, warned: 0, reported: 0 },
      [STORE.WHITELIST]:     [],
    });
    await refreshAllFeeds();
  }
  await chrome.alarms.create('nehboro_refresh', { periodInMinutes: FEED_REFRESH_MINUTES });
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'nehboro_report', title: '🚩 Report page (Nehboro GitHub Issue)', contexts: ['page'] });
    chrome.contextMenus.create({ id: 'nehboro_trust',  title: '✅ Trust this domain (Nehboro)',        contexts: ['page'] });
  });
});

chrome.alarms.onAlarm.addListener(async ({ name }) => {
  if (name === 'nehboro_refresh') await refreshAllFeeds();

  // Bypass expiry alarms look like "nehboro_bypass_evil.com"
  if (name.startsWith('nehboro_bypass_')) {
    const hostname = name.replace('nehboro_bypass_', '');
    await clearBypass(hostname);
  }
});

// ── Feed fetching ─────────────────────────────────────────
async function fetchFeed(url, type) {
  const r = await fetch(url, { cache: 'no-cache' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return parseFeed(await r.text(), type);
}

// ── Main refresh ──────────────────────────────────────────
async function refreshAllFeeds() {
  console.log('[Nehboro] Refreshing feeds from nehboro.github.io...');

  const { [STORE.CUSTOM_FEEDS]: customFeeds = [] } = await chrome.storage.local.get(STORE.CUSTOM_FEEDS);

  // Build feed URL map per type
  const feedMap = {};
  for (const type of Object.keys(DEFAULT_FEEDS)) feedMap[type] = [DEFAULT_FEEDS[type]];
  for (const cf of customFeeds) {
    if (!feedMap[cf.type]) feedMap[cf.type] = [];
    feedMap[cf.type].push(cf.url);
  }

  // Categorised IOC buckets
  const raw = { domains: [], urls: [], ips: [], ports: [] };

  for (const [type, urls] of Object.entries(feedMap)) {
    for (const url of urls) {
      try {
        const entries = await fetchFeed(url, type);
        (raw[type] = raw[type] || []).push(...entries);
        console.log(`[Nehboro] +${entries.length} ${type} from ${url.split('/').pop()}`);
      } catch (e) {
        console.warn(`[Nehboro] Feed error (${url}): ${e.message}`);
      }
    }
  }

  // Deduplicate
  for (const k of Object.keys(raw)) raw[k] = [...new Set(raw[k])];

  // Classify IPs into sub-buckets
  const ipPlain    = []; // regular IPs (no wildcard, no CIDR)
  const ipCIDR     = []; // CIDR ranges
  const ipWildcard = []; // wildcard IPs  e.g. 10.0.*.*

  for (const ioc of raw.ips) {
    if (isCIDR(ioc))        ipCIDR.push(ioc);
    else if (isWildcard(ioc)) ipWildcard.push(ioc);
    else                    ipPlain.push(ioc);
  }

  // Classify domains into sub-buckets
  const domainPlain    = raw.domains.filter(d => !isWildcard(d));
  const domainWildcard = raw.domains.filter(d =>  isWildcard(d));

  // Classify URLs
  const urlPlain    = raw.urls.filter(u => !isWildcard(u));
  const urlWildcard = raw.urls.filter(u =>  isWildcard(u));

  // Persist everything for webRequest fallback and popup display
  await chrome.storage.local.set({
    [STORE.BLOCKED]: {
      domainPlain, domainWildcard,
      urlPlain, urlWildcard,
      ipPlain, ipCIDR, ipWildcard,
      ports: raw.ports,
    },
    [STORE.LAST_REFRESH]: Date.now(),
  });

  await applyAllRules({ domainPlain, domainWildcard, urlPlain, urlWildcard, ipPlain, ipCIDR, ipWildcard, ports: raw.ports });

  const totalIOCs = domainPlain.length + domainWildcard.length + urlPlain.length + urlWildcard.length
    + ipPlain.length + ipCIDR.length + ipWildcard.length + raw.ports.length;
  console.log(`[Nehboro] Done - ${totalIOCs} total IOCs loaded`);
}

// ── Rule application ──────────────────────────────────────
async function applyAllRules(buckets) {
  // Clear existing dynamic rules
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  if (existing.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing.map(r => r.id) });
  }

  const rules   = [];
  const overflow = { domains: [], urls: [], ips: [], cidrs: [], wildcards: [] };
  let   id       = RULE_ID_BASE;
  const blockBase = chrome.runtime.getURL('blocked/blocked.html');

  const addRule = (urlFilter, reason, type, blocked = '') => {
    const bParam = blocked ? `&blocked=${encodeURIComponent(blocked)}` : '';
    rules.push({
      id: id++,
      priority: 10,
      action: {
        type: 'redirect',
        redirect: { url: `${blockBase}?reason=${reason}&score=100${bParam}` },
      },
      condition: { urlFilter, resourceTypes: ['main_frame', 'sub_frame'] },
    });
  };

  // ── Domains (plain) ─────────────────────────────────────
  let domainCount = 0;
  for (const domain of buckets.domainPlain) {
    if (domainCount >= DNR_BUDGET.domains) { overflow.domains.push(domain); continue; }
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(domain)) continue;
    rules.push({
      id: id++, priority: 10,
      action: { type: 'redirect', redirect: { url: `${blockBase}?reason=feed_domain&blocked=${encodeURIComponent(domain)}&score=100` } },
      condition: { requestDomains: [domain], resourceTypes: ['main_frame', 'sub_frame'] },
    });
    domainCount++;
  }

  // ── Domains (wildcard) ──────────────────────────────────
  for (const domain of buckets.domainWildcard) {
    if (domainCount >= DNR_BUDGET.domains) { overflow.wildcards.push({ ioc: domain, type: 'domains' }); continue; }
    addRule(wildcardToFilter(domain, 'domains'), 'feed_domain_wildcard', 'domains', domain);
    domainCount++;
  }

  // ── URLs (plain) ────────────────────────────────────────
  let urlCount = 0;
  for (const url of buckets.urlPlain) {
    if (urlCount >= DNR_BUDGET.urls) { overflow.urls.push(url); continue; }
    try { new URL(url); } catch { continue; }
    addRule(url, 'feed_url', 'urls', url);
    urlCount++;
  }

  // ── URLs (wildcard) ─────────────────────────────────────
  for (const url of buckets.urlWildcard) {
    if (urlCount >= DNR_BUDGET.urls) { overflow.wildcards.push({ ioc: url, type: 'urls' }); continue; }
    addRule(wildcardToFilter(url, 'urls'), 'feed_url_wildcard', 'urls', url);
    urlCount++;
  }

  // ── IPs (plain) ─────────────────────────────────────────
  let ipCount = 0;
  for (const ip of buckets.ipPlain) {
    if (ipCount >= DNR_BUDGET.ips) { overflow.ips.push(ip); continue; }
    addRule(`*://${ip}/*`, 'feed_ip', 'ips', ip);
    ipCount++;
  }

  // ── IPs (wildcard) ──────────────────────────────────────
  for (const ip of buckets.ipWildcard) {
    if (ipCount >= DNR_BUDGET.ips) { overflow.wildcards.push({ ioc: ip, type: 'ips' }); continue; }
    addRule(wildcardToFilter(ip, 'ips'), 'feed_ip_wildcard', 'ips', ip);
    ipCount++;
  }

  // ── CIDR ranges ─────────────────────────────────────────
  for (const cidr of buckets.ipCIDR) {
    if (ipCount >= DNR_BUDGET.ips) { overflow.cidrs.push(cidr); continue; }

    // Try aligned wildcard filter first (1 rule)
    const filter = cidrToUrlFilter(cidr);
    if (filter) {
      addRule(filter, 'feed_cidr', 'ips', cidr);
      ipCount++;
      continue;
    }

    // Try small expansion (≤ 16 IPs)
    const expanded = expandSmallCIDR(cidr);
    if (expanded) {
      for (const ip of expanded) {
        if (ipCount >= DNR_BUDGET.ips) { overflow.cidrs.push(cidr); break; }
        addRule(`*://${ip}/*`, 'feed_cidr_expanded', 'ips', cidr);
        ipCount++;
      }
      continue;
    }

    // Non-aligned / large CIDR → webRequest handles it
    overflow.cidrs.push(cidr);
  }

  // ── Ports ───────────────────────────────────────────────
  let portCount = 0;
  for (const entry of buckets.ports) {
    if (portCount >= DNR_BUDGET.ports) break;
    const ports = expandPort(entry);
    for (const p of ports) {
      if (portCount >= DNR_BUDGET.ports) break;
      addRule(`*://*/*:${p}/*`, 'feed_port', 'ports', String(p));
      portCount++;
    }
  }

  if (rules.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({ addRules: rules });
  }

  // Persist overflow for webRequest fallback
  await chrome.storage.local.set({ nehboro_overflow: overflow });

  console.log(`[Nehboro] ${rules.length} DNR rules | overflow: ${overflow.domains.length}d ${overflow.urls.length}u ${overflow.ips.length}ip ${overflow.cidrs.length}cidr ${overflow.wildcards.length}wc`);
}

// ── webRequest fallback ────────────────────────────────────
// Handles: overflow domains/IPs, non-aligned CIDRs, overflow wildcards

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type !== 'main_frame' && details.type !== 'sub_frame') return;

    chrome.storage.local.get(['nehboro_overflow', STORE.WHITELIST], (data) => {
      const ov        = data.nehboro_overflow || {};
      const whitelist = data[STORE.WHITELIST]  || [];

      let hostname, requestIP;
      try {
        const u   = new URL(details.url);
        hostname  = u.hostname;
        requestIP = hostname; // for direct IP connections
      } catch { return; }

      // Whitelist check
      if (whitelist.some(w => hostname === w || hostname.endsWith('.' + w))) return;

      let blocked = false;
      let reason  = '';

      // Overflow plain domains
      if (!blocked) {
        blocked = (ov.domains || []).some(d => hostname === d || hostname.endsWith('.' + d));
        if (blocked) reason = 'feed_domain_overflow';
      }

      // Overflow plain IPs
      if (!blocked) {
        blocked = (ov.ips || []).includes(hostname);
        if (blocked) reason = 'feed_ip_overflow';
      }

      // Non-aligned CIDR ranges
      if (!blocked) {
        blocked = (ov.cidrs || []).some(cidr => cidrContains(cidr, hostname));
        if (blocked) reason = 'feed_cidr_overflow';
      }

      // Overflow wildcard IOCs
      if (!blocked) {
        for (const { ioc } of (ov.wildcards || [])) {
          const regex = new RegExp('^' + ioc.replace(/\./g, '\\.').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
          if (regex.test(hostname) || regex.test(details.url)) {
            blocked = true;
            reason  = 'feed_wildcard_overflow';
            break;
          }
        }
      }

      if (blocked) {
        const blockUrl = chrome.runtime.getURL('blocked/blocked.html')
          + `?reason=${reason}&blocked=${encodeURIComponent(hostname)}&score=100`;
        chrome.tabs.update(details.tabId, { url: blockUrl });
      }
    });
  },
  { urls: ['<all_urls>'] }
);

// ── ntfy.sh Reporting ────────────────────────────────────
// POST a structured report to the private ntfy.sh topic.
// Auto-deletes after 12 hours. No account needed for reporters.
// You read reports at: https://ntfy.sh/NTFY_TOPIC
// or: curl "https://ntfy.sh/NTFY_TOPIC/json?poll=1" | jq .

async function openReport(reportedUrl, findings, score, meta = {}) {
  let hostname = '';
  try { hostname = new URL(reportedUrl).hostname; } catch {}

  const version  = chrome.runtime.getManifest().version;
  const dateStr  = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const isManual = findings.length === 0;

  // ── Markdown body ──────────────────────────────────────
  // ntfy renders markdown in the web UI and mobile app.
  const detectionLines = isManual
    ? ['- *(manual report - no automated detections)*']
    : findings.slice(0, 8).map(f => {
        const cat = f.category.replace(/_/g, ' ');
        const ev  = f.evidence ? `\n  > \`${f.evidence.substring(0, 100)}\`` : '';
        return `- **${cat}** *(+${f.score}pts)*: ${f.description}${ev}`;
      });

  const body = [
    `**URL:** \`${reportedUrl}\``,
    `**Host:** \`${hostname}\``,
    `**Score:** ${score} / 100`,
    `**Reported:** ${dateStr}`,
    `**Extension:** v${version}`,
    '',
    '### Page Info',
    `**Title:** ${meta.title || 'N/A'}`,
    `**Description:** ${meta.description || 'N/A'}`,
    `**Language:** ${meta.lang || 'N/A'}`,
    `**Protocol:** ${meta.protocol || 'N/A'}${meta.port ? ' | **Port:** ' + meta.port : ''}`,
    `**Referrer:** ${meta.referrer || 'direct'}`,
    '',
    '### Page Structure',
    `**Forms:** ${meta.forms ?? '?'} | **Password/text/email inputs:** ${meta.inputs ?? '?'}`,
    `**Iframes:** ${meta.iframes ?? '?'} | **External scripts:** ${meta.externalScripts ?? '?'} | **Links:** ${meta.links ?? '?'}`,
    '',
    '### Detections',
    ...detectionLines,
  ].join('\n');

  // ── ntfy headers ───────────────────────────────────────
  // Priority: 5 urgent (🔴) / 4 high (🟠) / 3 default / 2 low
  const priority = score >= 90 ? 5 : score >= 60 ? 4 : score >= 30 ? 3 : 2;

  // Tags become emoji badges in the web UI and app
  const tags = [
    score >= 90 ? 'rotating_light' : score >= 50 ? 'warning' : 'information_source',
    'shield',
    `score_${score}`,   // searchable in the web UI
  ].join(',');

  // Favicon: Google's public favicon service - gives the blocked site's icon
  // as the notification icon so you instantly recognise the brand being spoofed
  const faviconUrl = hostname
    ? `https://www.google.com/s2/favicons?domain=${hostname}&sz=128`
    : '';

  // Action buttons shown inside the notification (web UI + mobile app):
  //  1. "View site"     - opens the flagged URL in a browser tab
  //  2. "Add to feed"   - opens your domains.csv on GitHub for quick editing
  const githubEditUrl =
    'https://github.com/Nehboro/nehboro.github.io/edit/main/feeds/domains.csv';

  const actions = [
    `view, View flagged site, ${reportedUrl}, clear=false`,
    `view, Add to domains feed, ${githubEditUrl}, clear=true`,
  ].join('; ');

  // Encode body: UTF-8 → base64 → reverse
  const encoded = btoa(unescape(encodeURIComponent(body)));
  const reversed = encoded.split('').reverse().join('');

  try {
    const resp = await fetch(NTFY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Title':        `[THREAT] ${hostname || 'unknown'} - Score ${score}`,
        'Priority':     String(priority),
        'Tags':         tags,
        'Icon':         faviconUrl,
        'Click':        reportedUrl.startsWith('http') ? reportedUrl : NTFY_URL,
        'Actions':      actions,
      },
      body: reversed,
    });

    const { [STORE.STATS]: s } = await chrome.storage.local.get(STORE.STATS);
    s.reported = (s.reported || 0) + 1;
    await chrome.storage.local.set({ [STORE.STATS]: s });

    if (!resp.ok) throw new Error(`ntfy HTTP ${resp.status}`);
    return { ok: true, status: resp.status };

  } catch (err) {
    console.warn('[Nehboro] Report failed:', err.message);
    // Queue locally if offline - retried on next report attempt
    const { nehboro_pending_reports: q = [] } = await chrome.storage.local.get('nehboro_pending_reports');
    q.push({ url: reportedUrl, score, findings, ts: Date.now() });
    await chrome.storage.local.set({ nehboro_pending_reports: q.slice(-100) });
    return { ok: false, queued: true, error: err.message };
  }
}

// ── Message handler ───────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handle(msg, sender).then(sendResponse).catch(e => sendResponse({ error: e.message }));
  return true;
});

async function handle(msg, sender) {
  switch (msg.type) {

    case 'NW_PAGE_SCAN': {
      const data = await chrome.storage.local.get([STORE.STATS, STORE.THRESHOLDS]);
      const s = data[STORE.STATS] || { blocked: 0, warned: 0, reported: 0 };
      const t = data[STORE.THRESHOLDS] || {};
      const warnAt = t.warn ?? 45;
      const blockAt = t.block ?? 79;
      if (msg.blocked)          s.blocked = (s.blocked || 0) + 1;
      else if (msg.score>=warnAt) s.warned  = (s.warned  || 0) + 1;
      await chrome.storage.local.set({
        [STORE.STATS]: s,
        [`nehboro_scan_${msg.hostname}`]: { findings: msg.findings, score: msg.score, ts: msg.timestamp },
      });
      if (sender.tab?.id) {
        const badge = msg.score >= blockAt ? { text:'!', color:'#e74c3c' }
                    : msg.score >= warnAt ? { text:'▲', color:'#f39c12' }
                    : null;
        if (badge) {
          chrome.action.setBadgeText({ text: badge.text, tabId: sender.tab.id });
          chrome.action.setBadgeBackgroundColor({ color: badge.color, tabId: sender.tab.id });
        }
      }
      return { ok: true };
    }

    case 'NW_COMMUNITY_REPORT':
      return await openReport(msg.url, msg.findings || [], msg.score || 0, msg.meta || {});

    case 'NW_GET_SCAN': {
      const data = await chrome.storage.local.get(`nehboro_scan_${msg.hostname}`);
      const { [STORE.WHITELIST]: wl = [] } = await chrome.storage.local.get(STORE.WHITELIST);
      return { scan: data[`nehboro_scan_${msg.hostname}`] || null, whitelisted: wl.includes(msg.hostname) };
    }

    case 'NW_GET_STATS': {
      const { [STORE.STATS]: stats }       = await chrome.storage.local.get(STORE.STATS);
      const { [STORE.LAST_REFRESH]: lr }   = await chrome.storage.local.get(STORE.LAST_REFRESH);
      const { [STORE.BLOCKED]: bl = {} }   = await chrome.storage.local.get(STORE.BLOCKED);
      const counts = {
        domains: (bl.domainPlain?.length||0) + (bl.domainWildcard?.length||0),
        urls:    (bl.urlPlain?.length||0)    + (bl.urlWildcard?.length||0),
        ips:     (bl.ipPlain?.length||0)     + (bl.ipCIDR?.length||0) + (bl.ipWildcard?.length||0),
        ports:   (bl.ports?.length||0),
      };
      return { stats: stats||{}, lastRefresh: lr||null, iocCounts: counts };
    }

    case 'NW_GET_SETTINGS': {
      const data = await chrome.storage.local.get([STORE.CUSTOM_FEEDS, STORE.WHITELIST, STORE.BLOCKED, STORE.THRESHOLDS]);
      return { settings: data, defaultFeeds: DEFAULT_FEEDS };
    }

    case 'NW_ADD_CUSTOM_FEED': {
      const { [STORE.CUSTOM_FEEDS]: feeds = [] } = await chrome.storage.local.get(STORE.CUSTOM_FEEDS);
      feeds.push({ type: msg.feedType, url: msg.feedUrl, name: msg.name || msg.feedUrl });
      await chrome.storage.local.set({ [STORE.CUSTOM_FEEDS]: feeds });
      await refreshAllFeeds();
      return { ok: true, total: feeds.length };
    }

    case 'NW_REMOVE_CUSTOM_FEED': {
      const { [STORE.CUSTOM_FEEDS]: feeds = [] } = await chrome.storage.local.get(STORE.CUSTOM_FEEDS);
      feeds.splice(msg.index, 1);
      await chrome.storage.local.set({ [STORE.CUSTOM_FEEDS]: feeds });
      await refreshAllFeeds();
      return { ok: true };
    }

    case 'NW_WHITELIST_DOMAIN': {
      const { [STORE.WHITELIST]: wl = [] } = await chrome.storage.local.get(STORE.WHITELIST);
      if (!wl.includes(msg.domain)) wl.push(msg.domain);
      await chrome.storage.local.set({ [STORE.WHITELIST]: wl });
      return { ok: true };
    }

    case 'NW_REMOVE_WHITELIST': {
      const { [STORE.WHITELIST]: wl = [] } = await chrome.storage.local.get(STORE.WHITELIST);
      await chrome.storage.local.set({ [STORE.WHITELIST]: wl.filter(d => d !== msg.domain) });
      return { ok: true };
    }

    case 'NW_REFRESH_FEEDS':
      await refreshAllFeeds();
      return { ok: true };

    case 'NW_BYPASS_URL': {
      // User has consciously chosen to proceed past the block.
      // Add a 30-min session exception for this hostname.
      return await addBypass(msg.hostname || msg.url);
    }

    case 'NW_CHECK_BYPASS': {
      return { bypassed: await isBypassed(msg.hostname) };
    }

    case 'NW_CLEAR_BYPASS': {
      await clearBypass(msg.hostname);
      return { ok: true };
    }

    case 'NW_FORCE_SCAN': {
      const tabId = msg.tabId;
      if (!tabId) return { error: 'No tabId' };

      // Check if URL is scannable
      let tabUrl = '';
      try {
        const tab = await chrome.tabs.get(tabId);
        tabUrl = tab.url || '';
        if (!tabUrl || /^(chrome|chrome-extension|about|edge|moz-extension|brave):/.test(tabUrl)) {
          return { error: 'restricted' };
        }
      } catch { return { error: 'restricted' }; }

      // Helper: send message to tab with callback + timeout
      function tabMsg(tid, message, timeoutMs = 3000) {
        return new Promise((resolve) => {
          const timer = setTimeout(() => resolve(null), timeoutMs);
          try {
            chrome.tabs.sendMessage(tid, message, (resp) => {
              clearTimeout(timer);
              if (chrome.runtime.lastError || !resp) resolve(null);
              else resolve(resp);
            });
          } catch { clearTimeout(timer); resolve(null); }
        });
      }

      // Step 1: Try direct scan (scripts might already be loaded via manifest)
      let result = await tabMsg(tabId, { type: 'NW_MANUAL_SCAN' }, 2000);
      if (result && result.findings !== undefined) {
        return { ok: true, findings: result.findings, score: result.score || 0 };
      }

      // Step 1b: sendResponse might have failed but storage write succeeded
      try {
        const hostname = new URL(tabUrl).hostname;
        const manual = await chrome.storage.local.get('nehboro_manual_scan');
        if (manual.nehboro_manual_scan && manual.nehboro_manual_scan.hostname === hostname &&
            Date.now() - (manual.nehboro_manual_scan.ts || 0) < 5000) {
          return { ok: true, findings: manual.nehboro_manual_scan.findings || [], score: manual.nehboro_manual_scan.score || 0 };
        }
      } catch {}

      // Step 2: Inject content scripts
      try {
        // Inject MAIN world runtime interceptor first
        try {
          await chrome.scripting.executeScript({ target: { tabId }, files: ['content/runtime-interceptor.js'], world: 'MAIN' });
        } catch {}

        const manifest = chrome.runtime.getManifest();
        const csGroup = manifest.content_scripts?.find(c => c.js?.includes('content/detector.js'));
        if (csGroup) {
          const files = csGroup.js;
          const batchSize = 10;
          for (let i = 0; i < files.length; i += batchSize) {
            const batch = files.slice(i, i + batchSize);
            await chrome.scripting.executeScript({ target: { tabId }, files: batch });
          }
        }
      } catch (e) {
        return { error: 'inject_failed', detail: e.message };
      }

      // Step 3: Wait for initialization then scan
      await new Promise(r => setTimeout(r, 500));
      result = await tabMsg(tabId, { type: 'NW_MANUAL_SCAN' }, 5000);
      if (result && result.findings !== undefined) {
        return { ok: true, findings: result.findings, score: result.score || 0 };
      }

      // Step 4: Read from storage - content script stores results in nehboro_manual_scan
      await new Promise(r => setTimeout(r, 800));
      try {
        const hostname = new URL(tabUrl).hostname;
        // Try manual scan storage first (set by NW_MANUAL_SCAN handler)
        const manual = await chrome.storage.local.get('nehboro_manual_scan');
        if (manual.nehboro_manual_scan && manual.nehboro_manual_scan.hostname === hostname &&
            Date.now() - (manual.nehboro_manual_scan.ts || 0) < 10000) {
          return { ok: true, findings: manual.nehboro_manual_scan.findings || [], score: manual.nehboro_manual_scan.score || 0 };
        }
        // Try auto-scan storage (set by automatic scan on page load)
        const data = await chrome.storage.local.get(`nehboro_scan_${hostname}`);
        const scan = data[`nehboro_scan_${hostname}`];
        if (scan) return { ok: true, findings: scan.findings || [], score: scan.score || 0 };
      } catch {}

      // If we got here on Step 1 (scripts were already loaded), the scan found nothing
      // Return clean result instead of error
      return { ok: true, findings: [], score: 0 };
    }

    case 'NW_SAVE_AI_CONFIG': {
      await chrome.storage.local.set({ nehboro_ai_config: { provider: 'anthropic', apiKey: msg.apiKey, model: msg.model || 'claude-sonnet-4-20250514' } });
      return { ok: true };
    }

    case 'NW_GET_AI_CONFIG': {
      const { nehboro_ai_config: cfg } = await chrome.storage.local.get('nehboro_ai_config');
      return { config: cfg || {} };
    }

    case 'NW_CLEAR_AI_CONFIG': {
      await chrome.storage.local.remove('nehboro_ai_config');
      return { ok: true };
    }

    case 'NW_AI_SCAN': {
      const tabId = msg.tabId;
      if (!tabId) return { error: 'No tabId' };
      try {
        const result = await runAiAnalysis(tabId, msg.url, msg.hostname);
        return result;
      } catch (e) {
        return { error: e.message };
      }
    }

    case 'NW_GET_AI_RESULT': {
      const key = `nehboro_ai_${msg.hostname}`;
      const data = await chrome.storage.local.get(key);
      return { result: data[key] || null };
    }

    case 'NW_SILENT_BLOCK': {
      // Silent mode: close the dangerous tab and open a clean new tab
      const tabId = sender?.tab?.id;
      if (tabId) {
        try {
          await chrome.tabs.create({ active: true });
          await chrome.tabs.remove(tabId);
        } catch {
          // Fallback: navigate to new tab page
          try { await chrome.tabs.update(tabId, { url: 'chrome://newtab' }); } catch {}
        }
      }
      // Still count the block in stats
      const { nehboro_stats: st = {} } = await chrome.storage.local.get('nehboro_stats');
      st.blocked = (st.blocked || 0) + 1;
      await chrome.storage.local.set({ nehboro_stats: st });
      return { ok: true };
    }

    case 'NW_NOTIFY': {
      chrome.notifications.create({
        type: 'basic', iconUrl: 'icons/icon48.png',
        title: msg.title || 'Nehboro',
        message: msg.message || '',
      });
      return { ok: true };
    }

    case 'NW_SAVE_THRESHOLDS': {
      await chrome.storage.local.set({ [STORE.THRESHOLDS]: msg.thresholds });
      return { ok: true };
    }

    case 'NW_EXPORT_SCAN_HISTORY': {
      const all = await chrome.storage.local.get(null);
      const scans = Object.entries(all)
        .filter(([k]) => k.startsWith('nehboro_scan_'))
        .map(([k, v]) => ({ hostname: k.replace('nehboro_scan_', ''), ...v }));
      return { data: scans };
    }

    case 'NW_CLEAR_STATS': {
      await chrome.storage.local.set({ [STORE.STATS]: { blocked: 0, warned: 0, reported: 0 } });
      return { ok: true };
    }

    default:
      return { error: `Unknown: ${msg.type}` };
  }
}

// ── Bypass helpers ───────────────────────────────────────
// A bypass is a temporary DNR "allow" rule + storage entry.
// Expires after BYPASS_DURATION_MS (30 min).

async function addBypass(hostnameOrUrl) {
  let hostname = hostnameOrUrl;
  try { hostname = new URL(hostnameOrUrl).hostname; } catch {}
  if (!hostname) return { ok: false, error: 'No hostname' };

  const expires = Date.now() + BYPASS_DURATION_MS;

  // Store bypass record
  const { nehboro_bypasses: bypasses = {} } = await chrome.storage.local.get('nehboro_bypasses');
  bypasses[hostname] = expires;
  await chrome.storage.local.set({ nehboro_bypasses: bypasses });

  // Add a high-priority DNR allow rule so the block redirect is skipped
  const ruleId = BYPASS_RULE_ID_BASE + (Math.abs(hashStr(hostname)) % 1000);
  try {
    // Remove any existing bypass rule for this host first
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [ruleId] });
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{
        id:       ruleId,
        priority: 100,          // higher than block rules (priority 10)
        action:   { type: 'allow' },
        condition: { requestDomains: [hostname], resourceTypes: ['main_frame', 'sub_frame'] },
      }],
    });
  } catch (e) {
    console.warn('[Nehboro] Could not add bypass DNR rule:', e.message);
  }

  // Schedule auto-expiry via alarm
  await chrome.alarms.create(`nehboro_bypass_${hostname}`, { delayInMinutes: 30 });

  console.log(`[Nehboro] Bypass granted for ${hostname} (30 min)`);
  return { ok: true, hostname, expires };
}

async function isBypassed(hostname) {
  const { nehboro_bypasses: bypasses = {} } = await chrome.storage.local.get('nehboro_bypasses');
  const expires = bypasses[hostname];
  if (!expires) return false;
  if (Date.now() > expires) {
    // Expired - clean up
    await clearBypass(hostname);
    return false;
  }
  return true;
}

async function clearBypass(hostname) {
  const { nehboro_bypasses: bypasses = {} } = await chrome.storage.local.get('nehboro_bypasses');
  delete bypasses[hostname];
  await chrome.storage.local.set({ nehboro_bypasses: bypasses });

  const ruleId = BYPASS_RULE_ID_BASE + (Math.abs(hashStr(hostname)) % 1000);
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [ruleId] });
  } catch {}
  console.log(`[Nehboro] Bypass expired/cleared for ${hostname}`);
}

function hashStr(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return h;
}

// ── Context menu ─────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async ({ menuItemId }, tab) => {
  if (!tab?.url) return;
  if (menuItemId === 'nehboro_report') {
    const result = await openReport(tab.url, [], 0);
    chrome.notifications.create({
      type: 'basic', iconUrl: 'icons/icon48.png', title: 'Nehboro',
      message: result.ok ? '✅ Report sent successfully.' : '⚠️ Report queued (offline).',
    });
  }
  if (menuItemId === 'nehboro_trust') {
    let h; try { h = new URL(tab.url).hostname; } catch { return; }
    const { [STORE.WHITELIST]: wl=[] } = await chrome.storage.local.get(STORE.WHITELIST);
    if (!wl.includes(h)) wl.push(h);
    await chrome.storage.local.set({ [STORE.WHITELIST]: wl });
    chrome.notifications.create({ type:'basic', iconUrl:'icons/icon48.png', title:'Nehboro', message:`✅ ${h} trusted.` });
  }
});

console.log('[Nehboro] Service worker ready - feeds: nehboro.github.io/feeds/');

// ── AI Analysis Engine ───────────────────────────────────
// Optional third engine: sends structured page metadata to an LLM
// for AI-powered threat classification.

const AI_PROMPT = `You are a cybersecurity analyst. Analyze this website data for threats.

Evaluate for:
1. PHISHING: Domain spoofing, credential harvesting forms, brand impersonation
2. MALWARE: Suspicious scripts, drive-by downloads, encoded payloads
3. SCAM: Fake alerts, tech support scams, urgency manipulation
4. CLICKFIX: Instructions to run commands (Win+R, terminal, PowerShell)
5. SOCIAL_ENGINEERING: Fake CAPTCHAs, countdown pressure, deceptive UI

Respond ONLY with this JSON (no markdown):
{"status":"SAFE|SUSPICIOUS|DANGEROUS","threat":"PHISHING|MALWARE|SCAM|CLICKFIX|SOCIAL_ENGINEERING|NONE","confidence":0.0-1.0,"explanation":"one sentence reason"}

Website data:
`;

async function runAiAnalysis(tabId, url, hostname) {
  const { nehboro_ai_config: cfg } = await chrome.storage.local.get('nehboro_ai_config');
  if (!cfg || !cfg.provider || !cfg.apiKey) return { error: 'AI not configured' };

  // Get page data from the tab's scan results
  const scanData = await chrome.storage.local.get([`nehboro_scan_${hostname}`, 'nehboro_manual_scan']);
  const scan = scanData[`nehboro_scan_${hostname}`] || scanData.nehboro_manual_scan || {};

  // Build compact page metadata (no raw HTML - privacy-friendly)
  const pageInfo = {
    url: url,
    hostname: hostname,
    heuristic_score: scan.score || 0,
    heuristic_findings: (scan.findings || []).map(f => ({ id: f.category, name: f.name, score: f.score })),
    timestamp: new Date().toISOString(),
  };

  // Also get basic page info via scripting if available
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => ({
        title: document.title,
        forms: [...document.forms].slice(0, 5).map(f => ({
          action: f.action, method: f.method,
          inputs: [...f.querySelectorAll('input')].map(i => ({ type: i.type, name: i.name }))
        })),
        scripts: [...document.querySelectorAll('script[src]')].slice(0, 10).map(s => s.src),
        text_snippet: (document.body?.innerText || '').substring(0, 2000),
        has_password: document.querySelectorAll('input[type="password"]').length > 0,
        iframes: [...document.querySelectorAll('iframe[src]')].slice(0, 5).map(i => i.src),
      })
    });
    if (result?.result) Object.assign(pageInfo, result.result);
  } catch {}

  const payload = JSON.stringify(pageInfo, null, 2).substring(0, 15000);
  const fullPrompt = AI_PROMPT + payload;

  let aiResult;
  try {
    aiResult = await callAnthropic(cfg.apiKey, fullPrompt, cfg.model || 'claude-sonnet-4-20250514');
  } catch (e) {
    const result = { status: 'ERROR', explanation: e.message, ts: Date.now() };
    await chrome.storage.local.set({ [`nehboro_ai_${hostname}`]: result });
    return { error: e.message };
  }

  // Store result
  aiResult.ts = Date.now();
  aiResult.url = url;
  await chrome.storage.local.set({ [`nehboro_ai_${hostname}`]: aiResult });

  // Notify popup
  chrome.runtime.sendMessage({ type: 'NW_AI_RESULT', hostname, result: aiResult }).catch(() => {});

  return { ok: true, result: aiResult };
}

function parseAiJson(text) {
  // Try direct parse
  try { return JSON.parse(text); } catch {}
  // Try extracting JSON from markdown code block
  const m = text.match(/\{[\s\S]*\}/);
  if (m) try { return JSON.parse(m[0]); } catch {}
  return { status: 'ERROR', explanation: 'Could not parse AI response', confidence: 0 };
}

async function callAnthropic(apiKey, prompt, model) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    },
    body: JSON.stringify({
      model: model || 'claude-sonnet-4-20250514',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }]
    })
  });
  if (!resp.ok) throw new Error(`Anthropic API error: ${resp.status}`);
  const data = await resp.json();
  const text = data.content?.[0]?.text || '';
  return parseAiJson(text);
}
