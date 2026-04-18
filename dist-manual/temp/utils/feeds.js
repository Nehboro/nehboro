// ============================================================
// Nehboro - utils/feeds.js
// Feed parsing: CSV, wildcards, CIDR ranges, port ranges
// ============================================================

var NW_FEEDS = NW_FEEDS || {

  // ── Master parser - auto-detects format ──────────────────
  // Preserves wildcards (* ?) and CIDR notation as-is.
  parse(rawText, type) {
    const text = (rawText || '').trim();
    if (!text) return [];

    // JSON array or object
    if (text.startsWith('[') || text.startsWith('{')) {
      try {
        const p = JSON.parse(text);
        const arr = Array.isArray(p)
          ? p
          : (p.data || p.iocs || p.indicators || p[type] || []);
        return this._post(
          arr.map(i => typeof i === 'string' ? i : (i.ioc || i.indicator || i.value || '')).filter(Boolean),
          type
        );
      } catch {}
    }

    const entries  = [];
    const lines    = text.split('\n');

    // Skip CSV header row if first line looks like column names
    let start = 0;
    if (lines.length > 1) {
      const first = lines[0].replace(/["']/g, '').trim();
      if (!this._looksLikeIOC(first, type) && /^[a-z ,_-]+$/i.test(first)) start = 1;
    }

    for (let i = start; i < lines.length; i++) {
      let line = lines[i].trim();
      if (!line || line[0] === '#' || line[0] === '/' || line[0] === ';') continue;

      // Hosts-file format:  0.0.0.0  evil.com
      if (/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+/.test(line)) {
        line = line.replace(/^[^\s]+\s+/, '').split(/\s/)[0].toLowerCase();
      } else {
        // CSV: take first column, strip surrounding quotes
        line = line.split(',')[0].replace(/^["']|["']$/g, '').trim();
      }

      // Type-specific normalization
      if (type === 'domains') {
        // Strip scheme and path but keep wildcards intact
        line = line.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
      } else if (type === 'ports') {
        const m = line.match(/(\d{1,5}(?:-\d{1,5})?)/);
        if (!m) continue;
        line = m[1];
      }

      if (line) entries.push(line);
    }

    return this._post([...new Set(entries)], type);
  },

  _looksLikeIOC(str, type) {
    if (type === 'domains') return /[a-z0-9*][a-z0-9.*-]*\.[a-z]{2,}/i.test(str);
    if (type === 'ips')     return /\d+\.\d+/.test(str);
    if (type === 'urls')    return /^https?:\/\//i.test(str);
    if (type === 'ports')   return /^\d{1,5}/.test(str);
    return false;
  },

  // Post-processing: deduplicate and filter known-safe
  _post(entries, type) {
    if (type !== 'domains') return entries;
    const SAFE = new Set([
      'google.com','bing.com','duckduckgo.com','cloudflare.com',
      'github.com','githubusercontent.com','github.io','nehboro.github.io',
      'microsoft.com','office.com','microsoftonline.com','azure.com',
      'apple.com','icloud.com','facebook.com','instagram.com',
      'twitter.com','x.com','youtube.com','reddit.com',
      'amazon.com','amazonaws.com','wikipedia.org',
    ]);
    return entries.filter(e => {
      const bare = e.replace(/^\*\./, '');
      const tld2 = bare.split('.').slice(-2).join('.');
      return !SAFE.has(bare) && !SAFE.has(tld2);
    });
  },

  // ── Wildcard detection ────────────────────────────────────
  isWildcard(str) { return str.includes('*') || str.includes('?'); },

  // Convert any IOC with wildcards to a DNR urlFilter pattern
  wildcardToUrlFilter(ioc, type) {
    // Already has scheme
    if (/^https?:\/\//i.test(ioc)) return ioc.replace(/\?/g, '*');

    if (type === 'domains' || type === 'ips') {
      return `*://${ioc.replace(/\?/g, '*')}/*`;
    }
    return ioc.replace(/\?/g, '*');
  },

  // ── CIDR helpers ──────────────────────────────────────────
  isCIDR(str) {
    return /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(str);
  },

  // Convert aligned CIDRs (/8, /16, /24, /32) to DNR urlFilter wildcards.
  // Returns null for non-aligned prefixes (webRequest handles those).
  cidrToUrlFilter(cidr) {
    const [ip, bitsStr] = cidr.split('/');
    const bits  = parseInt(bitsStr, 10);
    const oct   = ip.split('.').map(Number);

    if (bits === 32)            return `*://${ip}/*`;
    if (bits >= 25 && bits < 32) {
      // Expand small ranges (/25–/31) - 2 to 128 IPs - return null, let expandCIDR handle
      return null;
    }
    if (bits === 24) return `*://${oct[0]}.${oct[1]}.${oct[2]}.*/*`;
    if (bits === 16) return `*://${oct[0]}.${oct[1]}.*.*/*`;
    if (bits === 8)  return `*://${oct[0]}.*.*.*/*`;
    return null; // non-aligned - webRequest
  },

  // Expand small CIDRs (/28–/32, max 16 IPs) to individual IP strings.
  // Returns null if the range is too large.
  expandCIDR(cidr) {
    const [ip, bitsStr] = cidr.split('/');
    const bits  = parseInt(bitsStr, 10);
    if (bits < 28) return null; // too large to expand
    const count   = 1 << (32 - bits); // 1–16
    const mask    = (~0 << (32 - bits)) >>> 0;
    const network = (this._ipToInt(ip) & mask) >>> 0;
    return Array.from({ length: count }, (_, i) => this._intToIP(network + i));
  },

  // Test whether an IP falls within a CIDR block
  cidrContains(cidr, ip) {
    try {
      const [net, bitsStr] = cidr.split('/');
      const bits = parseInt(bitsStr, 10);
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return (this._ipToInt(net) & mask) === (this._ipToInt(ip) & mask);
    } catch { return false; }
  },

  _ipToInt(ip) {
    return ip.split('.').reduce((a, o) => ((a << 8) + parseInt(o, 10)) >>> 0, 0) >>> 0;
  },
  _intToIP(n) {
    return `${(n>>>24)&255}.${(n>>>16)&255}.${(n>>>8)&255}.${n&255}`;
  },

  // ── Port helpers ──────────────────────────────────────────
  // Expand "8080" → [8080]  or  "8080-8085" → [8080..8085]
  // Returns [] for invalid / oversized ranges (>500 ports)
  expandPort(entry) {
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
  },

  portToUrlFilter(port) { return `*://*/*:${port}/*`; },
};

if (typeof window     !== 'undefined') window.NW_FEEDS     = NW_FEEDS;
if (typeof module     !== 'undefined') module.exports       = NW_FEEDS;
if (typeof globalThis !== 'undefined') globalThis.NW_FEEDS  = NW_FEEDS;
