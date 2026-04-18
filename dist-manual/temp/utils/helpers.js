// ============================================================
// Nehboro - utils/helpers.js
// Shared helper functions for all detection modules
// ============================================================

(function () {
  'use strict';

  const P = window.NW_PATTERNS;
  if (!P) return;

  function testAny(patterns, text) {
    if (!patterns) return false;
    for (const p of patterns) { if (p.test(text)) return true; }
    return false;
  }

  function countMatches(patterns, text) {
    if (!patterns) return 0;
    return patterns.filter(p => p.test(text)).length;
  }

  function firstMatch(patterns, text) {
    if (!patterns) return '';
    for (const p of patterns) {
      const m = text.match(p);
      if (m) return m[0].substring(0, 150);
    }
    return '';
  }

  function isOnSafeDomain() {
    const h = window.location.hostname;
    const path = window.location.pathname || '/';
    if (!P.SAFE_DOMAINS) return false;
    let domainMatch = false;
    for (const safe of P.SAFE_DOMAINS) {
      if (h === safe || h.endsWith('.' + safe)) { domainMatch = true; break; }
    }
    if (!domainMatch) return false;

    // Check path-based exclusions: even on a trusted domain, specific paths are NOT trusted
    // (e.g. test pages, demo malware repros, etc.)
    if (P.SAFE_DOMAIN_EXCLUSIONS) {
      for (const excl of P.SAFE_DOMAIN_EXCLUSIONS) {
        const exclHost = excl.host;
        const exclPath = excl.pathPrefix;
        if ((h === exclHost || h.endsWith('.' + exclHost)) && path.startsWith(exclPath)) {
          return false;
        }
      }
    }
    return true;
  }

  /** Return ALL distinct matches across patterns, capped at maxItems */
  function allMatches(patterns, text, maxItems) {
    const out = [];
    const seen = new Set();
    if (!patterns || !text) return out;
    const cap = maxItems || 30;
    for (const p of patterns) {
      // Force global flag for matchAll
      const re = p.flags.includes('g') ? p : new RegExp(p.source, p.flags + 'g');
      try {
        for (const m of text.matchAll(re)) {
          const s = m[0].substring(0, 200).trim();
          if (!s || seen.has(s.toLowerCase())) continue;
          seen.add(s.toLowerCase());
          out.push(s);
          if (out.length >= cap) return out;
        }
      } catch {}
    }
    return out;
  }

  /** Extract all distinct URLs from a page (href, src, action, src in JS) */
  function extractUrls(ctx) {
    const urls = new Set();
    try {
      // From DOM
      document.querySelectorAll('a[href], link[href], script[src], img[src], iframe[src], form[action], source[src], embed[src], object[data], video[src], audio[src]').forEach(el => {
        const v = el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('action') || el.getAttribute('data');
        if (v && /^(https?:|\/\/)/i.test(v)) urls.add(v);
      });
      // From inline scripts and HTML
      const text = (ctx?.pageHTML || '');
      const matches = text.match(/https?:\/\/[^\s'"<>`]{4,200}/gi) || [];
      for (const u of matches) urls.add(u.replace(/[.,;:)\]}>]+$/, ''));
    } catch {}
    return [...urls].slice(0, 200);
  }

  /** Build a context object that detections use */
  function buildContext() {
    const rawText  = document.body?.innerText || '';
    const pageHTML = document.documentElement?.innerHTML || '';
    return {
      rawText,
      pageText: rawText.toLowerCase(),
      pageHTML,
      hostname: window.location.hostname,
      url:      window.location.href,
      title:    document.title || '',
      hasPwdField: document.querySelectorAll('input[type="password"]').length > 0,
      formCount:   document.forms.length,
      iframeCount: document.querySelectorAll('iframe').length,
      inputCount:  document.querySelectorAll('input[type="password"], input[type="text"], input[type="email"]').length,
    };
  }

  window.NW_HELPERS = {
    testAny,
    countMatches,
    firstMatch,
    allMatches,
    extractUrls,
    isOnSafeDomain,
    buildContext,
  };

})();
