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
    if (!P.SAFE_DOMAINS) return false;
    for (const safe of P.SAFE_DOMAINS) {
      if (h === safe || h.endsWith('.' + safe)) return true;
    }
    return false;
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
    isOnSafeDomain,
    buildContext,
  };

})();
