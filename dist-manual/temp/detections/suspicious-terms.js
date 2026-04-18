(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'SUSPICIOUS_TERMS', name: 'Suspicious Keyword Accumulation',
    description: 'High density of security-sensitive terms in page (8+ required)',
    defaultScore: 2, tags: ['heuristic'],
    detect(ctx) {
      let hits = 0; const found = [];
      for (const term of P.SUSPICIOUS_TERMS) {
        if (ctx.pageText.includes(term) || ctx.pageHTML.toLowerCase().includes(term)) { hits++; found.push(term); }
      }
      if (hits >= 8) return { description: `${hits} security-sensitive terms found`, evidence: found.slice(0, 8).join(', '), scoreMultiplier: hits, scoreCap: 12 };
      return null;
    }
  });
})();
