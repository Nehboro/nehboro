(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'FAKE_SOCIAL_PROOF', name: 'Fake Social Proof',
    description: 'Fake user count or social proof claims',
    defaultScore: 12, tags: ['social-engineering'],
    detect(ctx) {
      const patterns = [/\d{3,}\s+users?\s+(?:verified|joined|already|signed)/i, /(?:trusted\s+by|used\s+by)\s+\d+,?\d+/i];
      for (const p of patterns) {
        const m = ctx.rawText.match(p);
        if (m) return { description: 'Fake social proof/user count detected', evidence: m[0] };
      }
      return null;
    }
  });
})();
