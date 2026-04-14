(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'URGENCY', name: 'Urgency Manipulation',
    description: 'Urgency/scarcity manipulation phrases (3+ required)',
    defaultScore: 6, tags: ['social-engineering'],
    detect(ctx) {
      const hits = H.countMatches(P.URGENCY, ctx.rawText);
      if (hits >= 3) return { description: `${hits} urgency/scarcity phrases`, evidence: H.firstMatch(P.URGENCY, ctx.rawText), scoreMultiplier: Math.min(hits, 5) };
      return null;
    }
  });
})();
