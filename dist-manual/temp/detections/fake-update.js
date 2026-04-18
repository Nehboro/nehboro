// Nehboro Detection: Fake Windows Update
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'FAKE_UPDATE', name: 'Fake Windows Update',
    description: 'Fake Windows Update screen (3+ signals required)',
    defaultScore: 30, tags: ['clickfix','social-engineering'],
    detect(ctx) {
      const hits = H.countMatches(P.FAKE_UPDATE, ctx.rawText);
      if (hits >= 3) return { description: `${hits} fake Windows Update signals`, evidence: H.firstMatch(P.FAKE_UPDATE, ctx.rawText) };
      return null;
    }
  });
})();
