// Nehboro Detection: Fake Video Conference
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'FAKE_MEETING', name: 'Fake Video Conference',
    description: 'Fake video conferencing interface used as lure',
    defaultScore: 28, tags: ['clickfix','social-engineering'],
    detect(ctx) {
      if (H.testAny(P.FAKE_MEETING, ctx.rawText) || H.testAny(P.FAKE_MEETING, ctx.hostname)) {
        const hasOpen = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
        const hasPaste = H.testAny(P.CF_PASTE, ctx.rawText);
        const bonus = (hasOpen || hasPaste) ? 10 : 0;
        return { description: 'Fake video conferencing interface detected', evidence: H.firstMatch(P.FAKE_MEETING, ctx.rawText) || ctx.hostname, scoreBonus: bonus };
      }
      return null;
    }
  });
})();
