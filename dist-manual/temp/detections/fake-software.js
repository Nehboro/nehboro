(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'FAKE_SOFTWARE_DL', name: 'Fake Software Download',
    description: 'Fake software download lure page',
    defaultScore: 25, tags: ['social-engineering'],
    detect(ctx) {
      if (H.testAny(P.FAKE_SOFTWARE, ctx.rawText) || H.testAny(P.FAKE_SOFTWARE, ctx.pageHTML))
        return { description: 'Fake software download lure detected', evidence: H.firstMatch(P.FAKE_SOFTWARE, ctx.rawText + ctx.pageHTML) };
      return null;
    }
  });
})();
