(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'CONSENTFIX', name: 'OAuth ConsentFix',
    description: 'OAuth ConsentFix token theft (copy URL from address bar)',
    defaultScore: 42, tags: ['phishing','clickfix'],
    detect(ctx) {
      if (H.testAny(P.CONSENTFIX, ctx.rawText) || H.testAny(P.CONSENTFIX, ctx.url))
        return { description: 'OAuth ConsentFix token theft pattern', evidence: H.firstMatch(P.CONSENTFIX, ctx.rawText + ctx.url) };
      return null;
    }
  });
})();
