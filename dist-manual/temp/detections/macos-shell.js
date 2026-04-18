(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'MACOS_SHELL', name: 'macOS Shell Attack',
    description: 'macOS shell attack patterns (curl|bash, osascript, API-gated C2)',
    defaultScore: 48, tags: ['clickfix','malware'],
    detect(ctx) {
      if (H.testAny(P.MACOS_SHELL, ctx.rawText) || H.testAny(P.MACOS_SHELL, ctx.pageHTML)) {
        const hasOpen = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
        const hasContext = hasOpen || H.testAny(P.CF_DOMAINS, ctx.hostname) || H.testAny(P.FAKE_MEETING, ctx.rawText);
        return { description: 'macOS shell attack pattern detected', evidence: H.firstMatch(P.MACOS_SHELL, ctx.rawText) || H.firstMatch(P.MACOS_SHELL, ctx.pageHTML), scoreOverride: hasContext ? undefined : 12 };
      }
      return null;
    }
  });
})();
