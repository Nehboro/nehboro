(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'WINHTTP_FULL', name: 'WinHttp VBScript Payload',
    description: 'WinHttp VBScript download/execute payload (2+ signals)',
    defaultScore: 50, tags: ['malware','critical'],
    detect(ctx) {
      const hits = H.countMatches(P.WINHTTP_FULL, ctx.pageHTML);
      if (hits >= 2) return { description: 'WinHttp VBScript download/execute payload', evidence: H.firstMatch(P.WINHTTP_FULL, ctx.pageHTML) };
      return null;
    }
  });
  NW_register({
    id: 'WINHTTP_PARTIAL', name: 'WinHttp/XMLHTTP Pattern',
    description: 'WinHttp/XMLHTTP pattern alongside instructions',
    defaultScore: 22, tags: ['malware'],
    detect(ctx) {
      const full = H.countMatches(P.WINHTTP_FULL, ctx.pageHTML);
      if (full >= 2) return null; // already caught by WINHTTP_FULL
      const hasOpen = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
      if (!hasOpen) return null;
      if (full === 1 || H.countMatches(P.WINHTTP_PARTIAL, ctx.pageHTML) >= 2)
        return { description: 'WinHttp/XMLHTTP pattern alongside instructions', evidence: H.firstMatch(P.WINHTTP_FULL, ctx.pageHTML) || H.firstMatch(P.WINHTTP_PARTIAL, ctx.pageHTML) };
      return null;
    }
  });
})();
