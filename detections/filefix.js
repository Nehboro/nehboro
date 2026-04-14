(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'FILEFIX', name: 'FileFix (Explorer Address Bar)',
    description: 'Instruction to paste command into File Explorer address bar',
    defaultScore: 38, tags: ['clickfix'],
    detect(ctx) {
      if (H.testAny(P.FILEFIX, ctx.rawText))
        return { description: 'FileFix: paste into Explorer address bar', evidence: H.firstMatch(P.FILEFIX, ctx.rawText) };
      return null;
    }
  });
})();
