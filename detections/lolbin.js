// Nehboro Detection: LOLBin in Instruction Context
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'LOLBIN_IN_CONTEXT', name: 'LOLBin with Instructions',
    description: 'Living-off-the-land binary referenced alongside execution instructions',
    defaultScore: 35, tags: ['clickfix','malware'],
    detect(ctx) {
      const hasOpen = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
      const hasPaste = H.testAny(P.CF_PASTE, ctx.rawText);
      const hasExecute = H.testAny(P.CF_EXECUTE, ctx.rawText);
      if (!hasOpen && [hasOpen, hasPaste, hasExecute].filter(Boolean).length < 2) return null;
      const hits = P.LOLBIN_ALL.filter(p => p.test(ctx.rawText) || p.test(ctx.pageHTML));
      if (hits.length === 0) return null;
      const examples = hits.slice(0, 3).map(p => (ctx.rawText.match(p) || ctx.pageHTML.match(p) || [''])[0].substring(0, 40)).filter(Boolean).join(', ');
      return { description: `${hits.length} LOLBin(s) alongside execution instructions`, evidence: examples, scoreBonus: hits.length > 3 ? 10 : 0 };
    }
  });
})();
