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

  // Standalone LOLBin detection - fires when multiple LOLBin commands appear in page
  // even without ClickFix execution instructions (suspicious on its own)
  NW_register({
    id: 'LOLBIN_COMMAND', name: 'LOLBin Command References',
    description: 'Multiple living-off-the-land binary commands appear in page content',
    defaultScore: 25, tags: ['malware'],
    detect(ctx) {
      const combined = ctx.rawText + ctx.pageHTML;
      const hits = P.LOLBIN_ALL.filter(p => p.test(combined));
      // Multiple LOLBin commands in one page is suspicious even without ClickFix instructions
      if (hits.length >= 3) {
        const examples = hits.slice(0, 4).map(p => (combined.match(p) || [''])[0].substring(0, 40)).filter(Boolean).join(', ');
        return {
          description: `${hits.length} different LOLBin commands referenced in page`,
          evidence: examples,
          scoreBonus: hits.length >= 5 ? 15 : 0,
        };
      }
      return null;
    }
  });
})();
