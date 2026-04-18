// Nehboro Detection: ClickFix Instruction Sequence
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'CLICKFIX_FULL_SEQUENCE', name: 'ClickFix Full Sequence',
    description: 'Complete open-paste-execute instruction sequence (Win+R → Ctrl+V → Enter)',
    defaultScore: 45, tags: ['clickfix','critical'],
    detect(ctx) {
      const hasOpen    = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
      const hasPaste   = H.testAny(P.CF_PASTE, ctx.rawText);
      const hasExecute = H.testAny(P.CF_EXECUTE, ctx.rawText);
      if (hasOpen && hasPaste && hasExecute) {
        return { description: 'Complete ClickFix execution sequence detected', evidence: H.firstMatch(P.CF_OPEN, ctx.rawText) || H.firstMatch(P.CF_OPEN, ctx.pageHTML) };
      }
      return null;
    }
  });

  NW_register({
    id: 'CLICKFIX_PARTIAL', name: 'ClickFix Partial Sequence',
    description: 'Partial open-paste-execute sequence (2 of 3 parts)',
    defaultScore: 25, tags: ['clickfix'],
    detect(ctx) {
      const hasOpen    = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
      const hasPaste   = H.testAny(P.CF_PASTE, ctx.rawText);
      const hasExecute = H.testAny(P.CF_EXECUTE, ctx.rawText);
      const parts = [hasOpen, hasPaste, hasExecute].filter(Boolean).length;
      if (parts === 2 && hasOpen) {
        return { description: `Partial ClickFix sequence (2/3): open dialog + ${hasPaste ? 'paste' : 'execute'}`, evidence: H.firstMatch(P.CF_OPEN, ctx.rawText) };
      }
      return null;
    }
  });
})();
