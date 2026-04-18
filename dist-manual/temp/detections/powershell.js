// Nehboro Detection: PowerShell Patterns
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'POWERSHELL_ENCODED', name: 'PowerShell Encoded Command',
    description: 'Encoded PowerShell with download/execution patterns (3+ signals)',
    defaultScore: 40, tags: ['clickfix','malware','critical'],
    detect(ctx) {
      const combined = ctx.rawText + ctx.pageHTML;
      const hits = H.countMatches(P.PS_ENCODED, combined);
      if (hits >= 3) return { description: `${hits} PowerShell encoding/download patterns`, evidence: H.firstMatch(P.PS_ENCODED, combined) };
      return null;
    }
  });

  NW_register({
    id: 'POWERSHELL_PARTIAL', name: 'PowerShell Suspicious Pattern',
    description: 'Partial PowerShell patterns (encoded command or download)',
    defaultScore: 20, tags: ['clickfix','malware'],
    detect(ctx) {
      const combined = ctx.rawText + ctx.pageHTML;
      const encHits = H.countMatches(P.PS_ENCODED, combined);
      if (encHits >= 1 && encHits < 3) return { description: 'PowerShell encoded/download pattern in page', evidence: H.firstMatch(P.PS_ENCODED, combined) };
      const partialHits = H.countMatches(P.PS_PARTIAL, combined);
      const hasOpen = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
      if (partialHits >= 2 && hasOpen) return { description: `${partialHits} PowerShell partial patterns alongside instructions`, evidence: H.firstMatch(P.PS_PARTIAL, ctx.rawText) };
      return null;
    }
  });
})();
