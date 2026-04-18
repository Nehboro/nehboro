(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'OBFUSCATION_HEAVY', name: 'Heavy JS Obfuscation',
    description: 'Heavy JavaScript obfuscation (RC4, _0x vars, anti-debug) - 3+ signals',
    defaultScore: 28, tags: ['malware','evasion'],
    detect(ctx) {
      const hits = H.countMatches(P.OBFUSCATION, ctx.pageHTML);
      if (hits >= 3) return { description: `${hits} heavy JS obfuscation patterns`, evidence: `${hits} obfuscation signals in page scripts` };
      return null;
    }
  });

  // Lighter detection - fires on any obfuscation signal (1-2 patterns)
  NW_register({
    id: 'OBFUSCATION', name: 'JS Obfuscation Patterns',
    description: 'JavaScript obfuscation patterns detected (eval, hex strings, _0x vars)',
    defaultScore: 12, tags: ['malware','evasion'],
    detect(ctx) {
      const hits = H.countMatches(P.OBFUSCATION, ctx.pageHTML);
      if (hits >= 1 && hits < 3) return {
        description: `${hits} JS obfuscation pattern(s) found`,
        evidence: H.firstMatch(P.OBFUSCATION, ctx.pageHTML) || `${hits} obfuscation signals`,
      };
      return null;
    }
  });
})();
