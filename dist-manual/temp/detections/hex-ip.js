(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'HEX_IP', name: 'Hex/Decimal Encoded IP',
    description: 'Hex/decimal-encoded IP address (mshta evasion)',
    defaultScore: 30, tags: ['malware','evasion'],
    detect(ctx) {
      if (H.testAny(P.HEX_IP, ctx.rawText) || H.testAny(P.HEX_IP, ctx.pageHTML))
        return { description: 'Hex/decimal-encoded IP address', evidence: H.firstMatch(P.HEX_IP, ctx.rawText + ctx.pageHTML) };
      return null;
    }
  });
})();
