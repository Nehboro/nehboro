(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'DNS_CLICKFIX', name: 'DNS ClickFix (nslookup C2)',
    description: 'nslookup-based payload delivery (KongTuke / DNS ClickFix)',
    defaultScore: 45, tags: ['clickfix','malware','critical'],
    detect(ctx) {
      if (H.testAny(P.DNS_CLICKFIX, ctx.rawText) || H.testAny(P.DNS_CLICKFIX, ctx.pageHTML))
        return { description: 'nslookup-based payload delivery detected', evidence: H.firstMatch(P.DNS_CLICKFIX, ctx.rawText + ctx.pageHTML) };
      return null;
    }
  });
})();
