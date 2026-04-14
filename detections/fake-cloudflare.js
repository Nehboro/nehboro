// Nehboro Detection: Fake Cloudflare / CAPTCHA
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;

  NW_register({
    id: 'FAKE_CLOUDFLARE_DOMAIN', name: 'Fake Cloudflare Domain',
    description: 'Typosquatted Cloudflare domain in URL or page content',
    defaultScore: 38, tags: ['clickfix','phishing'],
    detect(ctx) {
      if (H.testAny(P.CF_DOMAINS, ctx.hostname) || H.testAny(P.CF_DOMAINS, ctx.pageHTML))
        return { description: 'Typosquatted Cloudflare domain detected', evidence: ctx.hostname };
      return null;
    }
  });

  NW_register({
    id: 'FAKE_CLOUDFLARE_TEXT', name: 'Fake CAPTCHA Text',
    description: 'Multiple fake Cloudflare/CAPTCHA text signals (3+ required)',
    defaultScore: 8, tags: ['clickfix','social-engineering'],
    detect(ctx) {
      const hits = H.countMatches(P.CAPTCHA_TEXT, ctx.rawText);
      if (hits >= 3) return { description: `${hits} fake Cloudflare/CAPTCHA text signals`, evidence: H.firstMatch(P.CAPTCHA_TEXT, ctx.rawText), scoreMultiplier: Math.min(hits, 4) };
      return null;
    }
  });
})();
