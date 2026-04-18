(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'STEGANOGRAPHY', name: 'Steganography Payload',
    description: '.NET image manipulation steganography patterns (2+ signals)',
    defaultScore: 48, tags: ['malware','evasion'],
    detect(ctx) {
      const hits = H.countMatches(P.STEGANOGRAPHY, ctx.pageHTML);
      if (hits >= 2) return { description: `${hits} steganography payload signals`, evidence: H.firstMatch(P.STEGANOGRAPHY, ctx.pageHTML) };
      return null;
    }
  });
})();
