// Nehboro Detection: Fake Verification ID
// Catches fake branded verification IDs used in ClickFix CAPTCHA lures
// e.g. "Cloudflare Verification ID: 2628", "reCAPTCHA Verification ID: 8547"
(function () {
  NW_register({
    id: 'FAKE_VERIFICATION_ID', name: 'Fake Verification ID',
    description: 'Page displays a fake branded verification/authentication ID to appear legitimate',
    defaultScore: 30, tags: ['clickfix','social-engineering','critical'],
    detect(ctx) {
      const signals = [];

      // Fake verification ID patterns
      const pats = [
        // "Cloudflare Verification ID: 2628" (Image 5)
        /(?:cloudflare|recaptcha|captcha|hcaptcha|turnstile)\s+verification\s+id\s*:?\s*\d+/i,
        // "Booking Verification ID: 997825" (Image 4)
        /(?:booking|google|microsoft|apple|facebook|amazon|paypal)\s+verification\s+id\s*:?\s*\d+/i,
        // "I am not a robot - [Brand] Verification ID: XXXX" (Images 4-6)
        /i\s+am\s+not\s+a\s+robot\s*[-–-]\s*\w+\s+verification\s+id/i,
        // Generic "Verification ID:" with number
        /verification\s+(?:id|code|number)\s*:?\s*(?:#?\s*)?\d{3,}/i,
        // "Authentication ID:" / "Security ID:"
        /(?:authentication|security|session)\s+(?:id|code|token)\s*:?\s*(?:#?\s*)?\d{4,}/i,
      ];

      for (const p of pats) {
        const m = ctx.rawText.match(p);
        if (m) { signals.push(m[0].substring(0, 60)); }
      }

      // Even higher confidence if combined with CAPTCHA + ClickFix instructions
      const hasCaptcha = /(?:not\s+a\s+robot|verify\s+(?:you\s+are\s+)?human|verification\s+steps?|prove\s+you\s+are)/i.test(ctx.rawText);
      const hasClickFix = /(?:win(?:dows)?\s*\+\s*[rx]|ctrl\s*\+\s*v|press\s+enter|powershell|terminal)/i.test(ctx.rawText);

      if (signals.length >= 1) {
        return {
          description: `Fake verification ID: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: (hasCaptcha && hasClickFix) ? 15 : hasCaptcha ? 8 : 0,
        };
      }
      return null;
    }
  });
})();
