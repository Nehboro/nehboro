// Nehboro Detection: Device Code Phishing
// Catches fake "verification code" pages that trick users into entering device codes
// on legitimate auth pages (microsoft.com/devicelogin, google.com/device, etc.)
// This is distinct from ClickFix - no command execution, just code entry on a real site
(function () {
  NW_register({
    id: 'DEVICE_CODE_PHISH', name: 'Device Code Phishing',
    description: 'Fake verification code page that tricks users into entering codes on legitimate OAuth/device login pages',
    defaultScore: 38, tags: ['phishing','social-engineering','critical'],
    detect(ctx) {
      const signals = [];

      // Prominent verification/authorization code display
      const codePatterns = [
        /your\s+(?:verification|authorization|access|device|auth)\s+code/i,
        /(?:verification|authorization|access|device)\s+code\s*:?\s*[A-Z0-9]{6,}/i,
        /enter\s+(?:this\s+)?code\s+(?:to|on|at|in)\s+(?:your|the)/i,
        /copy\s+(?:the\s+)?code\s+(?:above|below)/i,
        /copy\s+code/i,
      ];
      for (const p of codePatterns) {
        const m = ctx.rawText.match(p);
        if (m) { signals.push(m[0].substring(0, 50)); break; }
      }

      // "Continue to [brand]" / "Sign in with [brand]" buttons
      const brandRedirect = [
        /continue\s+to\s+(?:microsoft|google|apple|facebook|meta|amazon|github)/i,
        /sign\s+in\s+with\s+(?:your\s+)?(?:microsoft|google|apple)\s+account/i,
        /verify\s+(?:your\s+)?identity\s+with\s+(?:microsoft|google|apple)/i,
        /(?:microsoft|google|apple)\s+(?:sign[- ]?in|login|authentication)/i,
      ];
      for (const p of brandRedirect) {
        const m = ctx.rawText.match(p);
        if (m) { signals.push(m[0].substring(0, 50)); break; }
      }

      // DocuSign/document signing lure
      const docLure = [
        /(?:verify|sign|review)\s+(?:to\s+)?(?:sign|access|view)\s+(?:this\s+)?document/i,
        /(?:docusign|adobe\s+sign|hellosign|pandadoc)\b/i,
        /document\s+(?:is\s+)?(?:ready|available|waiting)\s+for\s+(?:your\s+)?(?:signature|review)/i,
      ];
      for (const p of docLure) {
        const m = ctx.rawText.match(p);
        if (m) { signals.push(m[0].substring(0, 50)); break; }
      }

      // Steps telling user to copy code and paste it elsewhere
      const stepsPattern = /(?:1|step\s+1)[.)]\s*copy\s+(?:the\s+)?code[\s\S]{0,200}(?:2|step\s+2)[.)]\s*(?:click|go|navigate|open|continue)/i;
      if (stepsPattern.test(ctx.rawText)) signals.push('copy-code numbered steps');

      // Alphanumeric code displayed prominently (monospace/large font with 6-12 char code)
      const codeDisplay = ctx.pageHTML.match(/style\s*=\s*"[^"]*(?:font-size:\s*(?:2[0-9]|[3-9][0-9])|letter-spacing|monospace|font-weight:\s*(?:bold|[6-9]00))[^"]*"[^>]*>[^<]*[A-Z0-9]{6,12}[^<]*</i);
      if (codeDisplay) signals.push('large/styled code display');

      // Non-official domain impersonating brand
      const isBrandDomain = /(?:microsoft|google|apple|docusign|adobe)\.com/i.test(ctx.hostname);
      if (!isBrandDomain && signals.length >= 1) {
        signals.push('non-official domain');
      }

      if (signals.length >= 2) {
        return {
          description: `Device code phishing: ${signals.join(', ')}`,
          evidence: signals.slice(0, 4).join(' | '),
          scoreBonus: signals.length >= 3 ? 12 : 0,
        };
      }
      return null;
    }
  });
})();
