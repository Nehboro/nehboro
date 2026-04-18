// Nehboro Detection: Fake URL Bar / Browser-in-Browser (BitB)
// Catches base64-encoded images of browser chrome, fake address bars, fake EV certificates
(function () {
  NW_register({
    id: 'FAKE_URL_BAR', name: 'Fake URL Bar / BitB Attack',
    description: 'Page renders a fake browser URL bar or address bar as an image (Browser-in-Browser phishing)',
    defaultScore: 40, tags: ['phishing','social-engineering','critical'],
    detect(ctx) {
      const signals = [];

      // Base64 image that's very wide and short (URL bar shape: ~600-1200px wide, 30-80px tall)
      // This is the core BitB technique - screenshot of a URL bar embedded as data:image
      const imgEls = document.querySelectorAll('img[src^="data:image"]');
      for (const img of imgEls) {
        const w = img.naturalWidth || img.width;
        const h = img.naturalHeight || img.height;
        if (w > 400 && h > 20 && h < 100 && w / h > 6) {
          signals.push(`data:image bar-shaped (${w}x${h})`);
          break;
        }
      }

      // data:image/jpeg or png in src that looks like a URL bar screenshot
      if (/data:image\/(?:jpeg|png)[^"']{500,}/.test(ctx.pageHTML)) {
        // Check if nearby text references a domain or https
        if (/(?:https:\/\/|Microsoft Corporation|Verified by|EV SSL|secure\s+connection)/i.test(ctx.rawText))
          signals.push('base64 image near security text');
      }

      // Fake padlock / certificate indicators in text
      const fakeCertPats = [
        /\[US\]\s*https?:\/\//i,
        /Microsoft Corporation\s*\[US\]/i,
        /(?:Google|Apple|PayPal)\s+(?:LLC|Inc|Corp)\s*\[US\]/i,
        /verified?\s+(?:by|organization|identity)/i,
        /EV\s+(?:SSL|certificate|cert)/i,
      ];
      for (const p of fakeCertPats) {
        if (p.test(ctx.rawText) || p.test(ctx.pageHTML)) {
          signals.push('fake certificate indicator');
          break;
        }
      }

      // Iframe or nested frame simulating a browser window
      if (/class\s*=\s*["'][^"']*(?:browser-window|fake-browser|address-bar|url-bar|browser-frame|chrome-frame)/i.test(ctx.pageHTML))
        signals.push('fake browser frame CSS class');

      // S3/cloud storage hosting scam page (image 1 shows s3.amazonaws.com)
      if (/s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net/i.test(ctx.url) &&
          /(?:error|alert|warning|support|security|blocked)/i.test(ctx.rawText))
        signals.push('scam on cloud storage');

      if (signals.length >= 1) {
        return {
          description: `Fake URL bar / BitB: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: signals.length >= 2 ? 15 : 0,
        };
      }
      return null;
    }
  });
})();
