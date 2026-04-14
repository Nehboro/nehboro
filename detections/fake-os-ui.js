// Nehboro Detection: Fake OS/Browser UI Elements
// Catches pages that render fake Windows dialogs, browser popups, system notifications
(function () {
  NW_register({
    id: 'FAKE_OS_UI', name: 'Fake System UI Overlay',
    description: 'Page renders fake Windows dialog boxes, browser alerts, or OS notification overlays in HTML/CSS',
    defaultScore: 28, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      const signals = [];

      // Fake Windows dialog/titlebar keywords in styled elements
      const fakeDialogPats = [
        /security\s+warning/i,
        /windows\s+security\s+(?:alert|warning|notification)/i,
        /microsoft\s+(?:warning|alert|notification)\s+(?:alert)?/i,
        /system\s+(?:alert|warning|error|notification)/i,
        /(?:windows|microsoft)\s+(?:support|help)\s+(?:alert|warning)/i,
      ];
      let dialogHits = 0;
      for (const p of fakeDialogPats) if (p.test(ctx.rawText)) dialogHits++;
      if (dialogHits >= 2) signals.push(`${dialogHits} fake dialog titles`);

      // CSS that creates fake window chrome (title bars, X buttons, dialog borders)
      const fakeWindowCSS = [
        /class\s*=\s*["'][^"']*(?:dialog|modal|popup|overlay|titlebar|window-frame)[^"']*["']/gi,
        /class\s*=\s*["'][^"']*(?:close-btn|close-button|btn-close|x-button)[^"']*["']/gi,
      ];
      let cssHits = 0;
      for (const p of fakeWindowCSS) cssHits += (ctx.pageHTML.match(p) || []).length;
      if (cssHits >= 3) signals.push(`${cssHits} fake window UI elements`);

      // "Back to safety" / "OK" / "Close" buttons that are part of the scam (not real browser UI)
      if (/(?:back\s+to\s+safety|return\s+to\s+safety|close\s+all\s+tabs)/i.test(ctx.rawText) &&
          dialogHits >= 1)
        signals.push('fake safety button');

      // Multiple overlapping fixed/absolute positioned elements (simulating stacked dialogs)
      const fixedEls = ctx.pageHTML.match(/position\s*:\s*(?:fixed|absolute)/gi) || [];
      const zIndexHigh = ctx.pageHTML.match(/z-index\s*:\s*\d{4,}/gi) || [];
      if (fixedEls.length >= 5 && zIndexHigh.length >= 3)
        signals.push('stacked overlay dialogs');

      // Audio autoplay (scam pages often play alarm sounds)
      if (/<audio[^>]*autoplay/i.test(ctx.pageHTML) || /\.play\s*\(\s*\)/i.test(ctx.pageHTML))
        signals.push('autoplay audio');

      if (signals.length >= 1) {
        return {
          description: `Fake system UI: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: signals.length >= 3 ? 15 : signals.length >= 2 ? 8 : 0,
        };
      }
      return null;
    }
  });
})();
