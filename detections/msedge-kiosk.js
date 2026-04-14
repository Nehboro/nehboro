// Nehboro Detection: msedge --kiosk Phishing
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!H) return;

  NW_register({
    id: 'MSEDGE_KIOSK', name: 'Edge Kiosk Mode Phishing',
    description: 'Page instructs launching msedge.exe --kiosk to create a fake fullscreen login (BitB / kiosk phishing)',
    defaultScore: 50, tags: ['phishing','clickfix','critical'],
    detect(ctx) {
      // msedge --kiosk is used to open a chromeless fullscreen browser window
      // that mimics a real OS login prompt or browser popup
      const kioskPats = [
        /msedge(?:\.exe)?\s+--kiosk/i,
        /microsoft-edge:.*--kiosk/i,
        /start\s+msedge\s+.*--kiosk/i,
        /--kiosk\s+['""]?https?:\/\//i,
        /--window-size=\d+,\d+.*--kiosk/i,
        /--app=.*https?:\/\/.*(?:login|signin|auth|verify|account)/i,
      ];
      for (const p of kioskPats) {
        const m = (ctx.rawText + ctx.pageHTML).match(p);
        if (m) {
          // Extra score if combined with credential keywords
          const hasLogin = /(?:login|sign.?in|password|credential|authenticate|verify\s+your)/i.test(ctx.rawText);
          return {
            description: 'msedge --kiosk mode used to create fake fullscreen login window',
            evidence: m[0].substring(0, 200),
            scoreBonus: hasLogin ? 15 : 0,
          };
        }
      }
      // Also detect --app mode abuse (chromeless window for phishing)
      const appMode = (ctx.rawText + ctx.pageHTML).match(/(?:chrome|msedge|brave)(?:\.exe)?\s+--app\s*=\s*['"]?https?:\/\/[^\s'"]+/i);
      if (appMode) {
        const targetUrl = appMode[0];
        const isSuspicious = /(?:login|auth|signin|verify|account|secure|update)/i.test(targetUrl);
        if (isSuspicious) return {
          description: 'Browser --app mode launching suspicious login URL (chromeless phishing)',
          evidence: targetUrl.substring(0, 200),
          scoreOverride: 35,
        };
      }
      return null;
    }
  });
})();
