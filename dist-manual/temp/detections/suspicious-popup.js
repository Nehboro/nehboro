(function () {
  NW_register({
    id: 'SUSPICIOUS_POPUP', name: 'Suspicious window.open / Popup',
    description: 'Page opens popups or uses window.open with suspicious URLs',
    defaultScore: 12, tags: ['phishing','heuristic'],
    detect(ctx) {
      const popupPats = [/window\.open\s*\(\s*['"](?:data:|javascript:|blob:)/gi, /window\.open\s*\([^)]*(?:\.exe|\.msi|\.bat|\.ps1)/gi];
      for (const p of popupPats) {
        const m = ctx.pageHTML.match(p);
        if (m) return { description: 'Suspicious window.open call', evidence: m[0].substring(0, 100) };
      }
      return null;
    }
  });
})();
