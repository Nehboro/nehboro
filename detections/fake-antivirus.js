(function () {
  NW_register({
    id: 'FAKE_ANTIVIRUS', name: 'Fake Antivirus Scan',
    description: 'Fake antivirus scan or malware detection page',
    defaultScore: 35, tags: ['social-engineering','scam'],
    detect(ctx) {
      const pats = [
        /(?:virus|malware|trojan|threat)s?\s+(?:found|detected|discovered)/i,
        /(?:your|this)\s+(?:computer|device|system)\s+is\s+(?:infected|at\s+risk)/i,
        /(?:scan|scanning)\s+(?:complete|finished|results?)/i,
        /(?:remove|clean|fix)\s+(?:threats?|virus|malware)\s+now/i,
      ];
      let hits = 0;
      for (const p of pats) if (p.test(ctx.rawText)) hits++;
      if (hits >= 3) return { description: `${hits} fake antivirus scan signals`, evidence: ctx.rawText.match(pats.find(p => p.test(ctx.rawText)))?.[0] || '' };
      return null;
    }
  });
})();
