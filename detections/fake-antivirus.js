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
        /windows\s+defender.*(?:detected|alert|warning|threats?)/i,
        /(?:trojan|backdoor|worm|spyware|adware)[:.]\s*\w+/i,
        /(?:critical|severe|high)\s*(?:risk|severity|threat\s*level)/i,
      ];
      let hits = 0;
      const matched = [];
      for (const p of pats) {
        if (p.test(ctx.rawText)) {
          hits++;
          if (matched.length < 2) matched.push(ctx.rawText.match(p)[0].substring(0, 50));
        }
      }
      if (hits >= 2) return {
        description: `${hits} fake antivirus scan signals`,
        evidence: matched.join(' | '),
        scoreBonus: hits >= 4 ? 15 : hits >= 3 ? 8 : 0,
      };
      return null;
    }
  });
})();
