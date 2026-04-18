// Nehboro Detection: Fake Error / BSOD / System Warning Page
(function () {
  NW_register({
    id: 'FAKE_ERROR_PAGE', name: 'Fake Error / BSOD Page',
    description: 'Fake browser error, BSOD, system crash, or Windows warning page',
    defaultScore: 30, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      const pats = [
        // Computer blocked/locked/infected
        /your\s+(?:computer|pc|device)\s+(?:has\s+been|is|was)\s+(?:blocked|locked|infected|compromised|hacked)/i,
        // Windows Defender/Security alerts
        /windows\s+(?:defender|security)\s+(?:alert|warning|notification|has\s+detected)/i,
        // Critical error/alert
        /critical\s+(?:error|alert|warning)\s*:?\s*(?:your|this|#|code)/i,
        // BSOD / stop error / "ran into a problem" (Image 3)
        /(?:blue\s+screen|bsod|stop\s+error|0x[0-9A-F]{8})/i,
        /your\s+pc\s+ran\s+into\s+a\s+problem/i,
        /:\(\s*\n?\s*your\s+(?:pc|device|computer)/i,  // :( emoticon + PC error (BSOD style)
        // Do not close/shutdown
        /do\s+not\s+(?:close|shut\s*down|restart|turn\s*off|ignore)\s+(?:this|your)/i,
        // "If you close this page" threats
        /if\s+you\s+close\s+this\s+(?:page|window|browser|tab)/i,
        // Computer access will be disabled/restricted
        /(?:computer|access|account)\s+(?:will\s+be|has\s+been)\s+(?:disabled|restricted|suspended|terminated)/i,
        // "Your computer has alerted us"
        /(?:your\s+)?computer\s+has\s+(?:alerted|notified|reported|detected)/i,
        // "Please do not try to close" / "Do not ignore this critical alert"
        /(?:please\s+)?do\s+not\s+(?:try\s+to\s+)?(?:close|ignore|dismiss)\s+this\s+(?:critical|important)/i,
        // Malware Alert / Virus Alert in title-like text
        /(?:malware|virus|spyware|trojan)\s+(?:alert|warning|detected|found)\s*[!:]/i,
      ];
      let hits = 0;
      const evidence = [];
      for (const p of pats) {
        const m = ctx.rawText.match(p);
        if (m) { hits++; evidence.push(m[0]); }
      }
      if (hits >= 2) return {
        description: `${hits} fake error/crash page signals`,
        evidence: evidence.slice(0, 3).join(' | '),
        scoreBonus: hits >= 4 ? 15 : hits >= 3 ? 8 : 0,
      };
      return null;
    }
  });
})();
