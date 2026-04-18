// Nehboro Detection: Data Theft Scare Tactics
// Catches pages claiming user data is being stolen/compromised
(function () {
  NW_register({
    id: 'DATA_THEFT_SCARE', name: 'Data Theft Scare Tactic',
    description: 'Page claims personal data is being stolen (passwords, credit cards, photos, logins)',
    defaultScore: 25, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      const claimPats = [
        // "The following information is being stolen"
        /(?:following|this|your)\s+(?:information|data)\s+(?:is|are)\s+(?:being\s+)?(?:stolen|compromised|harvested|collected|accessed)/i,
        // Lists of stolen data types
        /(?:credit\s+card|bank\s+(?:account|detail)|password|login)\s+(?:details?|info|credentials?|data)\s+(?:are|is|being)\s+(?:stolen|at\s+risk|compromised)/i,
        // "Facebook logins", "Email Account Logins" style lists
        /(?:facebook|email|bank(?:ing)?|credit\s+card|social\s+media)\s+(?:account\s+)?logins?/i,
        // "Photos and documents stored on this computer"
        /(?:photos?|documents?|files?)\s+(?:stored|saved)\s+(?:on\s+)?(?:this|your)\s+(?:computer|device|pc)/i,
        // "Your identity is at risk"
        /(?:your|personal)\s+(?:identity|privacy|data)\s+(?:is|are)\s+(?:at\s+risk|in\s+danger|being\s+(?:stolen|compromised))/i,
        // "Pornographic spyware" style scare claims
        /(?:pornographic|adult)\s+(?:spyware|malware|virus|content)\s+(?:detected|found|installed)/i,
      ];

      let hits = 0;
      const evidence = [];
      for (const p of claimPats) {
        const m = ctx.rawText.match(p);
        if (m) { hits++; evidence.push(m[0]); }
      }

      if (hits >= 2) {
        return {
          description: `${hits} data theft scare claims detected`,
          evidence: evidence.slice(0, 3).join(' | '),
          scoreBonus: hits >= 3 ? 10 : 0,
        };
      }
      return null;
    }
  });
})();
