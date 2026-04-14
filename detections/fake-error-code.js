// Nehboro Detection: Fake System Error Codes
// Catches fake MS-xxxx, 0x error codes, DLL errors, Windows error names
(function () {
  NW_register({
    id: 'FAKE_ERROR_CODE', name: 'Fake Windows Error Code',
    description: 'Page displays fake Microsoft/Windows error codes (MS-SYSINFO, 0x errors, DLL errors)',
    defaultScore: 30, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      const pats = [
        // Fake MS- error codes (MS-SYSINFO32, MS-DCOM, etc.)
        /\bMS-[A-Z]{2,}(?:\d+)?\b/,
        // Fake Windows error names used in scams
        /\berror\s*(?:code|#|number)?\s*:?\s*(?:MS-|DW6VB|0x[0-9A-F]{4,}|WIN\d|ERR_)/i,
        // DLL missing/corrupt errors
        /\b\w+\.dll\s+(?:is\s+)?(?:missing|not\s+found|corrupt|failed|error)/i,
        // Windows Defender / Security Essentials fake alerts
        /windows\s+(?:security\s+essentials?|defender)\s+(?:was|has|could)\s+(?:not|unable)/i,
        // Fake firewall/protection disabled
        /(?:firewall|virus\s+protection|real.?time\s+protection)\s+(?:is\s+)?(?:disabled|turned\s+off|not\s+working)/i,
        // Definition update failures
        /(?:definition|virus\s+database)\s+(?:update|download)\s+(?:failed|error|could\s+not)/i,
      ];
      let hits = 0;
      const evidence = [];
      for (const p of pats) {
        const m = ctx.rawText.match(p);
        if (m) { hits++; evidence.push(m[0]); }
      }
      if (hits >= 1) {
        // Higher score if combined with phone number
        const hasPhone = /\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/.test(ctx.rawText);
        return {
          description: `${hits} fake error code(s) detected`,
          evidence: evidence.slice(0, 3).join(' | '),
          scoreBonus: hasPhone ? 15 : (hits >= 2 ? 8 : 0),
        };
      }
      return null;
    }
  });
})();
