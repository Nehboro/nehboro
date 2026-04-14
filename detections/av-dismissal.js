// Nehboro Detection: Antivirus Dismissal Pretext
// Catches pages that preemptively dismiss antivirus warnings as "expected behavior"
// This is a ClickFix evasion technique - tell the user to ignore security software warnings
(function () {
  NW_register({
    id: 'AV_DISMISSAL_PRETEXT', name: 'Antivirus Dismissal Pretext',
    description: 'Page tells users to ignore antivirus/security warnings as "expected behavior" or "false positive"',
    defaultScore: 30, tags: ['clickfix','social-engineering','evasion','critical'],
    detect(ctx) {
      const signals = [];

      const pats = [
        // "Windows Defender may display a notification. This is expected behavior" (Image 2)
        /(?:windows\s+defender|antivirus|security\s+software|firewall)\s+(?:may|might|could|will)\s+(?:display|show|trigger|flag|detect)/i,
        // "This is expected/normal behavior"
        /this\s+is\s+(?:expected|normal|standard)\s+(?:behavior|behaviour)/i,
        // "does not indicate any issue/threat"
        /does\s+not\s+(?:indicate|mean|represent)\s+(?:any\s+)?(?:issue|threat|problem|danger)/i,
        // "you can safely ignore"
        /(?:you\s+can\s+)?(?:safely\s+)?(?:ignore|dismiss|close|skip)\s+(?:the\s+)?(?:warning|alert|notification|popup)/i,
        // "this is a false positive"
        /(?:this\s+is\s+a?\s*)?false\s+positive/i,
        // "standard security verification/procedure"
        /(?:standard|routine|normal)\s+(?:security\s+)?(?:verification|procedure|process|check)\s+(?:performed\s+)?(?:for\s+)?(?:all\s+)?(?:users)?/i,
        // "For security and system integrity, this process follows standard Windows procedures" (Image 2 footer)
        /(?:security\s+and\s+system\s+integrity|follows?\s+standard\s+(?:windows|system)\s+procedures?)/i,
        // "your access will be fully restored"
        /(?:your\s+)?access\s+will\s+be\s+(?:fully\s+)?(?:restored|resumed|unblocked)/i,
        // "new security processes" dismissal
        /(?:new|updated?)\s+security\s+process(?:es)?\s+(?:and\s+)?(?:does\s+not|don't)/i,
      ];

      for (const p of pats) {
        const m = ctx.rawText.match(p);
        if (m) { signals.push(m[0].substring(0, 60)); }
      }

      // Higher confidence if combined with ClickFix instructions (Win+R, Ctrl+V, terminal)
      const hasClickFix = /(?:win(?:dows)?\s*\+\s*[rx]|ctrl\s*\+\s*v|press\s+enter|powershell|terminal)/i.test(ctx.rawText);

      if (signals.length >= 1 && hasClickFix) {
        return {
          description: `AV dismissal pretext with ClickFix: ${signals.join(', ')}`,
          evidence: signals.slice(0, 3).join(' | '),
          scoreBonus: signals.length >= 2 ? 10 : 0,
        };
      }

      if (signals.length >= 2) {
        return {
          description: `AV dismissal pretext: ${signals.join(', ')}`,
          evidence: signals.slice(0, 3).join(' | '),
        };
      }
      return null;
    }
  });
})();
