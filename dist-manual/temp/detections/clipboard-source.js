// Nehboro Detection: Clipboard API in Page Source
(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'CLIPBOARD_SOURCE', name: 'Clipboard Write in Source',
    description: 'Page source contains navigator.clipboard.writeText or execCommand copy calls',
    defaultScore: 10, tags: ['clickfix','malware'],
    detect(ctx) {
      const pats = [
        /navigator\s*\.\s*clipboard\s*\.\s*writeText/gi,
        /document\s*\.\s*execCommand\s*\(\s*['"]copy['"]/gi,
        /clipboardData\s*\.\s*setData/gi,
      ];
      const hits = pats.filter(p => p.test(ctx.pageHTML)).length;
      if (hits > 0) {
        // Check if there's also a suspicious payload nearby
        const hasSuspicious = /powershell|mshta|wscript|cscript|certutil|curl\s.*\|.*sh|osascript/i.test(ctx.pageHTML);
        return { description: `${hits} clipboard write API calls in page source`, evidence: `clipboard API + ${hasSuspicious ? 'suspicious payload' : 'unknown payload'}`, scoreBonus: hasSuspicious ? 15 : 0 };
      }
      return null;
    }
  });
})();
