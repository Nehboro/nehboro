(function () {
  NW_register({
    id: 'HIDDEN_CONTENT', name: 'Hidden Malicious Content',
    description: 'Suspicious commands hidden via CSS (display:none, tiny text, off-screen)',
    defaultScore: 20, tags: ['evasion','clickfix'],
    detect(ctx) {
      const hidden = document.querySelectorAll('[style*="display:none"], [style*="display: none"], [style*="visibility:hidden"], [style*="font-size:0"], [style*="font-size: 0"]');
      for (const el of hidden) {
        const t = el.textContent || '';
        if (/powershell|mshta|wscript|curl.*\|.*sh|certutil|bitsadmin/i.test(t))
          return { description: 'Suspicious commands hidden via CSS', evidence: t.substring(0, 100) };
      }
      return null;
    }
  });
})();
