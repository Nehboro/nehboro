(function () {
  NW_register({
    id: 'FORMJACKING', name: 'Formjacking / Skimmer',
    description: 'JavaScript payment card skimmer patterns (Magecart-style)',
    defaultScore: 40, tags: ['malware','critical'],
    detect(ctx) {
      const hasCardInput = /(?:card|cc|cvv|cvc|expir|billing)/i.test(ctx.pageHTML) && document.querySelectorAll('input[type="text"], input[type="tel"], input[type="number"]').length >= 3;
      const skimmerPats = [/(?:card_?number|cc_?num|pan)['"]\s*[:,]/i, /(?:btoa|encode|stringify)\s*\([^)]*(?:card|cvv|expir)/i, /new\s+Image\(\)\.src\s*=.*(?:card|cc|cvv)/i];
      const hasSkimmer = skimmerPats.some(p => p.test(ctx.pageHTML));
      if (hasCardInput && hasSkimmer)
        return { description: 'Payment card skimmer pattern detected', evidence: 'Card input fields + data exfiltration pattern' };
      return null;
    }
  });
})();
