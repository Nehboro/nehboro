// Nehboro Detection: Raw IP Address Hosting
// Pages served directly from IP addresses are suspicious, especially with scam content
(function () {
  NW_register({
    id: 'RAW_IP_HOSTING', name: 'Raw IP Address Hosting',
    description: 'Page served from a raw IP address (no domain name) combined with suspicious content',
    defaultScore: 15, tags: ['phishing','heuristic'],
    detect(ctx) {
      // Check if hostname is a raw IP address
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ctx.hostname)) return null;

      const signals = ['raw IP: ' + ctx.hostname];

      // Higher score if combined with scam signals
      if (/(?:blocked|locked|infected|error|alert|warning|support|call|phone)/i.test(ctx.rawText))
        signals.push('scam keywords present');
      if (ctx.hasPwdField)
        signals.push('login form on raw IP');
      if (/(?:microsoft|apple|google|amazon|facebook|paypal)/i.test(ctx.rawText))
        signals.push('brand name on raw IP');

      return {
        description: `Page served from raw IP address ${ctx.hostname}`,
        evidence: signals.join(' | '),
        scoreBonus: signals.length >= 3 ? 20 : signals.length >= 2 ? 10 : 0,
      };
    }
  });
})();
