(function () {
  const H = window.NW_HELPERS;
  if (!H) return;
  const BRANDS = [
    { name: 'Microsoft', domains: ['microsoft.com','live.com','outlook.com','microsoftonline.com'] },
    { name: 'Google', domains: ['google.com','gmail.com','accounts.google.com'] },
    { name: 'Apple', domains: ['apple.com','icloud.com'] },
    { name: 'Facebook', domains: ['facebook.com','instagram.com','meta.com'] },
    { name: 'PayPal', domains: ['paypal.com'] },
    { name: 'Amazon', domains: ['amazon.com','amazon.co.uk'] },
    { name: 'Netflix', domains: ['netflix.com'] },
    { name: 'LinkedIn', domains: ['linkedin.com'] },
  ];
  NW_register({
    id: 'PHISHING_IMPERSONATION', name: 'Brand Impersonation + Login',
    description: 'Page title impersonates a major brand while showing a login form on a non-official domain',
    defaultScore: 35, tags: ['phishing','critical'],
    detect(ctx) {
      if (!ctx.hasPwdField) return null;
      const title = ctx.title.toLowerCase();
      for (const brand of BRANDS) {
        const impersonates = title.includes(brand.name.toLowerCase()) && !brand.domains.some(d => ctx.hostname.endsWith(d));
        if (impersonates && !ctx.hostname.endsWith('.gov') && !ctx.hostname.endsWith('.edu'))
          return { description: `Impersonates ${brand.name} on non-official domain`, evidence: `Domain: ${ctx.hostname} | Title: ${ctx.title.substring(0, 80)}` };
      }
      return null;
    }
  });
})();
