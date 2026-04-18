(function () {
  const H = window.NW_HELPERS;
  if (!H) return;
  NW_register({
    id: 'SUSPICIOUS_HOST', name: 'Suspicious Hosting + Credentials',
    description: 'Credential form on free/suspicious hosting provider',
    defaultScore: 20, tags: ['phishing'],
    detect(ctx) {
      if (!ctx.hasPwdField) return null;
      const pats = [/\.pages\.dev$/, /\.netlify\.app$/, /\.vercel\.app$/, /\.000webhostapp\.com$/, /\.infinityfree\.net$/, /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/];
      for (const p of pats) {
        if (p.test(ctx.hostname)) return { description: `Credential form on suspicious hosting: ${ctx.hostname}`, evidence: ctx.hostname };
      }
      return null;
    }
  });
})();
