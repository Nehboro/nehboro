(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'SUSPICIOUS_REDIRECT', name: 'Suspicious Meta Redirect',
    description: 'Meta refresh redirect to a different domain',
    defaultScore: 18, tags: ['phishing'],
    detect(ctx) {
      const meta = document.querySelector('meta[http-equiv="refresh"]');
      if (!meta) return null;
      const content = meta.getAttribute('content') || '';
      if (!/url\s*=/i.test(content)) return null;
      const target = content.replace(/.*url\s*=\s*/i, '').trim();
      try {
        const host = new URL(target, ctx.url).hostname;
        if (host && host !== ctx.hostname)
          return { description: `Meta redirect to different domain: ${host}`, evidence: content.substring(0, 200) };
      } catch {}
      return null;
    }
  });
})();
