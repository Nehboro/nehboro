(function () {
  NW_register({
    id: 'EXTERNAL_SCRIPT_OVERLOAD', name: 'Excessive External Scripts',
    description: 'Unusually high number of external scripts from different domains',
    defaultScore: 12, tags: ['heuristic','malware'],
    detect(ctx) {
      const scripts = [...document.querySelectorAll('script[src]')];
      const externalDomains = new Set();
      for (const s of scripts) {
        try { const h = new URL(s.src).hostname; if (h !== ctx.hostname) externalDomains.add(h); } catch {}
      }
      if (externalDomains.size >= 10 && ctx.hasPwdField)
        return { description: `${externalDomains.size} external script domains on credential page`, evidence: [...externalDomains].slice(0, 5).join(', ') };
      return null;
    }
  });
})();
