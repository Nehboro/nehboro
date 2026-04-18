(function () {
  NW_register({
    id: 'SEO_POISONING', name: 'SEO Poisoning / Cloaking',
    description: 'Page serves different content based on referrer (SEO cloaking)',
    defaultScore: 15, tags: ['evasion','heuristic'],
    detect(ctx) {
      if (/document\.referrer\s*[\.\[].*(?:google|bing|yahoo|duckduckgo)/i.test(ctx.pageHTML) && /(?:location\s*[=.]|window\.location|redirect|replace)/i.test(ctx.pageHTML))
        return { description: 'Referrer-based content switching detected (SEO cloaking)', evidence: 'document.referrer check + redirect logic' };
      return null;
    }
  });
})();
