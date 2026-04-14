// Nehboro Detection: Search Hijacking
// Catches pages that redirect search queries or attempt to change default search
(function () {
  NW_register({
    id: 'SEARCH_HIJACKING', name: 'Search Hijacking',
    description: 'Page redirects search queries through a different search engine or modifies search behavior',
    defaultScore: 22, tags: ['malware','social-engineering'],
    detect(ctx) {
      const signals = [];

      // Check if current page is a fake search results page
      // Fake search pages mimic Google/Bing results but on a different domain
      const knownSearchDomains = ['google.com','bing.com','duckduckgo.com','yahoo.com','yandex.com','baidu.com','ecosia.org','startpage.com','brave.com','search.yahoo.com'];
      const isLegitSearch = knownSearchDomains.some(d => ctx.hostname === d || ctx.hostname.endsWith('.' + d));

      if (!isLegitSearch) {
        // Page has search query parameters and looks like search results
        const hasSearchParams = /[?&](?:q|query|search|keyword|term|s)=/i.test(ctx.url);
        const looksLikeResults = /(?:search\s+results?|results?\s+for|showing\s+results?|about\s+\d+\s+results?)/i.test(ctx.rawText);

        if (hasSearchParams && looksLikeResults) {
          signals.push('fake search results page');
        }

        // Page title mimics a search engine
        if (/(?:search|google|bing|yahoo)\s*[-–-]\s*(?:search|results)/i.test(ctx.title) && !isLegitSearch) {
          signals.push('title mimics search engine');
        }
      }

      // Page contains scripts that modify search settings
      const hijackPatterns = [
        // Modify browser new tab / homepage
        /chrome\.(?:settings|tabs)\.update.*(?:newTab|homepage)/i,
        // Override search provider
        /defaultSearchProvider|searchProvider|chrome\.search/i,
        // Redirect from legitimate search to fake
        /location\s*[.=].*(?:google|bing|yahoo|duckduckgo).*(?:replace|href|assign)/i,
      ];
      for (const p of hijackPatterns) {
        if (p.test(ctx.pageHTML)) {
          signals.push('search settings manipulation in code');
          break;
        }
      }

      // Intercepts search form submissions
      if (/form.*action.*(?:search|query).*addEventListener.*submit.*(?:location|window\.open|redirect)/is.test(ctx.pageHTML))
        signals.push('search form submission interception');

      if (signals.length >= 1) {
        return {
          description: `Search hijacking: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: signals.length >= 2 ? 10 : 0,
        };
      }
      return null;
    }
  });
})();
