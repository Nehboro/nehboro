(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'WEBDAV_MOUNT', name: 'WebDAV Share Mount',
    description: 'WebDAV share-mount signals (net use) - 2+ required',
    defaultScore: 38, tags: ['malware','clickfix'],
    detect(ctx) {
      const combined = ctx.rawText + ctx.pageHTML;
      const hits = H.countMatches(P.WEBDAV, combined);
      if (hits >= 2) return { description: `${hits} WebDAV share-mount signals`, evidence: H.firstMatch(P.WEBDAV, combined) };
      return null;
    }
  });
})();
