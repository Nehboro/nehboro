(function () {
  NW_register({
    id: 'DATA_URI_PAYLOAD', name: 'Data URI Payload',
    description: 'Suspicious data: URI with executable or encoded content',
    defaultScore: 25, tags: ['malware','evasion'],
    detect(ctx) {
      const m = ctx.pageHTML.match(/data:\s*(?:text\/html|application\/x-msdownload|application\/javascript)[^"'\s]{100,}/i);
      if (m) return { description: 'Suspicious data: URI with executable content', evidence: m[0].substring(0, 120) };
      return null;
    }
  });
})();
