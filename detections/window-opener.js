(function () {
  NW_register({
    id: 'WINDOW_OPENER_ABUSE', name: 'window.opener Abuse',
    description: 'Page manipulates window.opener to redirect the parent tab (reverse tabnabbing)',
    defaultScore: 22, tags: ['phishing'],
    detect(ctx) {
      if (/window\.opener\s*\.\s*(?:location|document)/i.test(ctx.pageHTML))
        return { description: 'window.opener manipulation detected (reverse tabnabbing)', evidence: (ctx.pageHTML.match(/window\.opener\s*\.\s*(?:location|document)[^;]{0,60}/i) || [''])[0] };
      return null;
    }
  });
})();
