// Nehboro Detection: Browser Lock / Fullscreen Abuse
(function () {
  const H = window.NW_HELPERS;
  if (!H) return;

  NW_register({
    id: 'BROWSER_LOCK', name: 'Browser Lock / Fullscreen Abuse',
    description: 'Page uses fullscreen API, history manipulation, or popstate traps to lock the user in',
    defaultScore: 30, tags: ['social-engineering','scam'],
    detect(ctx) {
      const signals = [];

      // Fullscreen API abuse
      if (/requestFullscreen|webkitRequestFullScreen|mozRequestFullScreen/i.test(ctx.pageHTML))
        signals.push('requestFullscreen');

      // History pushState spam to prevent back navigation
      if (/history\.pushState\s*\([\s\S]{0,50}\)\s*[;,][\s\S]{0,100}history\.pushState/i.test(ctx.pageHTML))
        signals.push('history.pushState spam');

      // Popstate trap (prevents leaving)
      if (/onpopstate|addEventListener\s*\(\s*['"]popstate['"]/i.test(ctx.pageHTML) &&
          /history\.pushState|history\.forward|location\.replace/i.test(ctx.pageHTML))
        signals.push('popstate trap');

      // beforeunload trap with custom message
      if (/onbeforeunload|addEventListener\s*\(\s*['"]beforeunload['"]/i.test(ctx.pageHTML) &&
          /returnValue\s*=|preventDefault/i.test(ctx.pageHTML))
        signals.push('beforeunload trap');

      // Disable right-click + keyboard combos
      if (/oncontextmenu\s*=\s*['"]?\s*return\s+false/i.test(ctx.pageHTML) &&
          /onkeydown|addEventListener\s*\(\s*['"]keydown['"]/i.test(ctx.pageHTML))
        signals.push('keyboard/context block');

      if (signals.length >= 2) {
        return { description: `Browser lock: ${signals.join(' + ')}`, evidence: signals.join(', ') };
      }
      return null;
    }
  });
})();
