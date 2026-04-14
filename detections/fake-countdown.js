(function () {
  NW_register({
    id: 'FAKE_COUNTDOWN', name: 'Fake Countdown Timer',
    description: 'Countdown timer with threat/action-required context',
    defaultScore: 10, tags: ['social-engineering'],
    detect(ctx) {
      const hasCountdown = /setInterval|countdown|timer/i.test(ctx.pageHTML) && /\d+\s*(?:seconds?|minutes?|s)\s*(?:remaining|left|before|until)/i.test(ctx.rawText);
      const hasThreat = /(?:expire|block|lock|suspend|restrict|delete)/i.test(ctx.rawText);
      if (hasCountdown && hasThreat)
        return { description: 'Countdown timer with threat context', evidence: (ctx.rawText.match(/\d+\s*(?:seconds?|minutes?)\s*(?:remaining|left|before|until)[^.]{0,40}/i) || [''])[0] };
      return null;
    }
  });
})();
