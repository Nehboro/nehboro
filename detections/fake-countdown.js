(function () {
  NW_register({
    id: 'FAKE_COUNTDOWN', name: 'Fake Countdown Timer',
    description: 'Countdown timer with threat/action-required context',
    defaultScore: 10, tags: ['social-engineering'],
    detect(ctx) {
      const html = ctx.pageHTML;
      const text = ctx.rawText;
      // Multiple countdown signals - need at least 2
      const signals = [];

      // 1. Countdown JS code
      const hasCountdownJS = /setInterval[\s\S]{0,200}(?:counter|timer|countdown|--|t-=)/i.test(html);
      if (hasCountdownJS) signals.push('countdown JS');

      // 2. Time format displayed (MM:SS, HH:MM:SS, "5 minutes left")
      const hasTimeFormat = /\d{1,2}\s*:\s*\d{2}/.test(text) ||
                            /\d+\s*(?:seconds?|minutes?|hours?|s|m|h)\s*(?:remaining|left|before|until|to\s+go)/i.test(text);
      if (hasTimeFormat) signals.push('time format displayed');

      // 3. Countdown id/class in HTML
      const hasCountdownId = /id\s*=\s*["'](?:counter|countdown|timer|clock)/i.test(html) ||
                             /class\s*=\s*["'][^"']*(?:countdown|timer|count-?down)/i.test(html);
      if (hasCountdownId) signals.push('countdown element');

      // 4. Threat/scarcity context
      const hasThreat = /(?:expire|block|lock|suspend|restrict|delete|miss|gone|sold\s+out|offer\s+ends?|hurry|last\s+chance|limited\s+time)/i.test(text);
      if (hasThreat) signals.push('scarcity context');

      if (signals.length >= 2) {
        return {
          description: `Countdown timer with ${signals.length} signals: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: signals.length >= 3 ? 8 : 0,
        };
      }
      return null;
    }
  });
})();
