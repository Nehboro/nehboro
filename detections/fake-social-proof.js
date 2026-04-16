(function () {
  NW_register({
    id: 'FAKE_SOCIAL_PROOF', name: 'Fake Social Proof',
    description: 'Fake user count, fake reviews, or popup-style social proof claims',
    defaultScore: 12, tags: ['social-engineering'],
    detect(ctx) {
      const text = ctx.rawText;
      const html = ctx.pageHTML;
      const signals = [];

      // Original patterns - explicit user counts
      const userCountPats = [
        /\d{3,}\s+users?\s+(?:verified|joined|already|signed|active|online)/i,
        /(?:trusted\s+by|used\s+by|joined\s+by)\s+\d+[,.]?\d+/i,
        /\d{1,3}(?:,\d{3})+\s+(?:users?|customers?|people|downloads?|members?)/i, // "12,847 users"
        /\d+,?\d+\s+(?:people|users?)\s+(?:downloaded|bought|signed\s+up|joined)\s+(?:this|today|this\s+week)/i,
        /join\s+(?:thousands|millions)\s+of\s+(?:satisfied\s+)?(?:customers|users)/i,
      ];
      for (const p of userCountPats) {
        const m = text.match(p);
        if (m) signals.push('user-count: ' + m[0].substring(0, 50));
      }

      // Fake star ratings ("⭐⭐⭐⭐⭐ 4.9/5 from 12,847")
      if (/[★⭐]{4,}\s*[\d.]+\/5/i.test(text) && /\d{3,}\s*(?:users?|reviews?|ratings?|customers?)/i.test(text))
        signals.push('star-rating + count');

      // Fake live notifications "Jessica from New York just bought"
      const liveNotifPats = [
        /\b[A-Z][a-z]+\s+from\s+[A-Z][a-z]+\s+just\s+(?:bought|signed\s+up|joined|downloaded|purchased|ordered)/i,
        /\b\d+\s+(?:minute|second|hour)s?\s+ago/i,
      ];
      let liveNotifs = 0;
      for (const p of liveNotifPats) {
        if (p.test(text)) liveNotifs++;
      }
      // Multiple "X minutes ago" occurrences = live notification spam
      const minutesAgoCount = (text.match(/\d+\s+minutes?\s+ago/gi) || []).length;
      if (minutesAgoCount >= 2) signals.push(`${minutesAgoCount} fake live notifications`);
      if (liveNotifs >= 1 && minutesAgoCount >= 1) signals.push('live notification format');

      // High count of testimonials / fake names with action
      const fakeBuyerCount = (text.match(/\b[A-Z][a-z]+\s+(?:from\s+[A-Z][a-z]+\s+)?just\s+(?:bought|signed|joined|ordered|purchased)/gi) || []).length;
      if (fakeBuyerCount >= 2) signals.push(`${fakeBuyerCount} fake buyer announcements`);

      if (signals.length >= 1) {
        return {
          description: `Fake social proof (${signals.length} signal${signals.length > 1 ? 's' : ''})`,
          evidence: signals.slice(0, 3).join(' | '),
          scoreBonus: signals.length >= 3 ? 10 : signals.length >= 2 ? 5 : 0,
        };
      }
      return null;
    }
  });
})();
