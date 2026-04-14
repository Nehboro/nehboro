// Nehboro Detection: Scam Phone Number Patterns
// Catches prominent/repeated phone numbers typical of tech support scams
(function () {
  NW_register({
    id: 'SCAM_PHONE_PROMINENT', name: 'Prominent Scam Phone Number',
    description: 'Phone number displayed prominently, repeated, or styled as call-to-action',
    defaultScore: 20, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      // Extract all phone numbers from page text
      const phonePattern = /\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
      const phones = ctx.rawText.match(phonePattern) || [];

      if (phones.length === 0) return null;

      const signals = [];

      // Same number repeated 2+ times = scam signal
      const normalized = phones.map(p => p.replace(/\D/g, ''));
      const freq = {};
      for (const n of normalized) freq[n] = (freq[n] || 0) + 1;
      const maxRepeat = Math.max(...Object.values(freq));
      if (maxRepeat >= 2) signals.push(`same number repeated ${maxRepeat}x`);

      // "Toll Free" / "Helpline" / "Call now" near phone number
      if (/(?:toll\s*free|helpline|help\s*desk|call\s+(?:now|us|immediately|this\s+number))\s*:?\s*\+?1?[-.\s]?\(?\d{3}\)?/i.test(ctx.rawText))
        signals.push('toll-free/helpline label');

      // Phone number in page title
      if (/\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/.test(ctx.title))
        signals.push('phone in page title');

      // "Expert engineers/technicians" call language
      if (/(?:expert|certified|microsoft)\s+(?:engineer|technician|specialist|support\s+team)/i.test(ctx.rawText))
        signals.push('expert technician claims');

      // "Call within X minutes" time pressure
      if (/call\s+(?:us\s+)?(?:within|in)\s+(?:the\s+next\s+)?\d+\s+minutes?/i.test(ctx.rawText))
        signals.push('call-within-minutes pressure');

      // "Walk you through the removal process"
      if (/(?:walk|guide)\s+you\s+through\s+(?:the\s+)?(?:removal|fix|repair|clean)/i.test(ctx.rawText))
        signals.push('guided removal offer');

      if (signals.length >= 1) {
        return {
          description: `Scam phone pattern: ${signals.join(', ')}`,
          evidence: `Numbers found: ${phones.slice(0, 3).join(', ')} | ${signals.join(', ')}`,
          scoreBonus: signals.length >= 3 ? 15 : signals.length >= 2 ? 8 : 0,
        };
      }
      return null;
    }
  });
})();
