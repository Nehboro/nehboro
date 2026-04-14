(function () {
  NW_register({
    id: 'TECH_SUPPORT_SCAM', name: 'Tech Support Scam',
    description: 'Tech support scam page with phone number and urgency',
    defaultScore: 40, tags: ['social-engineering','scam','critical'],
    detect(ctx) {
      const hasPhone = /(?:call|phone|dial|contact)\s*:?\s*\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/i.test(ctx.rawText);
      const hasUrgency = /(?:immediately|right\s+away|urgent|do\s+not\s+ignore|act\s+now)/i.test(ctx.rawText);
      const hasThreat = /(?:locked|blocked|hacked|compromised|unauthorized|suspicious\s+activity)/i.test(ctx.rawText);
      const hasBrand = /(?:microsoft|windows|apple|google|amazon)\s+(?:support|help|security|defender|tech)/i.test(ctx.rawText);
      if (hasPhone && hasUrgency && (hasThreat || hasBrand))
        return { description: 'Tech support scam pattern detected', evidence: `Phone: ${hasPhone}, Urgency: ${hasUrgency}, Threat: ${hasThreat}, Brand: ${hasBrand}` };
      return null;
    }
  });
})();
