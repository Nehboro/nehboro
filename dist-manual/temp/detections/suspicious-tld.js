(function () {
  NW_register({
    id: 'SUSPICIOUS_TLD', name: 'High-Risk TLD',
    description: 'Domain uses a TLD frequently associated with phishing/scam sites',
    defaultScore: 8, tags: ['phishing','heuristic'],
    detect(ctx) {
      const riskyTLDs = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.buzz','.rest','.surf','.monster','.click','.link','.support','.help','.sbs','.icu'];
      const tld = '.' + ctx.hostname.split('.').pop();
      if (riskyTLDs.includes(tld) && (ctx.hasPwdField || ctx.formCount > 0))
        return { description: `High-risk TLD "${tld}" with input forms`, evidence: ctx.hostname };
      return null;
    }
  });
})();
