(function () {
  NW_register({
    id: 'PUNYCODE_DOMAIN', name: 'Punycode/IDN Domain',
    description: 'Domain uses Punycode (xn--) internationalized encoding, common in homograph attacks',
    defaultScore: 20, tags: ['phishing'],
    detect(ctx) {
      if (/xn--/.test(ctx.hostname))
        return { description: `Punycode domain detected: ${ctx.hostname}`, evidence: ctx.hostname, scoreBonus: ctx.hasPwdField ? 15 : 0 };
      return null;
    }
  });
})();
