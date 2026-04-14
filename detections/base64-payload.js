(function () {
  NW_register({
    id: 'BASE64_PAYLOAD', name: 'Large Base64 Payload',
    description: 'Suspicious large base64-encoded string in page (possible encoded payload)',
    defaultScore: 15, tags: ['malware','evasion'],
    detect(ctx) {
      const b64 = ctx.pageHTML.match(/[A-Za-z0-9+/=]{200,}/g);
      if (!b64) return null;
      const suspicious = b64.filter(s => s.length > 200);
      if (suspicious.length >= 1) {
        const hasContext = /powershell|encodedcommand|frombase64|atob|decode/i.test(ctx.pageHTML);
        if (hasContext) return { description: `${suspicious.length} large base64 string(s) with decode context`, evidence: `Longest: ${suspicious[0].length} chars`, scoreBonus: 10 };
        if (suspicious[0].length > 500) return { description: `Large base64 string (${suspicious[0].length} chars)`, evidence: suspicious[0].substring(0, 60) + '...' };
      }
      return null;
    }
  });
})();
