(function () {
  NW_register({
    id: 'IFRAME_INJECTION', name: 'Hidden Iframe Injection',
    description: 'Dynamically injected hidden iframe pointing to external domain',
    defaultScore: 18, tags: ['malware','phishing'],
    detect(ctx) {
      if (/createElement\s*\(\s*['"]iframe['"]\)[\s\S]{0,200}(?:display\s*[:=]\s*['"]?none|visibility\s*[:=]\s*['"]?hidden|width\s*[:=]\s*['"]?0|height\s*[:=]\s*['"]?0)/i.test(ctx.pageHTML))
        return { description: 'Dynamically created hidden iframe detected', evidence: 'createElement("iframe") + hidden styling' };
      return null;
    }
  });
})();
