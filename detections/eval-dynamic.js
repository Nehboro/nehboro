(function () {
  NW_register({
    id: 'EVAL_DYNAMIC', name: 'Dynamic Code Execution',
    description: 'eval() or Function() with dynamic/obfuscated content',
    defaultScore: 15, tags: ['malware','evasion'],
    detect(ctx) {
      const evalPats = [/eval\s*\(\s*(?:atob|unescape|decodeURI|String\.fromCharCode)/gi, /new\s+Function\s*\(\s*(?:atob|unescape)/gi, /eval\s*\(\s*[\w.]+\s*\(\s*['"][A-Za-z0-9+/=]{50,}/gi];
      for (const p of evalPats) {
        const m = ctx.pageHTML.match(p);
        if (m) return { description: 'Dynamic code execution with encoding/obfuscation', evidence: m[0].substring(0, 100) };
      }
      return null;
    }
  });
})();
