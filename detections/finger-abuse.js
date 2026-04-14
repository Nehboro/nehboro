(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'FINGER_ABUSE', name: 'finger.exe Abuse / CrashFix',
    description: 'finger.exe abuse or CrashFix browser-crash recovery lure',
    defaultScore: 35, tags: ['malware','clickfix'],
    detect(ctx) {
      if (H.testAny(P.FINGER_ABUSE, ctx.rawText) || H.testAny(P.FINGER_ABUSE, ctx.pageHTML))
        return { description: 'finger.exe abuse or CrashFix lure', evidence: H.firstMatch(P.FINGER_ABUSE, ctx.rawText + ctx.pageHTML) };
      return null;
    }
  });
})();
