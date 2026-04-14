(function () {
  const P = window.NW_PATTERNS, H = window.NW_HELPERS;
  if (!P || !H) return;
  NW_register({
    id: 'LLM_ARTIFACT_ABUSE', name: 'AI Artifact Abuse',
    description: 'AI artifact / shared chat link delivering malicious instructions',
    defaultScore: 32, tags: ['clickfix','social-engineering'],
    detect(ctx) {
      const hasOpen = H.testAny(P.CF_OPEN, ctx.rawText) || H.testAny(P.CF_OPEN, ctx.pageHTML);
      if (H.testAny(P.LLM_ARTIFACT, ctx.pageHTML) && hasOpen)
        return { description: 'AI artifact used to deliver malicious instructions', evidence: H.firstMatch(P.LLM_ARTIFACT, ctx.pageHTML) };
      return null;
    }
  });
})();
