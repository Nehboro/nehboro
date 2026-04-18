// Nehboro Detection: Dialog Spam / Alert Loops
// Catches pages that spam alert/confirm dialogs to trap users
(function () {
  NW_register({
    id: 'DIALOG_SPAM', name: 'Alert Dialog Spam',
    description: 'Page uses alert/confirm/prompt loops or recursive dialogs to trap users',
    defaultScore: 25, tags: ['social-engineering','tech-support-scam','scam'],
    detect(ctx) {
      const signals = [];

      // alert() in a loop or called repeatedly
      const alertCount = (ctx.pageHTML.match(/\balert\s*\(/gi) || []).length;
      if (alertCount >= 3) signals.push(`${alertCount}x alert() calls`);

      // confirm() used for trapping
      if (/confirm\s*\([^)]*(?:virus|infected|blocked|locked|call|support|error)/i.test(ctx.pageHTML))
        signals.push('confirm() with scare text');

      // Recursive/loop dialog patterns
      if (/(?:while\s*\(\s*true|while\s*\(\s*1|for\s*\(;;\))\s*\{[^}]*(?:alert|confirm|prompt)/i.test(ctx.pageHTML))
        signals.push('infinite dialog loop');

      // setTimeout/setInterval calling alert
      if (/(?:setTimeout|setInterval)\s*\([^)]*(?:alert|confirm)\s*\(/i.test(ctx.pageHTML))
        signals.push('timed dialog trigger');

      // "Prevent this page from creating additional dialogues" - text visible when Chrome shows dialog spam
      if (/prevent\s+this\s+page\s+from\s+creating\s+additional\s+dialog/i.test(ctx.rawText))
        signals.push('dialog spam detected by browser');

      // onbeforeunload with alert
      if (/onbeforeunload[\s\S]{0,100}(?:alert|confirm)\s*\(/i.test(ctx.pageHTML))
        signals.push('beforeunload dialog trap');

      if (signals.length >= 1) {
        return {
          description: `Dialog spam: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: signals.length >= 3 ? 15 : signals.length >= 2 ? 8 : 0,
        };
      }
      return null;
    }
  });
})();
