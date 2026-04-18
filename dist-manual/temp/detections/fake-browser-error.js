// Nehboro Detection: Fake Browser Error
// Catches pages that impersonate browser update/error messages (Opera, Chrome, Edge, Firefox)
(function () {
  NW_register({
    id: 'FAKE_BROWSER_ERROR', name: 'Fake Browser Update/Error',
    description: 'Page impersonates a browser error or update prompt (Chrome, Opera, Edge, Firefox, Safari)',
    defaultScore: 35, tags: ['clickfix','social-engineering','critical'],
    detect(ctx) {
      const signals = [];

      // Browser names in error context (not from the actual browser UI)
      const browserErrorPats = [
        // English
        /(?:google\s+)?chrome\s+(?:update|error|problem|issue|needs?\s+(?:to\s+be\s+)?update)/i,
        /(?:microsoft\s+)?edge\s+(?:update|error|problem|issue|needs?\s+(?:to\s+be\s+)?update)/i,
        /opera\s+(?:update|error|problem|issue|needs?\s+(?:to\s+be\s+)?update)/i,
        /(?:mozilla\s+)?firefox\s+(?:update|error|problem|issue|needs?\s+(?:to\s+be\s+)?update)/i,
        /safari\s+(?:update|error|problem|issue|needs?\s+(?:to\s+be\s+)?update)/i,
        /brave\s+(?:update|error|problem|issue|needs?\s+(?:to\s+be\s+)?update)/i,
        // "Something went wrong while displaying this web page" (Image 1 in multiple languages)
        /something\s+went\s+wrong\s+(?:while\s+)?(?:displaying|loading|rendering)/i,
        /(?:algo\s+sali[oó]\s+mal|quelque\s+chose\s+s'est\s+mal\s+pass[eé]|etwas\s+ist\s+schiefgelaufen|qualcosa\s+[eè]\s+andato\s+storto)/i,
        // Browser version/update errors
        /(?:error|problem)\s+(?:during|with)\s+(?:the\s+)?(?:latest|last|recent)\s+(?:update|version)/i,
        /(?:error|erreur|fehler|error|errore)\s+(?:durante|pendant|bei|durante)\s+(?:la\s+)?(?:[uú]ltima|derni[eè]re|letzten?|ultima)\s+(?:actualizaci[oó]n|mise\s+[aà]\s+jour|aktualisierung|aggiornamento)/i,
        // "caused malfunction of some web pages"
        /(?:caused?|provocó|provoqué|verursacht)\s+(?:the\s+)?(?:malfunction|mal\s+funcionamiento|dysfonctionnement|fehlfunktion)/i,
      ];

      for (const p of browserErrorPats) {
        const m = ctx.rawText.match(p);
        if (m) { signals.push(m[0].substring(0, 60)); }
      }

      // Browser logos/icons displayed on non-browser domains
      // Check for browser brand images
      if (/(?:opera|chrome|firefox|edge|safari|brave)[-_]?(?:logo|icon|brand)/i.test(ctx.pageHTML)) {
        const isOfficialBrowser = /(?:opera\.com|google\.com|mozilla\.org|microsoft\.com|apple\.com|brave\.com)/i.test(ctx.hostname);
        if (!isOfficialBrowser) signals.push('browser logo on non-official domain');
      }

      // "Follow these instructions to fix/resolve the problem"
      if (/(?:follow|siga|suivez|folgen|segui)\s+(?:these|estas|ces|diese|queste)\s+(?:instructions|instrucciones|instructions|anweisungen|istruzioni)/i.test(ctx.rawText))
        signals.push('fix instructions');

      // "Copy solution/fix" button
      if (/(?:copy\s+(?:solution|fix)|copiar?\s+(?:la\s+)?soluci[oó]n|copier?\s+(?:la\s+)?solution|l[oö]sung\s+kopieren|copia(?:re)?\s+(?:la\s+)?soluzione)/i.test(ctx.rawText))
        signals.push('copy solution button');

      if (signals.length >= 2) {
        return {
          description: `Fake browser error: ${signals.join(', ')}`,
          evidence: signals.slice(0, 4).join(' | '),
          scoreBonus: signals.length >= 3 ? 10 : 0,
        };
      }
      return null;
    }
  });
})();
