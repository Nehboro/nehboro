// Nehboro Detection: Multilingual ClickFix Instructions
// Catches ClickFix command execution instructions in non-English languages
(function () {
  NW_register({
    id: 'CLICKFIX_MULTILANG', name: 'Multilingual ClickFix Instructions',
    description: 'ClickFix-style "copy + paste + run" instructions in Spanish, Portuguese, French, German, or Italian',
    defaultScore: 40, tags: ['clickfix','social-engineering','critical'],
    detect(ctx) {
      const signals = [];

      // ── Spanish ─────────────────────────────────────────
      const es = [
        /copiar?\s+(?:la\s+)?soluci[oó]n/i,                     // "Copiar solución" (Image 1)
        /haga\s+clic\s+(?:derecho\s+)?en\s+(?:el\s+)?icono\s+de\s+windows/i, // "Haga clic derecho en el icono de Windows"
        /seleccione\s+['"]?windows\s+powershell/i,               // "Seleccione Windows PowerShell"
        /ventana\s+del\s+terminal/i,                              // "ventana del terminal"
        /siga\s+(?:estas?\s+)?instrucciones/i,                    // "Siga estas instrucciones"
        /copiar?\s+(?:y\s+)?pegar?\s+(?:el\s+)?(?:comando|código)/i, // "copiar y pegar el comando"
        /(?:ejecutar?|abrir?)\s+(?:el\s+)?(?:terminal|powershell|cmd)/i,
        /algo\s+sali[oó]\s+mal\s+al\s+mostrar/i,                 // "Algo salió mal al mostrar" (Image 1)
        /resolver\s+(?:el\s+)?problema/i,
      ];

      // ── Portuguese ──────────────────────────────────────
      const pt = [
        /copiar?\s+(?:a\s+)?solu[cç][aã]o/i,
        /clique\s+(?:com\s+o\s+bot[aã]o\s+)?direito\s+no\s+[ií]cone\s+do\s+windows/i,
        /selecione\s+['"]?windows\s+powershell/i,
        /janela\s+do\s+terminal/i,
        /siga\s+(?:estas?\s+)?instru[cç][oõ]es/i,
        /copiar?\s+e\s+colar?\s+o\s+comando/i,
        /algo\s+deu\s+errado/i,
        /para\s+provar\s+que\s+n[aã]o\s+[eé]\s+um\s+rob[oô]/i,   // "Para provar que não é um robô" (Image 2)
        /passos?\s+de\s+verifica[cç][aã]o/i,                      // "Passos de verificação"
        /pressione\s+(?:e\s+mantenha\s+)?(?:pressionada?\s+)?(?:a\s+tecla\s+)?windows/i, // "Pressione e mantenha pressionada a tecla Windows"
        /janela\s+de\s+verifica[cç][aã]o/i,                       // "Na janela de verificação"
        /verifique\s+que\s+[eé]\s+humano/i,                       // "Verifique que é humano"
        /verifica[cç][aã]o\s+da\s+cloudflare/i,                   // "Verificação da Cloudflare"
        /pressione\s+enter\s+no\s+seu\s+teclado/i,                // "Pressione Enter no seu teclado"
        /siga\s+os\s+passos\s+acima/i,                            // "Siga os passos acima"
      ];

      // ── French ──────────────────────────────────────────
      const fr = [
        /copier?\s+(?:la\s+)?solution/i,
        /cliquez?\s+(?:droit\s+)?sur\s+(?:l[''])?ic[oô]ne\s+(?:de\s+)?windows/i,
        /s[eé]lectionnez?\s+['"]?windows\s+powershell/i,
        /fen[eê]tre\s+du\s+terminal/i,
        /suivez?\s+(?:ces?\s+)?instructions/i,
        /copier?\s+(?:et\s+)?coller?\s+(?:la?\s+)?commande/i,
        /une?\s+erreur\s+(?:s'est\s+produite|est\s+survenue)/i,
      ];

      // ── German ──────────────────────────────────────────
      const de = [
        /(?:l[oö]sung\s+)?kopieren/i,
        /rechtsklick\s+auf\s+(?:das\s+)?windows[-\s]?(?:symbol|icon)/i,
        /w[aä]hlen\s+sie\s+['"]?windows\s+powershell/i,
        /terminal[-\s]?fenster/i,
        /(?:folgen|befolgen)\s+sie\s+(?:diese[nr]?\s+)?(?:anweisungen|schritte)/i,
        /(?:befehl|code)\s+kopieren\s+und\s+einf[uü]gen/i,
        /(?:etwas\s+ist\s+)?schiefgelaufen/i,
      ];

      // ── Italian ─────────────────────────────────────────
      const it = [
        /copia(?:re)?\s+(?:la\s+)?soluzione/i,
        /(?:clic(?:ca)?|fare\s+clic)\s+(?:destro\s+)?(?:sull[''])?icona\s+(?:di\s+)?windows/i,
        /seleziona(?:re)?\s+['"]?windows\s+powershell/i,
        /finestra\s+del\s+terminale/i,
        /segui(?:re)?\s+(?:queste?\s+)?istruzioni/i,
        /copiare?\s+(?:e\s+)?incollare?\s+(?:il\s+)?comando/i,
      ];

      let totalHits = 0;
      for (const pats of [es, pt, fr, de, it]) {
        for (const p of pats) {
          const m = ctx.rawText.match(p);
          if (m) { totalHits++; if (signals.length < 4) signals.push(m[0].substring(0, 50)); }
        }
      }

      if (totalHits >= 2) {
        return {
          description: `${totalHits} multilingual ClickFix instruction signals`,
          evidence: signals.join(' | '),
          scoreBonus: totalHits >= 4 ? 15 : totalHits >= 3 ? 8 : 0,
        };
      }
      return null;
    }
  });
})();
