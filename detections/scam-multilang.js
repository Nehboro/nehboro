// Nehboro Detection: Multilingual Tech Support Scams
// Catches scam patterns in French, Spanish, German, Italian, Portuguese
(function () {
  NW_register({
    id: 'SCAM_MULTILANG', name: 'Multilingual Scam Patterns',
    description: 'Tech support scam text in non-English languages (French, Spanish, German, etc.)',
    defaultScore: 30, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      const signals = [];
      const text = ctx.rawText;

      // ── French ──────────────────────────────────────────
      const fr = [
        /(?:accès|acces)\s+(?:à\s+)?(?:ce|cet|votre)\s+(?:PC|ordinateur|système|systeme)\s+(?:a\s+été|est)\s+(?:bloqué|bloqu[ée]|verrouill[ée])/i,
        /(?:appel(?:er|ez)|contact(?:er|ez))\s+(?:l[''])?assistance\s+(?:Windows|Microsoft|Apple|Google)/i,
        /(?:avertissement|alerte)\s+(?:de\s+)?(?:sécurité|securite)/i,
        /(?:centre|service)\s+de\s+(?:sécurité|securite)\s+(?:Windows|Apple)\s+Defender/i,
        /(?:ne\s+pas\s+(?:fermer|ignorer)|en\s+fermant\s+cette\s+(?:fenêtre|fenetre))/i,
        /(?:informations?\s+personnelles?\s+en\s+danger|perte\s+de\s+données|donnees)/i,
        /(?:identifiants?\s+de\s+messagerie|mots?\s+de\s+passe\s+bancaires?|identifiant\s+Facebook)/i,
        /(?:numéro|numero)\s+(?:de\s+)?(?:sécurité|securite)\s+gratuit/i,
        /(?:raisons?\s+de\s+sécurité|securite)/i,
        // More common French scam variants
        /(?:votre|son)\s+(?:ordinateur|système|systeme|PC|appareil)\s+(?:est|a\s+été)\s+(?:bloqué|bloqu[ée]|infect[ée]|compromis|verrouill[ée])/i,
        /(?:appelez|contactez)\s+(?:immédiatement|immediatement|maintenant|d['']urgence)/i,
        /(?:supports?|assistance)\s+technique\s+(?:Microsoft|Apple|Google|Windows)/i,
        /(?:ne\s+fermez|n[e']?\s*éteignez)\s+pas\s+(?:cette|votre)/i,
        /(?:vos|tes)\s+(?:données|donnees|informations)\s+personnelles?\s+(?:sont|seront)\s+(?:en\s+danger|exposées|volées)/i,
        /(?:votre|sa)\s+(?:licence|abonnement|certificat)\s+(?:Windows|Microsoft|Office)\s+(?:a\s+)?expir[ée]/i,
        /Windows\s+Defender\s+a\s+(?:détecté|trouvé|identifié)/i,
        /(?:cliquez\s+ici\s+pour\s+(?:renouveler|réparer|nettoyer|continuer))/i,
        /menace\s+(?:critique|grave|urgente|détectée)/i,
        /virus\s+(?:détectés?|trouvés?|identifiés?)/i,
      ];

      // ── Spanish ─────────────────────────────────────────
      const es = [
        /(?:acceso|su\s+(?:PC|computadora|ordenador))\s+(?:ha\s+sido|está|fue)\s+(?:bloqueado|infectado)/i,
        /llam(?:ar|e)\s+(?:al?\s+)?(?:soporte|asistencia)\s+(?:de\s+)?(?:Windows|Microsoft|Apple)/i,
        /(?:alerta|advertencia)\s+de\s+seguridad/i,
        /(?:no\s+cierre|no\s+ignore)\s+esta\s+(?:ventana|página|pagina)/i,
        /(?:información|informacion)\s+personal\s+en\s+(?:peligro|riesgo)/i,
      ];

      // ── German ──────────────────────────────────────────
      const de = [
        /(?:Ihr\s+)?(?:Computer|PC|Zugang)\s+(?:wurde|ist)\s+(?:gesperrt|blockiert|infiziert)/i,
        /(?:rufen\s+Sie|kontaktieren\s+Sie)\s+(?:den\s+)?(?:Windows|Microsoft|Apple)[-\s]?Support/i,
        /Sicherheits(?:warnung|hinweis|alarm)/i,
        /(?:schließen|ignorieren)\s+Sie\s+(?:dieses?\s+)?(?:Fenster|Seite)\s+nicht/i,
      ];

      // ── Italian ─────────────────────────────────────────
      const it = [
        /(?:accesso|computer|PC)\s+(?:è\s+stato|viene)\s+(?:bloccato|infettato)/i,
        /(?:chiamare|contattare)\s+(?:il\s+)?(?:supporto|assistenza)\s+(?:Windows|Microsoft|Apple)/i,
        /(?:avviso|allerta)\s+di\s+sicurezza/i,
      ];

      // ── Fake product names (any language) ───────────────
      const fakeProducts = [
        /Apple\s+Defender/i,           // doesn't exist
        /Google\s+Defender/i,          // doesn't exist
        /Windows\s+Security\s+Essentials?\s+(?:was|has|a)/i, // deprecated/misused
        /Centre\s+de\s+sécurité\s+Apple/i,
        /Microsoft\s+Security\s+(?:Alert|Warning|Centre|Center)\s+(?:has|was|a)/i,
      ];

      let langHits = 0;
      for (const p of [...fr, ...es, ...de, ...it]) {
        if (p.test(text)) { langHits++; if (langHits <= 3) signals.push((text.match(p) || [''])[0].substring(0, 60)); }
      }

      let fakeHits = 0;
      for (const p of fakeProducts) {
        if (p.test(text)) { fakeHits++; signals.push('fake product: ' + ((text.match(p) || [''])[0]).substring(0, 40)); }
      }

      if (langHits >= 2 || (langHits >= 1 && fakeHits >= 1)) {
        return {
          description: `${langHits} multilingual scam signals + ${fakeHits} fake product names`,
          evidence: signals.slice(0, 4).join(' | '),
          scoreBonus: langHits >= 4 ? 15 : langHits >= 3 ? 8 : 0,
        };
      }

      // Fake product name alone is still suspicious
      if (fakeHits >= 1) {
        return {
          description: `Fake security product name detected`,
          evidence: signals.join(' | '),
          scoreOverride: 20,
        };
      }

      return null;
    }
  });
})();
