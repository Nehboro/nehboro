// Nehboro Detection: ClickFix Pretexts
// Catches the fake excuses used to trick users into running Win+R/Ctrl+V/Enter
// These are the "cover stories" - driver issues, missing fonts, microphone access, BSOD, etc.
(function () {
  NW_register({
    id: 'CLICKFIX_PRETEXT', name: 'ClickFix Pretext / Cover Story',
    description: 'Fake excuse used to trick users into running commands (missing fonts, driver updates, mic access, BSOD)',
    defaultScore: 30, tags: ['clickfix','social-engineering','critical'],
    detect(ctx) {
      const signals = [];

      const pretexts = [
        // ── Driver update pretexts (Image 1) ──────────────
        /(?:audio|video|display|graphics|network|sound)\s+driver(?:s)?\s+(?:are\s+)?(?:outdated|missing|corrupted|need(?:s?\s+(?:to\s+be\s+)?)?update)/i,
        /please\s+update\s+(?:by\s+)?(?:pressing|following)/i,
        /driver\s+(?:update|updater|fix)\s+\d/i,  // "Audio Driver Updater 4.7X"

        // ── Missing font pretexts (Image 3) ───────────────
        /(?:missing|required)\s+font(?:\s+resource)?/i,
        /font\s+(?:resource\s+)?(?:is\s+)?(?:missing|not\s+found|corrupted|damaged)/i,
        /missing\s+or\s+(?:damaged|corrupted)\s+fonts?\s+(?:can\s+)?(?:cause|prevent)/i,

        // ── Fake BSOD pretexts (Image 3) ──────────────────
        /your\s+pc\s+ran\s+into\s+a\s+problem/i,
        /recovery\s+instructions?\s+(?:below\s+)?to\s+(?:protect|save|recover)\s+your\s+data/i,
        /(?:recovery|repair)\s+(?:command|instructions?)\s+(?:has\s+been\s+)?copied\s+to\s+(?:your\s+)?clipboard/i,

        // ── Microphone/camera/hardware access pretexts (Images 1, 5) ──
        /(?:browser|system)\s+is\s+blocking\s+access\s+to\s+(?:microphone|camera|audio|webcam)/i,
        /microphone\s+(?:access\s+)?issues?/i,
        /(?:allow|grant|enable)\s+(?:microphone|camera|audio)\s+access/i,
        /(?:microphone|camera)\s+(?:identifiers?|devices?)\s+(?:not\s+)?(?:found|detected|available)/i,
        /follow\s+(?:the\s+)?actions?\s+below\s+to\s+(?:allow|enable|grant)\s+access/i,

        // ── Verification/security pretexts (Image 6) ──────
        /additional\s+verification\s+required/i,
        /(?:press|click)\s+.*?\s+to\s+(?:open\s+the\s+)?run\s+dialog/i,
        /(?:paste|press\s+ctrl\s*\+\s*v)\s+(?:to\s+)?(?:paste\s+)?the\s+command/i,
        /(?:click|press)\s+(?:ok|enter)\s+to\s+continue/i,

        // ── Fake shared file pretexts ──────────────────────
        /we\s+have\s+shared\s+(?:the\s+)?(?:an?\s+)?\S+\.(?:pdf|doc|xlsx?|pptx?)\s+file/i,
        /(?:incident|report|invoice|document|policy|contract|agreement)[-_]\w*\.(?:pdf|docx?|xlsx?)/i,
        /made\s+["']?\S+\.(?:pdf|docx?|xlsx?)["']?\s+available\s+to\s+you/i,  // "made HRPolicy.docx available to you"
        /to\s+access\s+\S+\.(?:pdf|docx?|xlsx?)\s*,?\s*follow/i,             // "To access HRPolicy.docx, follow"
        /C:\\(?:Users\\(?:Default|Public)\\Documents?|company|internal|shared|filedrive)\\/i, // C:\company\internal-secure\...
        /copy\s+the\s+file\s+path\s+below/i,                                  // "Copy the file path below"
        /open\s+file\s+explorer\s+and\s+(?:select|click)\s+the\s+address\s+bar/i,
        /paste\s+the\s+file\s+path\s+(?:and\s+)?(?:press|into)/i,            // "Paste the file path and press Enter"

        // ── Portuguese CAPTCHA pretexts (Image 2) ─────────
        /para\s+provar\s+que\s+n[aã]o\s+[eé]\s+um\s+rob[oô]/i,
        /passos?\s+de\s+verifica[cç][aã]o/i,
        /pressione\s+(?:e\s+mantenha\s+pressionada?\s+)?(?:a\s+tecla\s+)?windows/i,
        /janela\s+de\s+verifica[cç][aã]o/i,
        /verifica[cç][aã]o\s+da\s+cloudflare/i,
        /verifique\s+que\s+[eé]\s+humano/i,
      ];

      const hasClickFix = /(?:win(?:dows)?\s*(?:key\s*)?\+\s*[rx]|ctrl\s*\+\s*v|press\s+enter|powershell|terminal|run\s+dialog)/i.test(ctx.rawText);

      for (const p of pretexts) {
        const m = ctx.rawText.match(p);
        if (m) { signals.push(m[0].substring(0, 60)); }
      }

      if (signals.length >= 1 && hasClickFix) {
        return {
          description: `ClickFix pretext with execution instructions: ${signals[0]}`,
          evidence: signals.slice(0, 3).join(' | '),
          scoreBonus: signals.length >= 2 ? 10 : 0,
        };
      }

      // Even without ClickFix combo, multiple pretexts are suspicious
      if (signals.length >= 2) {
        return {
          description: `Multiple ClickFix pretext signals: ${signals.length}`,
          evidence: signals.slice(0, 3).join(' | '),
          scoreOverride: 20, // lower score without ClickFix instructions
        };
      }

      return null;
    }
  });
})();
