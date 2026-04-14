// Nehboro Detection: Scam Audio / Alarm Sounds
// Catches autoplay audio elements used by tech support scam pages
(function () {
  NW_register({
    id: 'SCAM_AUDIO', name: 'Scam Alarm Audio',
    description: 'Page autoplays alarm, warning, or alert audio to frighten users',
    defaultScore: 20, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      const signals = [];

      // Audio elements with autoplay
      const audioEls = document.querySelectorAll('audio[autoplay], audio[src], video[autoplay]');
      for (const el of audioEls) {
        const src = (el.getAttribute('src') || '').toLowerCase();
        const autoplay = el.hasAttribute('autoplay');
        const loop = el.hasAttribute('loop');

        // Check for alarm/warning audio filenames
        if (/(?:alarm|warning|alert|siren|beep|error|danger|emergency|notification)/i.test(src)) {
          signals.push('alarm audio: ' + src.substring(0, 60));
        }
        // Autoplay + loop = aggressive
        if (autoplay && loop) signals.push('autoplay+loop audio');
        // Autoplay audio on non-media site
        if (autoplay && !/(youtube|spotify|soundcloud|bandcamp|music|radio|podcast)/i.test(ctx.hostname))
          signals.push('autoplay on non-media site');
      }

      // Source elements inside audio/video
      const sources = document.querySelectorAll('audio source, video source');
      for (const s of sources) {
        const src = (s.getAttribute('src') || '').toLowerCase();
        if (/(?:alarm|warning|alert|siren|beep|error|danger)/i.test(src))
          signals.push('alarm source: ' + src.substring(0, 60));
      }

      // JavaScript Audio() constructor with suspicious names
      if (/new\s+Audio\s*\(\s*['"][^'"]*(?:alarm|warning|alert|siren|beep|error|danger)[^'"]*['"]\s*\)/i.test(ctx.pageHTML))
        signals.push('JS Audio() with alarm sound');

      // .play() called on audio with suspicious nearby text
      if (/\.play\s*\(\s*\)/i.test(ctx.pageHTML)) {
        const hasScamContext = /(?:virus|infected|blocked|error|support|call|phone)/i.test(ctx.rawText);
        if (hasScamContext) signals.push('audio.play() in scam context');
      }

      if (signals.length >= 1) {
        return {
          description: `Scam audio: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: signals.length >= 2 ? 10 : 0,
        };
      }
      return null;
    }
  });
})();
