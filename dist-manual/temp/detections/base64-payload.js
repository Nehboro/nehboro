// Nehboro Detection: Base64 Payload (Enhanced)
// Validates that strings are actually base64 and checks decoded content for threats
(function () {
  NW_register({
    id: 'BASE64_PAYLOAD', name: 'Large Base64 Payload',
    description: 'Verified base64-encoded string in page with suspicious decoded content',
    defaultScore: 15, tags: ['malware','evasion'],
    detect(ctx) {
      // Match potential base64 strings (min 100 chars, must end with optional padding)
      const candidates = ctx.pageHTML.match(/[A-Za-z0-9+/]{100,}={0,2}/g);
      if (!candidates) return null;

      const findings = [];

      for (const raw of candidates) {
        // Skip data URIs for images/fonts/media (legitimate base64)
        const pos = ctx.pageHTML.indexOf(raw);
        const before = ctx.pageHTML.substring(Math.max(0, pos - 60), pos);
        if (/data:(?:image|font|audio|video|application\/(?:pdf|font|octet))/.test(before)) continue;

        // Validate it's actually base64:
        // 1. Must contain mixed case + digits (not just hex or just alpha)
        if (!/[A-Z]/.test(raw) || !/[a-z]/.test(raw) || !/[0-9]/.test(raw)) continue;
        // 2. Must not look like a long CSS class, hash, or URL path
        if (/^[a-f0-9]+$/i.test(raw)) continue; // pure hex
        // 3. Try to decode
        const padded = raw + '='.repeat((4 - raw.length % 4) % 4);
        let decoded = '';
        try {
          decoded = atob(padded);
        } catch {
          continue; // Not valid base64
        }
        if (!decoded || decoded.length < 20) continue;

        // Check decoded content for suspicious patterns
        const signals = [];

        // PowerShell / command execution
        if (/powershell|cmd\.exe|mshta|wscript|cscript|invoke-|downloadstring|webclient|iex\s*\(/i.test(decoded))
          signals.push('PowerShell/cmd in decoded');

        // URLs in decoded content (download stages)
        if (/https?:\/\/[^\s'"]{10,}/i.test(decoded))
          signals.push('URL in decoded');

        // PE header / MZ executable / ZIP
        if (decoded.startsWith('MZ') || decoded.startsWith('PK') || decoded.charCodeAt(0) === 0x4D && decoded.charCodeAt(1) === 0x5A)
          signals.push('executable header (MZ/PK)');

        // Script injection in decoded
        if (/<script|eval\s*\(|document\.write|\.innerHTML\s*=/i.test(decoded))
          signals.push('script injection in decoded');

        // Shell commands
        if (/\/bin\/(?:ba)?sh|curl\s|wget\s|chmod\s|osascript/i.test(decoded))
          signals.push('shell command in decoded');

        // Executable file references
        if (/\.(?:exe|dll|ps1|bat|vbs|hta|scr|cmd|msi)\b/i.test(decoded))
          signals.push('executable extension in decoded');

        // Windows paths
        if (/C:\\|%TEMP%|%APPDATA%|\\Windows\\|\\System32\\/i.test(decoded))
          signals.push('Windows path in decoded');

        // High binary content (non-printable chars = shellcode/binary payload)
        let nonPrintable = 0;
        const checkLen = Math.min(decoded.length, 500);
        for (let i = 0; i < checkLen; i++) {
          const c = decoded.charCodeAt(i);
          if (c < 32 && c !== 10 && c !== 13 && c !== 9) nonPrintable++;
        }
        if (nonPrintable / checkLen > 0.3 && decoded.length > 500)
          signals.push('high binary content');

        if (signals.length > 0) {
          findings.push({ len: raw.length, signals });
        }
      }

      if (findings.length === 0) {
        // Fallback: large base64 near decode keywords (weaker, lower score)
        const large = candidates.filter(s => s.length > 500);
        if (large.length > 0 && /frombase64|encodedcommand|atob\s*\(|base64.*decode/i.test(ctx.pageHTML)) {
          return {
            description: large.length + ' large base64 string(s) near decode context',
            evidence: 'Longest: ' + large[0].length + ' chars',
            scoreOverride: 8,
          };
        }
        return null;
      }

      const best = findings.sort((a, b) => b.signals.length - a.signals.length)[0];
      return {
        description: 'Verified base64 payload: ' + best.signals.join(', '),
        evidence: best.len + ' chars | ' + best.signals.join(', '),
        scoreBonus: best.signals.length >= 2 ? 15 : 5,
      };
    }
  });
})();
