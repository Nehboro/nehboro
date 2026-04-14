// Nehboro Detection: IP/Geolocation Scare Display
// Catches pages that display the user's IP address, location, and ISP to intimidate
(function () {
  NW_register({
    id: 'IP_GEOLOCATION_SCARE', name: 'IP/Location Scare Display',
    description: 'Page displays user IP address, location, or ISP alongside security warnings to intimidate',
    defaultScore: 22, tags: ['social-engineering','tech-support-scam'],
    detect(ctx) {
      const signals = [];

      // IP address displayed in page (not in code/scripts - in visible text)
      const ipInText = /(?:IP|adresse?\s+IP|your\s+IP|votre\s+IP)\s*:?\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(ctx.rawText);
      if (ipInText) signals.push('IP address displayed');

      // ISP name displayed
      if (/(?:ISP|fournisseur|provider)\s*:\s*\w+/i.test(ctx.rawText) && ipInText)
        signals.push('ISP displayed');

      // Location/city displayed alongside IP
      if (/(?:location|emplacement|ville|city|pays|country)\s*:\s*\w+/i.test(ctx.rawText) && ipInText)
        signals.push('location displayed');

      // Timestamp displayed with IP (scare: "we know when you visited")
      if (/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\s*,?\s*\d{1,2}:\d{2}/i.test(ctx.rawText) && ipInText)
        signals.push('timestamp + IP');

      // "Your IP has been logged/tracked/reported"
      if (/(?:your\s+)?IP\s+(?:has\s+been\s+|address\s+)?(?:logged|tracked|reported|recorded|flagged)/i.test(ctx.rawText))
        signals.push('IP tracking threat');

      if (signals.length >= 1) {
        // Much higher score if combined with phone number or threat language
        const hasThreat = /(?:blocked|locked|infected|compromised|bloqué|sécurité|sicherheit)/i.test(ctx.rawText);
        return {
          description: `IP/geolocation scare: ${signals.join(', ')}`,
          evidence: signals.join(' | '),
          scoreBonus: hasThreat ? 12 : 0,
        };
      }
      return null;
    }
  });
})();
