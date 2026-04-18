// Nehboro Detection: Lookalike / Typosquat Domains
(function () {
  const H = window.NW_HELPERS;
  if (!H) return;

  const BRANDS = {
    'google':['google.com','gmail.com','accounts.google.com'],'microsoft':['microsoft.com','login.microsoftonline.com','outlook.com','office.com','live.com'],
    'apple':['apple.com','icloud.com','appleid.apple.com'],'amazon':['amazon.com','amazon.co.uk','amazon.de','amazon.fr','aws.amazon.com'],
    'paypal':['paypal.com','paypal.me'],'facebook':['facebook.com','fb.com','messenger.com'],'instagram':['instagram.com'],
    'twitter':['twitter.com','x.com'],'netflix':['netflix.com'],'linkedin':['linkedin.com'],'dropbox':['dropbox.com'],
    'chase':['chase.com'],'wellsfargo':['wellsfargo.com'],'bankofamerica':['bankofamerica.com','bofa.com'],
    'coinbase':['coinbase.com'],'binance':['binance.com'],'metamask':['metamask.io'],'discord':['discord.com','discord.gg'],
    'steam':['steampowered.com','steamcommunity.com'],'whatsapp':['whatsapp.com','web.whatsapp.com'],
    'telegram':['telegram.org','web.telegram.org'],'yahoo':['yahoo.com','mail.yahoo.com'],
    'dhl':['dhl.com'],'fedex':['fedex.com'],'ups':['ups.com'],'usps':['usps.com'],'stripe':['stripe.com'],
  };

  const HOMOGLYPHS = {
    'a':['@','4','à','á','â','ã','ä','å','ɑ','а'],'b':['d','6','ь','б'],'c':['(','ç','с','ϲ'],'d':['b','cl'],
    'e':['3','è','é','ê','ë','е','ё'],'g':['9','q','ɡ'],'h':['ħ','н'],'i':['1','l','!','|','í','ì','î','ï','і'],
    'k':['κ','к'],'l':['1','i','|','ℓ'],'m':['rn','nn'],'n':['m','ñ','п'],'o':['0','ø','ö','ò','ó','ô','õ','о','ο'],
    'p':['р','ρ'],'r':['ŗ','г'],'s':['5','$','ş','ѕ'],'t':['7','+','т'],'u':['v','ü','ù','ú','û','µ','υ'],
    'v':['u','ν'],'w':['vv','ω','ш'],'x':['×','х'],'y':['ý','ÿ','у'],'z':['2','ž'],
  };

  function normalize(str) {
    let r = str.toLowerCase();
    for (const [base, alts] of Object.entries(HOMOGLYPHS)) for (const a of alts) r = r.split(a).join(base);
    return r.replace(/[-_.]/g, '');
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (!m) return n; if (!n) return m;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
      dp[i][j] = Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+(a[i-1]!==b[j-1]?1:0));
    return dp[m][n];
  }

  function getDomainBase(hostname) {
    const bare = hostname.replace(/^www\./, '');
    const parts = bare.split('.');
    if (parts.length >= 3 && ['co','com','org','net','gov'].includes(parts[parts.length-2])) return parts.slice(-3).join('.').split('.')[0];
    if (parts.length >= 2) return parts.slice(-2).join('.').split('.')[0];
    return null;
  }

  NW_register({
    id: 'LOOKALIKE_HOMOGRAPH', name: 'Homograph Domain Attack',
    description: 'Domain uses character substitution to impersonate a brand (e.g. goog1e.com)',
    defaultScore: 40, tags: ['phishing','critical'],
    detect(ctx) {
      const base = getDomainBase(ctx.hostname);
      if (!base) return null;
      const norm = normalize(base);
      for (const [brand, legit] of Object.entries(BRANDS)) {
        if (legit.some(d => ctx.hostname === d || ctx.hostname.endsWith('.'+d))) continue;
        if (norm === brand) return { description: `Domain "${ctx.hostname}" uses character substitution to mimic "${brand}"`, evidence: `Normalized: ${norm} → ${brand}` };
      }
      return null;
    }
  });

  NW_register({
    id: 'LOOKALIKE_TYPOSQUAT', name: 'Typosquat Domain',
    description: 'Domain is 1-2 characters away from a major brand (e.g. gogle.com)',
    defaultScore: 35, tags: ['phishing'],
    detect(ctx) {
      const base = getDomainBase(ctx.hostname);
      if (!base) return null;
      const norm = normalize(base);
      for (const [brand, legit] of Object.entries(BRANDS)) {
        if (legit.some(d => ctx.hostname === d || ctx.hostname.endsWith('.'+d))) continue;
        const dist = levenshtein(norm, brand);
        if (dist === 1 && brand.length >= 4) return { description: `Domain "${ctx.hostname}" is 1 char from "${brand}"`, evidence: `Edit distance: ${dist}` };
        if (dist === 2 && brand.length >= 6) return { description: `Domain "${ctx.hostname}" is close to "${brand}"`, evidence: `Edit distance: ${dist}`, scoreOverride: 15 };
      }
      return null;
    }
  });

  NW_register({
    id: 'LOOKALIKE_BRAND_SUBSTRING', name: 'Brand Name in Domain',
    description: 'Domain contains a brand name but is not the official site',
    defaultScore: 10, tags: ['phishing'],
    detect(ctx) {
      const base = getDomainBase(ctx.hostname);
      if (!base) return null;
      for (const [brand, legit] of Object.entries(BRANDS)) {
        if (legit.some(d => ctx.hostname === d || ctx.hostname.endsWith('.'+d))) continue;
        if (base.includes(brand) && base !== brand && brand.length >= 5)
          return { description: `Domain contains "${brand}" but is not official`, evidence: `${ctx.hostname} (legit: ${legit[0]})`, scoreBonus: ctx.hasPwdField ? 15 : 0 };
      }
      return null;
    }
  });
})();
