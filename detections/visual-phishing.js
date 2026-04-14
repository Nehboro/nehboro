// ============================================================
// Nehboro Detection: Visual Phishing Analysis
// Inspired by Phinn (2017) - modernized without CNN dependency.
// Analyzes visual signals: favicon, brand colors, logo images,
// form structure, and page layout to detect brand impersonation.
// ============================================================

(function () {
  const H = window.NW_HELPERS;
  if (!H) return;

  // ── Known brand visual signatures ───────────────────────
  const BRAND_SIGNATURES = {
    google: {
      domains: ['google.com','gmail.com','accounts.google.com'],
      colors: ['#4285f4','#ea4335','#fbbc05','#34a853','#1a73e8'],
      faviconHints: ['google','gstatic','gmail'],
      logoHints: ['google','gmail','g-logo'],
      titleHints: ['sign in','google account','gmail'],
      formAction: ['accounts.google.com'],
    },
    microsoft: {
      domains: ['microsoft.com','login.microsoftonline.com','outlook.com','office.com','live.com'],
      colors: ['#0078d4','#00a4ef','#7fba00','#f25022','#ffb900','#737373'],
      faviconHints: ['microsoft','msft','outlook','office','live'],
      logoHints: ['microsoft','ms-logo','office','outlook','windows'],
      titleHints: ['sign in','microsoft','outlook','office 365'],
      formAction: ['login.microsoftonline.com','login.live.com'],
    },
    apple: {
      domains: ['apple.com','icloud.com','appleid.apple.com'],
      colors: ['#333333','#007aff','#000000'],
      faviconHints: ['apple','icloud'],
      logoHints: ['apple-logo','apple','icloud'],
      titleHints: ['apple id','sign in','icloud'],
      formAction: ['appleid.apple.com','icloud.com'],
    },
    facebook: {
      domains: ['facebook.com','fb.com','messenger.com','instagram.com','meta.com'],
      colors: ['#1877f2','#42b72a','#e4e6eb','#1b74e4'],
      faviconHints: ['facebook','fb','meta'],
      logoHints: ['facebook','fb-logo','meta'],
      titleHints: ['log in','facebook','sign up'],
      formAction: ['facebook.com','fb.com'],
    },
    paypal: {
      domains: ['paypal.com','paypal.me'],
      colors: ['#003087','#009cde','#012169','#0070ba'],
      faviconHints: ['paypal'],
      logoHints: ['paypal','pp-logo'],
      titleHints: ['log in','paypal','send money'],
      formAction: ['paypal.com'],
    },
    amazon: {
      domains: ['amazon.com','amazon.co.uk','amazon.de','amazon.fr','aws.amazon.com'],
      colors: ['#ff9900','#232f3e','#131921','#febd69'],
      faviconHints: ['amazon','aws'],
      logoHints: ['amazon','a-logo','aws'],
      titleHints: ['sign in','amazon','aws'],
      formAction: ['amazon.com','signin.aws.amazon.com'],
    },
    netflix: {
      domains: ['netflix.com'],
      colors: ['#e50914','#141414','#b9090b'],
      faviconHints: ['netflix','nflx'],
      logoHints: ['netflix','nf-logo'],
      titleHints: ['sign in','netflix','login'],
      formAction: ['netflix.com'],
    },
    github: {
      domains: ['github.com'],
      colors: ['#24292e','#0366d6','#2ea44f','#1b1f23'],
      faviconHints: ['github','octocat'],
      logoHints: ['github','octocat','invertocat'],
      titleHints: ['sign in','github','log in'],
      formAction: ['github.com'],
    },
    linkedin: {
      domains: ['linkedin.com'],
      colors: ['#0a66c2','#004182','#0077b5'],
      faviconHints: ['linkedin'],
      logoHints: ['linkedin','in-logo'],
      titleHints: ['sign in','linkedin','log in'],
      formAction: ['linkedin.com'],
    },
    discord: {
      domains: ['discord.com','discord.gg'],
      colors: ['#5865f2','#2c2f33','#23272a','#57f287','#fee75c'],
      faviconHints: ['discord'],
      logoHints: ['discord','clyde'],
      titleHints: ['login','discord','log in'],
      formAction: ['discord.com'],
    },
    twitter: {
      domains: ['twitter.com','x.com'],
      colors: ['#1da1f2','#14171a','#657786','#000000'],
      faviconHints: ['twitter','x.com','twimg'],
      logoHints: ['twitter','x-logo','bird'],
      titleHints: ['log in','twitter','x','sign in'],
      formAction: ['twitter.com','x.com'],
    },
    coinbase: {
      domains: ['coinbase.com'],
      colors: ['#0052ff','#1652f0','#050f19'],
      faviconHints: ['coinbase'],
      logoHints: ['coinbase'],
      titleHints: ['sign in','coinbase','log in'],
      formAction: ['coinbase.com'],
    },
    binance: {
      domains: ['binance.com'],
      colors: ['#f0b90b','#1e2329','#f3ba2f'],
      faviconHints: ['binance','bnb'],
      logoHints: ['binance','bnb'],
      titleHints: ['log in','binance','sign in'],
      formAction: ['binance.com'],
    },
  };

  // ── Helper: extract dominant colors from page ───────────
  function extractPageColors() {
    const colors = new Set();
    const elements = document.querySelectorAll('button, a, [class*="btn"], [class*="login"], [class*="sign"], header, nav, [class*="brand"], [class*="logo"]');
    for (const el of [...elements].slice(0, 30)) {
      try {
        const style = window.getComputedStyle(el);
        for (const prop of ['backgroundColor', 'color', 'borderColor']) {
          const val = style[prop];
          if (val && val !== 'rgba(0, 0, 0, 0)' && val !== 'transparent' && val !== 'rgb(0, 0, 0)' && val !== 'rgb(255, 255, 255)') {
            colors.add(val);
          }
        }
      } catch {}
    }
    return [...colors];
  }

  // ── Helper: rgb string to hex ───────────────────────────
  function rgbToHex(rgb) {
    const m = rgb.match(/\d+/g);
    if (!m || m.length < 3) return '';
    return '#' + [m[0],m[1],m[2]].map(x => parseInt(x).toString(16).padStart(2,'0')).join('');
  }

  // ── Helper: color distance (simple euclidean) ───────────
  function colorDistance(hex1, hex2) {
    const r1 = parseInt(hex1.slice(1,3),16), g1 = parseInt(hex1.slice(3,5),16), b1 = parseInt(hex1.slice(5,7),16);
    const r2 = parseInt(hex2.slice(1,3),16), g2 = parseInt(hex2.slice(3,5),16), b2 = parseInt(hex2.slice(5,7),16);
    return Math.sqrt((r1-r2)**2 + (g1-g2)**2 + (b1-b2)**2);
  }

  // ── Helper: check if page color matches brand palette ───
  function colorMatchScore(pageColors, brandColors) {
    let matches = 0;
    const pageHexes = pageColors.map(rgbToHex).filter(Boolean);
    for (const brandColor of brandColors) {
      for (const pageHex of pageHexes) {
        if (colorDistance(pageHex, brandColor) < 40) { matches++; break; }
      }
    }
    return matches;
  }

  // ── Main: Visual Brand Impersonation ────────────────────
  NW_register({
    id: 'VISUAL_BRAND_IMPERSONATION', name: 'Visual Brand Impersonation',
    description: 'Page visually mimics a known brand (colors, logos, favicon, form structure) but is on a non-official domain',
    defaultScore: 10, tags: ['phishing','visual'],
    detect(ctx) {
      // Only analyze pages with login forms
      if (!ctx.hasPwdField && ctx.inputCount < 2) return null;

      const hostname = ctx.hostname;
      const title = ctx.title.toLowerCase();
      const html = ctx.pageHTML.toLowerCase();

      for (const [brandName, sig] of Object.entries(BRAND_SIGNATURES)) {
        // Skip if we're on the legit domain
        if (sig.domains.some(d => hostname === d || hostname.endsWith('.' + d))) continue;

        let signals = 0;
        let evidence = [];

        // 1. Title matches brand
        const titleMatch = sig.titleHints.some(h => title.includes(h));
        if (titleMatch) { signals += 2; evidence.push('title:' + title.substring(0, 40)); }

        // 2. Favicon hints
        const favicons = document.querySelectorAll('link[rel*="icon"]');
        for (const fav of favicons) {
          const href = (fav.getAttribute('href') || '').toLowerCase();
          if (sig.faviconHints.some(h => href.includes(h))) {
            signals += 2; evidence.push('favicon:' + href.substring(0, 60)); break;
          }
        }

        // 3. Logo images
        const images = document.querySelectorAll('img[src], img[alt], svg[class], svg[aria-label]');
        for (const img of [...images].slice(0, 20)) {
          const src = (img.getAttribute('src') || '').toLowerCase();
          const alt = (img.getAttribute('alt') || '').toLowerCase();
          const cls = (img.getAttribute('class') || '').toLowerCase();
          if (sig.logoHints.some(h => src.includes(h) || alt.includes(h) || cls.includes(h))) {
            signals += 2; evidence.push('logo:' + (src || alt || cls).substring(0, 60)); break;
          }
        }

        // 4. Color palette matching
        const pageColors = extractPageColors();
        const colorMatches = colorMatchScore(pageColors, sig.colors);
        if (colorMatches >= 2) { signals += colorMatches; evidence.push('colors:' + colorMatches + ' brand colors matched'); }

        // 5. Form action pointing to official domain (overridden to phish)
        const forms = document.querySelectorAll('form[action]');
        for (const form of forms) {
          const action = (form.getAttribute('action') || '').toLowerCase();
          if (sig.formAction.some(d => action.includes(d))) {
            signals += 1; evidence.push('form-action-spoof:' + action.substring(0, 60));
          }
        }

        // 6. Brand name in body text with password field
        if (html.includes(brandName) && ctx.hasPwdField) {
          signals += 1; evidence.push('brand-text:' + brandName);
        }

        // Threshold: need 4+ signals for high confidence
        if (signals >= 4) {
          return {
            description: `Page visually impersonates ${brandName.charAt(0).toUpperCase() + brandName.slice(1)} (${signals} visual signals) on non-official domain ${hostname}`,
            evidence: evidence.join(' | '),
            scoreBonus: signals >= 6 ? 15 : signals >= 5 ? 8 : 0,
          };
        }
      }
      return null;
    }
  });

  // ── Favicon domain mismatch ─────────────────────────────
  NW_register({
    id: 'FAVICON_BRAND_MISMATCH', name: 'Favicon Brand Mismatch',
    description: 'Favicon loads from a known brand CDN but page is on a different domain',
    defaultScore: 20, tags: ['phishing','visual'],
    detect(ctx) {
      const brandCDNs = {
        'google': ['gstatic.com','google.com','googleapis.com'],
        'microsoft': ['microsoft.com','msftauth.net','aadcdn.msauth.net','msauth.net'],
        'facebook': ['fbcdn.net','facebook.com','fbstatic-a.akamaihd.net'],
        'apple': ['apple.com','mzstatic.com'],
        'github': ['github.com','githubassets.com'],
        'amazon': ['amazon.com','ssl-images-amazon.com','media-amazon.com'],
      };

      const favicons = document.querySelectorAll('link[rel*="icon"]');
      for (const fav of favicons) {
        const href = fav.getAttribute('href') || '';
        if (!href.startsWith('http')) continue;
        try {
          const favHost = new URL(href).hostname;
          for (const [brand, cdns] of Object.entries(brandCDNs)) {
            if (cdns.some(cdn => favHost === cdn || favHost.endsWith('.' + cdn))) {
              // Favicon is from brand CDN - check if page is on brand domain
              const brandDomains = BRAND_SIGNATURES[brand]?.domains || [];
              if (!brandDomains.some(d => ctx.hostname === d || ctx.hostname.endsWith('.' + d))) {
                return { description: `Favicon loaded from ${brand} CDN (${favHost}) but page is on ${ctx.hostname}`, evidence: href.substring(0, 120) };
              }
            }
          }
        } catch {}
      }
      return null;
    }
  });

  // ── Login form visual fingerprint ───────────────────────
  NW_register({
    id: 'LOGIN_FORM_VISUAL', name: 'Suspicious Login Form Layout',
    description: 'Login form uses centered single-column layout typical of brand phishing pages',
    defaultScore: 8, tags: ['phishing','visual','heuristic'],
    detect(ctx) {
      if (!ctx.hasPwdField) return null;

      const forms = document.querySelectorAll('form');
      for (const form of forms) {
        const pwd = form.querySelector('input[type="password"]');
        if (!pwd) continue;

        // Check if form is centered, narrow, single-column (typical phishing layout)
        const rect = form.getBoundingClientRect();
        const vpWidth = window.innerWidth;
        const formWidth = rect.width;
        const centered = Math.abs((rect.left + rect.right) / 2 - vpWidth / 2) < vpWidth * 0.15;
        const narrow = formWidth < vpWidth * 0.5 && formWidth > 200;

        // Count visible inputs
        const inputs = form.querySelectorAll('input:not([type="hidden"]):not([type="submit"])');
        const fewInputs = inputs.length >= 1 && inputs.length <= 4;

        // Has submit button
        const hasSubmit = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');

        // Social login buttons (sign in with Google/Facebook/etc.)
        const socialLogin = /sign\s*in\s*with|log\s*in\s*with|continue\s*with/i.test(form.textContent);

        if (centered && narrow && fewInputs && hasSubmit) {
          const signals = [];
          if (centered) signals.push('centered');
          if (narrow) signals.push(`narrow(${Math.round(formWidth)}px)`);
          if (fewInputs) signals.push(`${inputs.length} inputs`);
          if (socialLogin) signals.push('social-login-buttons');
          return { description: `Login form matches phishing layout: ${signals.join(', ')}`, evidence: `Form: ${Math.round(rect.width)}x${Math.round(rect.height)} at (${Math.round(rect.left)},${Math.round(rect.top)})`, scoreBonus: socialLogin ? 6 : 0 };
        }
      }
      return null;
    }
  });

  // ── Screenshot-like resource loading from brand ─────────
  NW_register({
    id: 'BRAND_ASSET_THEFT', name: 'Brand Asset Loading',
    description: 'Page loads images/CSS/fonts directly from a brand CDN it does not belong to',
    defaultScore: 10, tags: ['phishing','visual'],
    detect(ctx) {
      const brandAssets = {
        'google': ['fonts.googleapis.com','accounts.google.com/favicon','gstatic.com/images'],
        'microsoft': ['aadcdn.msauth.net','logincdn.msauth.net','microsoft.com/favicon'],
        'apple': ['appleid.cdn-apple.com','iforgot.apple.com'],
        'facebook': ['static.xx.fbcdn.net','facebook.com/favicon'],
      };

      const resources = document.querySelectorAll('img[src], link[href], script[src]');
      const found = {};
      for (const el of resources) {
        const src = (el.getAttribute('src') || el.getAttribute('href') || '').toLowerCase();
        for (const [brand, patterns] of Object.entries(brandAssets)) {
          if (patterns.some(p => src.includes(p))) {
            const brandDomains = BRAND_SIGNATURES[brand]?.domains || [];
            if (!brandDomains.some(d => ctx.hostname === d || ctx.hostname.endsWith('.' + d))) {
              found[brand] = (found[brand] || 0) + 1;
            }
          }
        }
      }

      const topBrand = Object.entries(found).sort((a,b) => b[1] - a[1])[0];
      if (topBrand && topBrand[1] >= 2) {
        return { description: `${topBrand[1]} assets loaded from ${topBrand[0]} CDN on non-official domain`, evidence: `Brand: ${topBrand[0]}, assets: ${topBrand[1]}`, scoreBonus: topBrand[1] >= 4 ? 10 : 0 };
      }
      return null;
    }
  });

})();
