// Nehboro Detection: Combination Bonuses
// These fire when multiple detections combine into a known attack pattern
(function () {
  // These detections inspect the findings array from other detections
  // They use a special _postProcess flag so the orchestrator runs them last
  NW_register({
    id: 'BONUS_CLIPBOARD_INSTRUCTION', name: 'Combo: Clipboard + Instructions',
    description: 'Clipboard write combined with execution instructions - classic ClickFix',
    defaultScore: 15, tags: ['combo','critical'], _postProcess: true,
    detect(ctx, allFindings) {
      const cats = new Set(allFindings.map(f => f.category));
      if ((cats.has('CLICKFIX_FULL_SEQUENCE') || cats.has('CLICKFIX_PARTIAL')) && (cats.has('CLIPBOARD_SOURCE') || cats.has('CLIPBOARD_HIJACK')))
        return { description: 'Clipboard write + execution instructions - classic ClickFix', evidence: '' };
      return null;
    }
  });

  NW_register({
    id: 'BONUS_LOLBIN_INSTRUCTION', name: 'Combo: LOLBin + Instructions',
    description: 'LOLBin reference combined with execution instructions',
    defaultScore: 12, tags: ['combo'], _postProcess: true,
    detect(ctx, allFindings) {
      const cats = new Set(allFindings.map(f => f.category));
      if ((cats.has('CLICKFIX_FULL_SEQUENCE') || cats.has('CLICKFIX_PARTIAL')) && cats.has('LOLBIN_IN_CONTEXT') && !cats.has('CLIPBOARD_SOURCE') && !cats.has('CLIPBOARD_HIJACK'))
        return { description: 'LOLBin + execution instructions', evidence: '' };
      return null;
    }
  });

  NW_register({
    id: 'BONUS_CAPTCHA_INSTRUCTION', name: 'Combo: Fake CAPTCHA + Instructions',
    description: 'Fake CAPTCHA/Cloudflare lure combined with execution instructions',
    defaultScore: 15, tags: ['combo','critical'], _postProcess: true,
    detect(ctx, allFindings) {
      const cats = new Set(allFindings.map(f => f.category));
      if ((cats.has('CLICKFIX_FULL_SEQUENCE') || cats.has('CLICKFIX_PARTIAL')) && (cats.has('FAKE_CLOUDFLARE_TEXT') || cats.has('FAKE_CLOUDFLARE_DOMAIN')))
        return { description: 'Fake CAPTCHA lure + execution instructions', evidence: '' };
      return null;
    }
  });

  NW_register({
    id: 'BONUS_PS_CLIPBOARD', name: 'Combo: PowerShell + Clipboard',
    description: 'Clipboard hijack combined with encoded PowerShell - definitive ClickFix',
    defaultScore: 20, tags: ['combo','critical'], _postProcess: true,
    detect(ctx, allFindings) {
      const cats = new Set(allFindings.map(f => f.category));
      if ((cats.has('CLIPBOARD_SOURCE') || cats.has('CLIPBOARD_HIJACK')) && cats.has('POWERSHELL_ENCODED'))
        return { description: 'Clipboard hijack + encoded PowerShell - definitive ClickFix', evidence: '' };
      return null;
    }
  });

  NW_register({
    id: 'BONUS_CRYPTO_LOOKALIKE', name: 'Combo: Crypto + Lookalike',
    description: 'Crypto wallet phishing on a lookalike domain',
    defaultScore: 20, tags: ['combo','critical'], _postProcess: true,
    detect(ctx, allFindings) {
      const cats = new Set(allFindings.map(f => f.category));
      if (cats.has('CRYPTO_WALLET_PHISHING') && (cats.has('LOOKALIKE_HOMOGRAPH') || cats.has('LOOKALIKE_TYPOSQUAT')))
        return { description: 'Crypto wallet phishing on lookalike domain', evidence: '' };
      return null;
    }
  });

  NW_register({
    id: 'BONUS_SCAM_FULLKIT', name: 'Combo: Full Scam Kit',
    description: 'Multiple social engineering signals combined (urgency + fake error + phone + dialogs)',
    defaultScore: 25, tags: ['combo','critical'], _postProcess: true,
    detect(ctx, allFindings) {
      const cats = new Set(allFindings.map(f => f.category));
      const scamSignals = [
        'URGENCY','FAKE_ERROR_PAGE','FAKE_ERROR_CODE','TECH_SUPPORT_SCAM',
        'FAKE_ANTIVIRUS','FAKE_COUNTDOWN','DATA_THEFT_SCARE','DIALOG_SPAM',
        'SCAM_PHONE_PROMINENT','FAKE_OS_UI','BROWSER_LOCK',
        'FAKE_URL_BAR','IP_GEOLOCATION_SCARE','SCAM_MULTILANG','RAW_IP_HOSTING',
        'PRINT_LOOP','NOTIFICATION_SPAM','HISTORY_LOOP','URL_CREATE_LOOP',
        'FULLSCREEN_SPAM','SCAM_AUDIO'
      ].filter(c => cats.has(c)).length;
      if (scamSignals >= 3)
        return { description: `Full scam kit: ${scamSignals} social engineering signals combined`, evidence: [...cats].filter(c => c.includes('FAKE') || c.includes('SCAM') || c.includes('SCARE') || c === 'URGENCY' || c === 'DIALOG_SPAM').join(', ') };
      return null;
    }
  });

  NW_register({
    id: 'BONUS_VISUAL_PHISH', name: 'Combo: Visual Impersonation + Login',
    description: 'Visual brand impersonation combined with credential harvesting or lookalike domain',
    defaultScore: 20, tags: ['combo','critical'], _postProcess: true,
    detect(ctx, allFindings) {
      const cats = new Set(allFindings.map(f => f.category));
      const hasVisual = cats.has('VISUAL_BRAND_IMPERSONATION') || cats.has('FAVICON_BRAND_MISMATCH') || cats.has('BRAND_ASSET_THEFT');
      const hasPhish = cats.has('PHISHING_IMPERSONATION') || cats.has('LOOKALIKE_HOMOGRAPH') || cats.has('LOOKALIKE_TYPOSQUAT') || cats.has('FORM_EXTERNAL_ACTION');
      if (hasVisual && hasPhish)
        return { description: 'Visual brand impersonation + credential harvesting signals', evidence: '' };
      return null;
    }
  });
})();
