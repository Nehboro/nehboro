// Nehboro Detection: Enhanced Credit Card Skimmer
// Detects JS skimmers targeting payment card autocomplete fields
// Inspired by Malwarebytes Browser Guard skimmer protection
(function () {
  NW_register({
    id: 'CARD_SKIMMER_ENHANCED', name: 'Credit Card Skimmer (Enhanced)',
    description: 'JavaScript intercepting credit card autocomplete fields or exfiltrating payment data',
    defaultScore: 40, tags: ['malware','critical'],
    detect(ctx) {
      const signals = [];

      // Credit card autocomplete field names (HTML5 standard)
      const ccAutoComplete = ['cc-name','cc-number','cc-csc','cc-exp-month','cc-exp-year','cc-exp','cc-type'];
      const ccFields = document.querySelectorAll('input[autocomplete]');
      let ccFieldCount = 0;
      for (const field of ccFields) {
        if (ccAutoComplete.includes(field.getAttribute('autocomplete'))) ccFieldCount++;
      }

      // Also check for common payment input names
      const paymentInputs = document.querySelectorAll(
        'input[name*="card"], input[name*="cc_"], input[name*="cvv"], input[name*="cvc"], ' +
        'input[name*="expir"], input[id*="card"], input[id*="cvv"], input[id*="cvc"]'
      );
      const hasPaymentFields = ccFieldCount >= 2 || paymentInputs.length >= 3;

      if (!hasPaymentFields) return null;

      // Check for skimmer patterns in scripts
      const skimmerPats = [
        // addEventListener on payment fields that sends data externally
        /addEventListener\s*\(\s*['"](?:input|change|blur|keyup|keydown|submit)['"][\s\S]{0,500}(?:fetch|XMLHttpRequest|navigator\.sendBeacon|new\s+Image)/i,
        // Collecting input values and encoding
        /(?:btoa|atob|encodeURI|JSON\.stringify)\s*\([^)]*(?:card|cvv|cvc|ccnum|cc_number|expir)/i,
        // Sending to external endpoint via image pixel
        /new\s+Image\s*\(\s*\)\.src\s*=.*(?:card|cc|cvv|payment)/i,
        // Fetch/XHR to suspicious external domain
        /fetch\s*\(\s*['"]https?:\/\/(?!(?:.*(?:stripe|paypal|braintree|adyen|square|checkout)\.com))[^'"]+['"][\s\S]{0,300}(?:card|payment|cc|cvv)/i,
        // Dynamic script injection targeting payment
        /createElement\s*\(\s*['"]script['"]\s*\)[\s\S]{0,200}(?:card|payment|checkout|cc)/i,
        // MutationObserver on payment forms
        /MutationObserver[\s\S]{0,300}(?:payment|card|cc-|checkout)/i,
      ];

      for (const p of skimmerPats) {
        if (p.test(ctx.pageHTML)) {
          signals.push('skimmer code pattern');
          break;
        }
      }

      // Check for data exfiltration to non-payment domains
      const suspiciousExfil = /(?:fetch|XMLHttpRequest|sendBeacon|Image)\s*\([^)]*(?:collect|track|log|grab|steal|siphon|exfil)/i;
      if (suspiciousExfil.test(ctx.pageHTML)) signals.push('suspicious data collection');

      // External scripts on payment pages from non-standard domains
      const scripts = document.querySelectorAll('script[src]');
      let suspiciousScriptCount = 0;
      const trustedPayment = ['stripe.com','js.stripe.com','paypal.com','braintreegateway.com','adyen.com','checkout.com','square.com','recurly.com'];
      for (const s of scripts) {
        try {
          const h = new URL(s.src).hostname;
          if (h !== ctx.hostname && !trustedPayment.some(t => h === t || h.endsWith('.' + t))) {
            suspiciousScriptCount++;
          }
        } catch {}
      }
      if (suspiciousScriptCount >= 5) signals.push(`${suspiciousScriptCount} untrusted scripts on payment page`);

      if (signals.length >= 1) {
        return {
          description: `Card skimmer signals on payment page: ${signals.join(', ')}`,
          evidence: `${ccFieldCount} CC autocomplete fields, ${paymentInputs.length} payment inputs | ${signals.join(', ')}`,
          scoreBonus: signals.length >= 2 ? 15 : 0,
        };
      }

      return null;
    }
  });
})();
