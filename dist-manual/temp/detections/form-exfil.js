(function () {
  NW_register({
    id: 'FORM_EXTERNAL_ACTION', name: 'Form Posts to External Domain',
    description: 'Login/credential form posts data to a different domain',
    defaultScore: 25, tags: ['phishing'],
    detect(ctx) {
      const forms = document.querySelectorAll('form[action]');
      for (const form of forms) {
        const hasCreds = form.querySelector('input[type="password"], input[type="email"], input[name*="user"], input[name*="login"]');
        if (!hasCreds) continue;
        try {
          const actionHost = new URL(form.action, ctx.url).hostname;
          if (actionHost && actionHost !== ctx.hostname && actionHost !== 'localhost')
            return { description: `Credential form posts to external domain: ${actionHost}`, evidence: `Form action: ${form.action.substring(0, 100)}` };
        } catch {}
      }
      return null;
    }
  });

  NW_register({
    id: 'CREDENTIAL_EXFIL_FETCH', name: 'Credential Exfil via Fetch/XHR',
    description: 'Page source sends form data to external endpoint via fetch/XMLHttpRequest',
    defaultScore: 22, tags: ['phishing','malware'],
    detect(ctx) {
      const fetchToExternal = /fetch\s*\(\s*['"]https?:\/\/(?!(?:.*(?:google|facebook|microsoft|apple|cloudflare)\.com))/i.test(ctx.pageHTML);
      const sendsPassword   = /(?:password|passwd|pwd|pass)\b/i.test(ctx.pageHTML) && ctx.hasPwdField;
      if (fetchToExternal && sendsPassword)
        return { description: 'Page may exfiltrate credentials via fetch/XHR', evidence: 'fetch() to external domain + password field references' };
      return null;
    }
  });
})();
