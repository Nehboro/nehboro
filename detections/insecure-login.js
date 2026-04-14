// Nehboro Detection: Insecure Login Form
// Catches login forms that submit credentials over HTTP (not HTTPS)
(function () {
  NW_register({
    id: 'INSECURE_LOGIN', name: 'Insecure Login Form (HTTP)',
    description: 'Login form submits credentials over unencrypted HTTP connection',
    defaultScore: 25, tags: ['phishing','critical'],
    detect(ctx) {
      // Only flag on HTTP pages or forms posting to HTTP
      const isHTTP = ctx.url.startsWith('http://');
      const forms = document.querySelectorAll('form');

      for (const form of forms) {
        const hasCreds = form.querySelector('input[type="password"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="pass"]');
        if (!hasCreds) continue;

        const action = form.getAttribute('action') || '';
        let actionIsHTTP = false;

        if (action) {
          try {
            const actionUrl = new URL(action, ctx.url);
            actionIsHTTP = actionUrl.protocol === 'http:';
          } catch {}
        } else {
          // No action = submits to current page
          actionIsHTTP = isHTTP;
        }

        if (isHTTP || actionIsHTTP) {
          return {
            description: `Login form submits credentials over HTTP${actionIsHTTP && action ? ' to ' + action.substring(0, 60) : ''}`,
            evidence: `Protocol: ${isHTTP ? 'HTTP page' : 'HTTPS page'} → ${actionIsHTTP ? 'HTTP form action' : 'same'}`,
            scoreBonus: isHTTP && actionIsHTTP ? 10 : 0,
          };
        }
      }
      return null;
    }
  });
})();
