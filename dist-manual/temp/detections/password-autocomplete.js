(function () {
  NW_register({
    id: 'PASSWORD_AUTOCOMPLETE', name: 'Password Field Autocomplete Abuse',
    description: 'Hidden or deceptive password fields designed to capture autofill data',
    defaultScore: 25, tags: ['phishing'],
    detect(ctx) {
      const pwdFields = document.querySelectorAll('input[type="password"]');
      for (const f of pwdFields) {
        const style = window.getComputedStyle(f);
        const isHidden = style.opacity === '0' || parseInt(style.height) < 2 || parseInt(style.width) < 2 || style.position === 'absolute' && (parseInt(style.left) < -100 || parseInt(style.top) < -100);
        if (isHidden) return { description: 'Hidden password field designed to capture autofill', evidence: `opacity:${style.opacity} size:${style.width}x${style.height}` };
      }
      return null;
    }
  });
})();
