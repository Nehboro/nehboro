(function () {
  NW_register({
    id: 'KEYLOGGER_PATTERN', name: 'Keylogger Pattern',
    description: 'Page captures keystrokes and sends them to external endpoint',
    defaultScore: 35, tags: ['malware','phishing','critical'],
    detect(ctx) {
      const capturesKeys = /addEventListener\s*\(\s*['"]key(?:down|press|up)['"]/gi.test(ctx.pageHTML);
      const sendsData = /(?:fetch|XMLHttpRequest|navigator\.sendBeacon|new\s+Image)\s*\(/i.test(ctx.pageHTML);
      const storesKeys = /(?:keylog|keystroke|pressed|keyBuffer|keyData|captured)/i.test(ctx.pageHTML);
      if (capturesKeys && sendsData && storesKeys)
        return { description: 'Keylogger pattern: captures keystrokes and sends externally', evidence: 'keydown/keypress listener + data exfil + key storage' };
      return null;
    }
  });
})();
