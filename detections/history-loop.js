// Nehboro Detection: History pushState/replaceState Loop (runtime-detected)
(function () {
  NW_register({
    id: 'HISTORY_LOOP', name: 'History API Loop',
    description: 'Page spams history.pushState/replaceState to prevent back navigation (browser lock)',
    defaultScore: 30, tags: ['social-engineering','tech-support-scam'],
    detect() { return null; }
  });
})();
