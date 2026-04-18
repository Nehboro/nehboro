// Nehboro Detection: Print Loop (runtime-detected)
// The actual interception is in runtime-interceptor.js (MAIN world)
// This registration provides metadata/scoring for the popup
(function () {
  NW_register({
    id: 'PRINT_LOOP', name: 'Print Dialog Spam',
    description: 'Page calls window.print() in a loop to freeze the browser (browser lock technique)',
    defaultScore: 35, tags: ['social-engineering','tech-support-scam','critical'],
    detect() { return null; } // Event-driven from runtime-interceptor.js
  });
})();
