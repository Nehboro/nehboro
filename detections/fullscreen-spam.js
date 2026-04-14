// Nehboro Detection: Fullscreen Request Spam (runtime-detected)
(function () {
  NW_register({
    id: 'FULLSCREEN_SPAM', name: 'Fullscreen Request Spam',
    description: 'Page calls requestFullscreen() in a loop to lock user in fullscreen mode',
    defaultScore: 30, tags: ['social-engineering','tech-support-scam'],
    detect() { return null; }
  });
})();
