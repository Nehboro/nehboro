// Nehboro Detection: Notification Permission Spam (runtime-detected)
(function () {
  NW_register({
    id: 'NOTIFICATION_SPAM', name: 'Notification Permission Spam',
    description: 'Page calls Notification.requestPermission() repeatedly to harass user',
    defaultScore: 25, tags: ['social-engineering','scam'],
    detect() { return null; }
  });
})();
