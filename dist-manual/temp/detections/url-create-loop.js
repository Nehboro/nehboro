// Nehboro Detection: createObjectURL Loop (runtime-detected)
(function () {
  NW_register({
    id: 'URL_CREATE_LOOP', name: 'createObjectURL Loop',
    description: 'Page creates blob URLs in rapid succession to exhaust browser resources',
    defaultScore: 30, tags: ['malware','tech-support-scam'],
    detect() { return null; }
  });
})();
