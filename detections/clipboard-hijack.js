// Nehboro Detection: Runtime Clipboard Hijack (event-driven)
// NOTE: The actual clipboard interception is in content/runtime-interceptor.js (MAIN world)
// which runs at document_start. This detection processes intercepted events.
(function () {
  const H = window.NW_HELPERS;
  if (!H) return;
  NW_register({
    id: 'CLIPBOARD_HIJACK', name: 'Clipboard Hijack (Runtime)',
    description: 'Page attempted to write suspicious content to clipboard at runtime',
    defaultScore: 40, tags: ['clickfix','malware','critical'],
    // This detection is event-driven - the runtime-interceptor fires __NW_FINDING__ events
    // The orchestrator handles those events separately; this registration is for metadata/scoring only.
    detect() { return null; }
  });
})();
