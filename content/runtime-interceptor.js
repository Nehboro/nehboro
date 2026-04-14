// ============================================================
// Nehboro - content/runtime-interceptor.js
// MAIN world runtime API interception.
// Monitors: clipboard writes, print() spam, history.pushState
// loops, Notification.requestPermission spam, createObjectURL
// loops, and auth dialog loops.
// Fires __NW_FINDING__ events consumed by detector.js.
// ============================================================
(function () {
  'use strict';

  if (location.href.startsWith('chrome-extension://') || location.href.startsWith('moz-extension://')) return;
  if (window.__nehboro_interceptor_loaded) return;
  window.__nehboro_interceptor_loaded = true;

  // ── Helpers ─────────────────────────────────────────────
  // Use postMessage to communicate across MAIN → ISOLATED world boundary
  function fire(category, description, evidence, score, critical) {
    window.postMessage({
      __nehboro: true,
      type: '__NW_FINDING__',
      detail: { category, description, evidence: (evidence || '').substring(0, 300), score, critical: !!critical }
    }, '*');
  }

  // Rate limiter: returns true when threshold exceeded
  function makeRateLimiter(windowMs, maxCalls) {
    const calls = [];
    return function () {
      const now = Date.now();
      calls.push(now);
      // Remove old entries
      while (calls.length > 0 && calls[0] < now - windowMs) calls.shift();
      return calls.length >= maxCalls;
    };
  }

  const SUSPICIOUS_CMD = /powershell|mshta|wscript|cscript|certutil|bitsadmin|curl\s.*\|.*sh|osascript|nslookup|finger\.exe|regsvr32|rundll32|cmd\s*\/c|EncodedCommand|DownloadString|Invoke-|WebClient|WinHttp|XMLHTTP/i;

  // ── 1. Clipboard write interception ─────────────────────
  const origWriteText = navigator.clipboard?.writeText?.bind(navigator.clipboard);
  if (navigator.clipboard && origWriteText) {
    navigator.clipboard.writeText = function (text) {
      if (typeof text === 'string' && SUSPICIOUS_CMD.test(text)) {
        fire('CLIPBOARD_HIJACK', 'Clipboard hijack: suspicious command written at runtime', text, 40, true);
      }
      return origWriteText(text);
    };
  }

  const origExecCommand = document.execCommand?.bind(document);
  if (origExecCommand) {
    document.execCommand = function (cmd, ...args) {
      if (cmd === 'copy') {
        const sel = window.getSelection()?.toString() || '';
        if (SUSPICIOUS_CMD.test(sel)) {
          fire('CLIPBOARD_HIJACK', 'Clipboard hijack via execCommand copy', sel, 40, true);
        }
      }
      return origExecCommand(cmd, ...args);
    };
  }

  // ── 2. Print loop detection ─────────────────────────────
  let printFired = false;
  const printLimiter = makeRateLimiter(10000, 3); // 3 calls in 10s = loop
  const origPrint = window.print?.bind(window);
  if (origPrint) {
    window.print = function () {
      if (printLimiter() && !printFired) {
        printFired = true;
        fire('PRINT_LOOP', 'Print dialog spam detected - page calling window.print() in a loop', 'print() called 3+ times in 10s', 35, true);
        throw new Error('Nehboro: Breaking print loop');
      }
      return origPrint();
    };
  }

  // ── 3. History pushState/replaceState loop ──────────────
  let historyFired = false;
  const historyLimiter = makeRateLimiter(1000, 500); // 500 calls in 1s = loop

  const origPushState = history.pushState?.bind(history);
  if (origPushState) {
    history.pushState = function (...args) {
      if (historyLimiter() && !historyFired) {
        historyFired = true;
        fire('HISTORY_LOOP', 'History pushState spam detected - browser lock attempt', 'pushState() called 500+ times in 1s', 30, true);
        throw new Error('Nehboro: Breaking history loop');
      }
      return origPushState(...args);
    };
  }

  // Delay replaceState interception to avoid breaking SPA routers during initial load
  setTimeout(() => {
    const origReplaceState = history.replaceState?.bind(history);
    if (origReplaceState) {
      const replaceLimiter = makeRateLimiter(1000, 500);
      history.replaceState = function (...args) {
        if (replaceLimiter() && !historyFired) {
          historyFired = true;
          fire('HISTORY_LOOP', 'History replaceState spam detected - browser lock attempt', 'replaceState() called 500+ times in 1s', 30, true);
          throw new Error('Nehboro: Breaking history loop');
        }
        return origReplaceState(...args);
      };
    }
  }, 2000);

  // ── 4. Notification.requestPermission spam ──────────────
  let notifFired = false;
  if (window.Notification) {
    const notifLimiter = makeRateLimiter(5000, 2); // 2 calls in 5s = spam
    const origRequestPermission = Notification.requestPermission?.bind(Notification);
    if (origRequestPermission) {
      Notification.requestPermission = function (...args) {
        if (notifLimiter() && !notifFired) {
          notifFired = true;
          fire('NOTIFICATION_SPAM', 'Notification permission spam detected', 'requestPermission() called repeatedly', 25, true);
        }
        return origRequestPermission(...args);
      };
    }
  }

  // ── 5. createObjectURL loop ─────────────────────────────
  let urlLoopFired = false;
  const urlLimiter = makeRateLimiter(1000, 500); // 500 in 1s = abuse
  const origCreateURL = URL.createObjectURL?.bind(URL);
  if (origCreateURL) {
    URL.createObjectURL = function (...args) {
      if (urlLimiter() && !urlLoopFired) {
        urlLoopFired = true;
        fire('URL_CREATE_LOOP', 'createObjectURL loop detected - browser resource exhaustion', 'createObjectURL() called 500+ times in 1s', 30, true);
        throw new Error('Nehboro: Breaking createObjectURL loop');
      }
      return origCreateURL(...args);
    };
  }

  // ── 6. Fullscreen request spam ──────────────────────────
  let fullscreenFired = false;
  const fscLimiter = makeRateLimiter(3000, 3); // 3 in 3s = spam
  const origRequestFS = Element.prototype.requestFullscreen;
  if (origRequestFS) {
    Element.prototype.requestFullscreen = function (...args) {
      if (fscLimiter() && !fullscreenFired) {
        fullscreenFired = true;
        fire('FULLSCREEN_SPAM', 'Fullscreen request spam detected - browser lock attempt', 'requestFullscreen() called 3+ times in 3s', 30, true);
        throw new Error('Nehboro: Breaking fullscreen loop');
      }
      return origRequestFS.apply(this, args);
    };
  }

})();
