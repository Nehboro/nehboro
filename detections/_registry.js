// ============================================================
// Nehboro - detections/_registry.js
// Central registry for all detection modules.
// Each detection file calls NW_register() to add itself.
// ============================================================

(function () {
  'use strict';

  // Guard: don't reset if already initialized (re-injection safety)
  if (window.NW_DETECTIONS && window.NW_DETECTIONS.length > 0 && window.NW_register) return;

  /** @type {Array<{id:string, name:string, description:string, defaultScore:number, tags:string[], detect:function}>} */
  window.NW_DETECTIONS = [];

  /**
   * Register a detection module.
   */
  window.NW_register = function (config) {
    if (!config.id || !config.detect) {
      console.warn('[Nehboro] Invalid detection registration:', config);
      return;
    }
    // Prevent duplicate registration
    if (window.NW_DETECTIONS.some(d => d.id === config.id)) return;
    window.NW_DETECTIONS.push(config);
  };

})();
