// ============================================================
// Nehboro - blocked/blocked.js
// Enhanced: close-tab safety, full evidence, animated report, localization
// ============================================================

(async function () {
  'use strict';

  // ── I18n initialization ─────────────────────────────────────
  const storage = await chrome.storage.local.get('nehboro_lang');
  const savedLang = storage.nehboro_lang || chrome.i18n.getUILanguage().split('-')[0];
  NehboroI18n.init(savedLang);

  NehboroI18n.applyTranslations();

  const params     = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url') || params.get('blocked') || '';
  const scoreParam = parseInt(params.get('score') || '0', 10);
  const reasonsRaw = params.get('reasons') || '';
  const reasonSingle = params.get('reason') || '';
  const t = NehboroI18n.t;

  function esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ── Populate URL ────────────────────────────────────────
  const urlEl = document.getElementById('blocked-url');
  if (urlEl) urlEl.textContent = blockedUrl || document.referrer || t('url_not_available');

  // ── Load full findings from storage ─────────────────────
  chrome.storage.local.get(['nehboro_block_details', 'nehboro_thresholds'], (data) => {
    const details    = data.nehboro_block_details || null;
    const thresholds = data.nehboro_thresholds || {};
    const blockAt    = thresholds.block ?? 79;

    const hasDetails = details && details.findings && details.findings.length > 0
      && (!blockedUrl || details.url === blockedUrl || Date.now() - (details.ts || 0) < 30000);

    const findings = hasDetails ? details.findings : [];
    const score    = hasDetails ? details.score : scoreParam;

    // Score display
    const scoreEl = document.getElementById('score-value');
    if (scoreEl) scoreEl.textContent = score > 0 ? score : '100+';

    const descEl = document.getElementById('info-desc');
    if (descEl && blockedUrl) {
      let hostname = '';
      try { hostname = new URL(blockedUrl).hostname; } catch {}
      if (hostname) {
        descEl.textContent = t('threat_description_dynamic')
          .replace('{hostname}', hostname)
          .replace('{score}', score > 0 ? score : '100+')
          .replace('{threshold}', blockAt);
      }
    }

    // Score bar (animate after short delay)
    const barEl = document.getElementById('score-breakdown');
    if (barEl && score > 0) {
      barEl.style.display = 'flex';
      document.getElementById('score-bar-text').textContent = `${score} pts`;
      document.getElementById('score-threshold').textContent = blockAt;
      setTimeout(() => {
        const pct = Math.min((score / Math.max(score, blockAt * 1.5)) * 100, 100);
        const fill = document.getElementById('score-fill');
        if (fill) fill.style.width = pct + '%';
      }, 200);
    }

    // Detailed findings
    if (findings.length > 0) {
      renderDetections(findings);
    } else {
      const allReasons = [
        ...(reasonSingle ? [reasonSingle] : []),
        ...reasonsRaw.split(',').filter(Boolean),
      ].map(r => r.replace(/_/g, ' ').toUpperCase());
      if (allReasons.length > 0) {
        const fallback = document.getElementById('reasons-fallback');
        const list = document.getElementById('reasons-list');
        if (fallback && list) {
          fallback.style.display = 'block';
          list.innerHTML = allReasons.map(r => `<span class="reason-tag">${esc(r)}</span>`).join('');
        }
      }
    }

    // Store findings ref for report button
    window._nwFindings = findings;
    window._nwScore = score;
    window._nwMeta = details?.meta || {};
  });

  // ── Render expandable detection cards ─────────────────
  function renderDetections(findings) {
    const section = document.getElementById('detections-section');
    const list    = document.getElementById('detections-list');
    const titleEl = document.getElementById('detections-title');
    if (!section || !list) return;

    section.style.display = 'block';
    titleEl.textContent = `${t('detections')} (${findings.length})`;

    const sorted = [...findings].sort((a, b) => (b.score || 0) - (a.score || 0));

    list.innerHTML = sorted.map((f, i) => {
      const name = esc((f.name || f.category || '').replace(/_/g, ' '));
      const cat  = esc(f.category || '');
      const desc = esc(f.description || '');
      const ev   = f.evidence || '';
      const sc   = f.score || 0;
      const scClass = sc >= 30 ? 'high' : sc >= 15 ? 'med' : 'low';
      const tags = (f.tags || []).map(t => {
        const cls = t === 'critical' ? 'critical' : t === 'combo' ? 'combo' : '';
        return `<span class="detail-tag ${cls}">${esc(t)}</span>`;
      }).join('');

      return `
        <div class="detection-card" data-idx="${i}">
          <div class="detection-row" data-toggle="${i}">
            <span class="detection-arrow" data-arrow="${i}">▶</span>
            <span class="detection-name">${name}</span>
            <span class="detection-score ${scClass}">+${sc}</span>
          </div>
          <div class="detection-detail" data-detail="${i}">
            ${cat ? `<div style="font-size:10px;color:#555;font-family:monospace;margin-bottom:4px;">${cat}</div>` : ''}
            <div class="detail-desc">${desc}</div>
            ${ev ? `
              <div class="detail-evidence-label">${t('matched_content')}</div>
              <div class="detail-evidence">${esc(ev)}</div>
            ` : ''}
            ${tags ? `<div class="detail-tags">${tags}</div>` : ''}
          </div>
        </div>`;
    }).join('');

    // Click to expand
    list.addEventListener('click', (e) => {
      const row = e.target.closest('[data-toggle]');
      if (!row) return;
      const i = row.dataset.toggle;
      const detail = list.querySelector(`[data-detail="${i}"]`);
      const arrow  = list.querySelector(`[data-arrow="${i}"]`);
      if (!detail) return;
      const open = detail.classList.toggle('open');
      if (arrow) arrow.textContent = open ? '▼' : '▶';
    });

    // Expand / collapse all
    let allOpen = false;
    document.getElementById('detections-toggle')?.addEventListener('click', () => {
      allOpen = !allOpen;
      list.querySelectorAll('.detection-detail').forEach(d => d.classList.toggle('open', allOpen));
      list.querySelectorAll('.detection-arrow').forEach(a => a.textContent = allOpen ? '▼' : '▶');
      document.getElementById('detections-toggle').textContent = allOpen ? '▲ ' + t('collapse_all') : '▼ ' + t('expand_all');
    });
  }

  // ── Back to Safety: close tab + open new tab ────────────
  document.getElementById('btn-back')?.addEventListener('click', () => {
    chrome.tabs.getCurrent((tab) => {
      // Open a clean new tab first, then close this one
      chrome.tabs.create({ url: 'chrome://newtab' }, () => {
        if (tab && tab.id) chrome.tabs.remove(tab.id);
      });
    });
  });

  // ── Report button with animation ──────────────────────
  document.getElementById('btn-report')?.addEventListener('click', function () {
    const btn = this;
    if (btn.classList.contains('sent')) return;
    btn.innerHTML = `<span class="btn-icon">⏳</span> ${t('sending')}…`;
    btn.style.opacity = '0.7';

    chrome.runtime.sendMessage({
      type: 'NW_COMMUNITY_REPORT',
      url: blockedUrl || window.location.href,
      findings: window._nwFindings || [],
      score: window._nwScore || scoreParam,
      meta: window._nwMeta || {},
    }, (resp) => {
      btn.style.opacity = '1';
      btn.classList.add('sent');
      if (resp && resp.ok) {
        btn.innerHTML = `<span class="btn-icon check-anim">✓</span> ${t('report_sent')}`;
      } else if (resp && resp.queued) {
        btn.innerHTML = `<span class="btn-icon">📥</span> ${t('queued')}`;
      } else {
        btn.innerHTML = `<span class="btn-icon check-anim">✓</span> ${t('reported')}`;
      }
    });
  });

  // ── Proceed with warning ──────────────────────────────
  document.getElementById('btn-proceed')?.addEventListener('click', () => {
    const warning = document.getElementById('proceed-warning');
    if (warning) warning.style.display = 'block';
  });

  document.getElementById('btn-proceed-confirm')?.addEventListener('click', function () {
    const btn = this;
    btn.textContent = `⏳ ${t('registering_exception')}…`; btn.disabled = true;
    const target = (blockedUrl && blockedUrl.startsWith('http')) ? blockedUrl : (document.referrer || null);
    if (!target) { btn.textContent = t('no_url_to_proceed'); return; }
    let hostname = '';
    try { hostname = new URL(target).hostname; } catch {}
    chrome.runtime.sendMessage({ type: 'NW_BYPASS_URL', hostname, url: target }, (resp) => {
      if (resp && resp.ok) setTimeout(() => { window.location.href = target; }, 150);
      else window.location.href = target;
    });
  });

})();
