(async function () {
  'use strict';

  // ── I18n initialization ─────────────────────────────────────
  const storage = await chrome.storage.local.get('nehboro_lang');
  const savedLang = storage.nehboro_lang || chrome.i18n.getUILanguage().split('-')[0];
  NehboroI18n.init(savedLang);

  function applyTranslations() {
    const t = NehboroI18n.t;
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val !== key) {
        if (el.childNodes.length <= 1) {
          el.textContent = val;
        } else {
          const textNode = [...el.childNodes].find(n => n.nodeType === 3);
          if (textNode) textNode.textContent = val;
        }
      }
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = t(key);
      if (val !== key) el.placeholder = val;
    });

    const langSelect = document.getElementById('select-lang');
    if (langSelect) langSelect.value = NehboroI18n.getLanguage();
  }

  applyTranslations();

  document.getElementById('select-lang')?.addEventListener('change', async (e) => {
    const newLang = e.target.value;
    await chrome.storage.local.set({ nehboro_lang: newLang });
    location.reload();
  });

  // ── Tab navigation ──────────────────────────────────────
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    });
  });

  // ── Current tab ─────────────────────────────────────────
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let currentHostname = '';
  try { currentHostname = new URL(activeTab?.url || '').hostname; } catch {}

  function msg(type, extra = {}) {
    return chrome.runtime.sendMessage({ type, hostname: currentHostname, url: activeTab?.url, ...extra });
  }

  function showMsg(id, text, color = 'var(--accent-green)') {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.style.color = color;
    setTimeout(() => { if (el) el.textContent = ''; }, 4000);
  }

  function esc(s) {
    return String(s || '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── STATUS TAB ──────────────────────────────────────────
  async function loadStatus() {
    const { scan, whitelisted } = await msg('NW_GET_SCAN');
    const container = document.getElementById('status-content');
    const t = NehboroI18n.t;

    if (whitelisted) {
      container.innerHTML = `
        <div class="status-card safe">
          <div class="status-row">
            <span class="status-icon">✅</span>
            <div>
              <div class="status-label">${t('trusted_domain')}</div>
              <div class="status-host">${esc(currentHostname)}</div>
            </div>
            <span class="badge-green">TRUSTED</span>
          </div>
        </div>
        <div class="engine-cards">
          <div class="engine-card"><div class="engine-card-title"><span class="icon">⚡</span> ${t('ioc_engine')}</div><div class="engine-card-value safe">SKIP</div><div class="engine-card-sub">${t('trusted_domain')}</div></div>
          <div class="engine-card"><div class="engine-card-title"><span class="icon">🔬</span> ${t('heuristic_engine')}</div><div class="engine-card-value safe">SKIP</div><div class="engine-card-sub">${t('trusted_domain')}</div></div>
        </div>`;
      return;
    }

    if (!scan) {
      container.innerHTML = `
        <div class="status-card safe">
          <div class="status-row">
            <span class="status-icon">✅</span>
            <div>
              <div class="status-label">${t('no_threats')}</div>
              <div class="status-host">${esc(currentHostname) || 'No page loaded'}</div>
            </div>
            <span class="status-score safe">${t('clean')}</span>
          </div>
        </div>
        <div class="engine-cards">
          <div class="engine-card"><div class="engine-card-title"><span class="icon">⚡</span> ${t('ioc_engine')}</div><div class="engine-card-value safe">${t('pass')}</div><div class="engine-card-sub">${t('no_feed_match')}</div></div>
          <div class="engine-card"><div class="engine-card-title"><span class="icon">🔬</span> ${t('heuristic_engine')}</div><div class="engine-card-value safe">${t('pass')}</div><div class="engine-card-sub">${t('no_detections')}</div></div>
        </div>`;
      return;
    }

    const score    = scan.score || 0;
    const threshData = await chrome.storage.local.get('nehboro_thresholds');
    const th = threshData.nehboro_thresholds || {};
    const blockAt = th.block ?? 79;
    const warnAt  = th.warn ?? 45;
    const sc       = score >= blockAt ? 'danger' : score >= warnAt ? 'warn' : 'safe';
    const icon     = score >= blockAt ? '🚨' : score >= warnAt ? '⚠️' : '✅';
    const label    = score >= blockAt ? t('blocked').toUpperCase() : score >= warnAt ? t('tab_settings').toUpperCase() : t('clean');
    const findings = scan.findings || [];

    const feedFindings = findings.filter(f => f.category === 'FEED_MATCH');
    const heurFindings = findings.filter(f => f.category !== 'FEED_MATCH');
    const feedStatus   = feedFindings.length > 0 ? 'danger' : 'safe';
    const heurStatus   = heurFindings.length > 0 ? (score >= blockAt ? 'danger' : 'warn') : 'safe';

    let html = `
      <div class="status-card ${sc}">
        <div class="status-row">
          <span class="status-icon">${icon}</span>
          <div>
            <div class="status-label">${label}</div>
            <div class="status-host">${esc(currentHostname)}</div>
          </div>
          <span class="status-score ${sc}">${score}</span>
        </div>
      </div>
      <div class="engine-cards">
        <div class="engine-card">
          <div class="engine-card-title"><span class="icon">⚡</span> ${t('ioc_engine')}</div>
          <div class="engine-card-value ${feedStatus}">${feedFindings.length > 0 ? t('hit') : t('pass')}</div>
          <div class="engine-card-sub">${feedFindings.length > 0 ? feedFindings.length + ' ' + t('no_feed_match') : t('no_feed_match')}</div>
        </div>
        <div class="engine-card">
          <div class="engine-card-title"><span class="icon">🔬</span> ${t('heuristic_engine')}</div>
          <div class="engine-card-value ${heurStatus}">${heurFindings.length > 0 ? heurFindings.length + ' ' + t('hit') : t('pass')}</div>
          <div class="engine-card-sub">${heurFindings.length > 0 ? t('threat_score') + ': ' + heurFindings.reduce((s,f)=>s+f.score,0) : t('no_detections')}</div>
        </div>
      </div>`;

    if (findings.length) {
      html += `<div class="section-title">${t('detections_count')} (${findings.length}) <span class="line"></span></div>`;
      for (const f of [...findings].sort((a,b) => (b.score||0) - (a.score||0))) {
        const hi = f.score >= 30;
        const fid = 'f_' + Math.random().toString(36).slice(2, 9);
        const matches = Array.isArray(f.matches) ? f.matches : [];
        const matchesBlock = matches.length > 0
          ? `<div class="match-panel" id="${fid}_panel" style="display:none;">
               <div class="match-panel-title">🔍 ${t('matched_content')} <span class="match-count">${matches.length}</span></div>
               <div class="match-items">
                 ${matches.slice(0, 40).map(m => `<div class="match-item">${esc(String(m).substring(0, 200))}</div>`).join('')}
                 ${matches.length > 40 ? `<div class="match-item match-more">+${matches.length - 40} more…</div>` : ''}
               </div>
             </div>`
          : '';
        const toggleBtn = matches.length > 0
          ? `<button class="match-toggle" data-target="${fid}_panel">${t('show_all').replace('{count}', matches.length)} ${matches.length} ${t('matched_keywords')} ▾</button>`
          : '';
        html += `
          <div class="finding ${hi ? '' : 'warn'}">
            <span class="finding-score" style="color:${hi ? 'var(--red)' : 'var(--amber)'}">+${f.score}</span>
            <div class="finding-category">${esc((f.name || f.category).replace(/_/g,' '))}</div>
            <div class="finding-desc">${esc(f.description)}</div>
            ${f.evidence ? `<div class="finding-evidence" title="${esc(f.evidence)}">${esc(f.evidence.substring(0,100))}</div>` : ''}
            ${toggleBtn}
            ${matchesBlock}
          </div>`;
      }
    }

    const extractedUrls = Array.isArray(scan.meta?.extractedUrls) ? scan.meta.extractedUrls : [];
    if (extractedUrls.length > 0) {
      html += `<div class="section-title">${t('extracted_urls')} (${extractedUrls.length}) <span class="line"></span></div>`;
      html += `<div class="urls-panel" id="urls_panel_wrap">
        <div class="urls-toolbar">
          <input class="urls-filter" id="urls_filter" type="text" placeholder="${t('filter_urls')}" />
          <button class="urls-copy" id="urls_copy">${t('copy_all')}</button>
        </div>
        <div class="urls-list" id="urls_list">
          ${extractedUrls.slice(0, 100).map(u => `<div class="url-item" title="${esc(u)}">${esc(u)}</div>`).join('')}
          ${extractedUrls.length > 100 ? `<div class="url-item match-more">+${extractedUrls.length - 100} more…</div>` : ''}
        </div>
      </div>`;
    }

    container.innerHTML = html;

    container.querySelectorAll('.match-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const panel = container.querySelector('#' + btn.dataset.target);
        if (!panel) return;
        const showing = panel.style.display !== 'none';
        panel.style.display = showing ? 'none' : 'block';
        btn.innerHTML = btn.innerHTML.replace(showing ? '▴' : '▾', showing ? '▾' : '▴');
      });
    });

    const urlFilter = container.querySelector('#urls_filter');
    const urlsList  = container.querySelector('#urls_list');
    if (urlFilter && urlsList) {
      urlFilter.addEventListener('input', () => {
        const q = urlFilter.value.trim().toLowerCase();
        urlsList.querySelectorAll('.url-item').forEach(el => {
          el.style.display = (!q || el.textContent.toLowerCase().includes(q)) ? 'block' : 'none';
        });
      });
    }
    const copyBtn = container.querySelector('#urls_copy');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(extractedUrls.join('\n')).then(() => {
          const original = copyBtn.textContent;
          copyBtn.textContent = '✓';
          setTimeout(() => { copyBtn.textContent = original; }, 1500);
        });
      });
    }
  }

  // ── FEEDS TAB ───────────────────────────────────────────
  async function loadFeeds() {
    const { settings, defaultFeeds } = await msg('NW_GET_SETTINGS');
    const customFeeds = settings?.nehboro_custom_feeds || [];
    const t = NehboroI18n.t;

    const defList = document.getElementById('default-feeds-list');
    if (defList && defaultFeeds) {
      defList.innerHTML = Object.entries(defaultFeeds).map(([type, url]) => `
        <div class="feed-item">
          <div class="feed-info">
            <div class="feed-name">Nehboro/nehboro.github.io - ${type}</div>
            <div class="feed-url">${esc(url)}</div>
          </div>
          <span class="feed-type">${type}</span>
        </div>`).join('');
    }

    const container = document.getElementById('custom-feeds-list');
    if (!container) return;
    if (customFeeds.length === 0) {
      container.innerHTML = `<div style="color:var(--muted);font-size:12px;padding:6px 0;">${t('no_custom_feeds')}</div>`;
    } else {
      container.innerHTML = customFeeds.map((f, i) => `
        <div class="feed-item">
          <div class="feed-info">
            <div class="feed-name">${esc(f.name || f.url)}</div>
            <div class="feed-url">${esc(f.url)}</div>
          </div>
          <span class="feed-type">${f.type}</span>
          <button class="btn-remove" data-idx="${i}">✕</button>
        </div>`).join('');

      container.querySelectorAll('.btn-remove').forEach(btn => {
        btn.addEventListener('click', async () => {
          await msg('NW_REMOVE_CUSTOM_FEED', { index: parseInt(btn.dataset.idx) });
          showMsg('feed-status-msg', t('feed_removed'));
          loadFeeds(); loadStats();
        });
      });
    }
  }

  document.getElementById('btn-add-feed')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    const name = document.getElementById('feed-name')?.value.trim();
    const url  = document.getElementById('feed-url')?.value.trim();
    const type = document.getElementById('feed-type')?.value;
    if (!url) { showMsg('feed-status-msg', t('please_enter_url'), 'var(--accent-red)'); return; }
    try { new URL(url); } catch { showMsg('feed-status-msg', t('invalid_url'), 'var(--accent-red)'); return; }
    const btn = document.getElementById('btn-add-feed');
    const originalText = btn.textContent;
    btn.disabled = true; btn.textContent = t('adding');
    try {
      const r = await msg('NW_ADD_CUSTOM_FEED', { name, feedUrl: url, feedType: type });
      showMsg('feed-status-msg', t('feed_added').replace('{total}', r.total));
      document.getElementById('feed-name').value = '';
      document.getElementById('feed-url').value  = '';
      loadFeeds(); loadStats();
    } catch { showMsg('feed-status-msg', t('error_adding_feed'), 'var(--accent-red)'); }
    finally { btn.disabled = false; btn.textContent = originalText; }
  });

  document.getElementById('btn-refresh-feeds')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    const btn = document.getElementById('btn-refresh-feeds');
    const originalText = btn.textContent;
    btn.disabled = true; btn.textContent = '⏳ ' + t('refreshing');
    await msg('NW_REFRESH_FEEDS');
    showMsg('feed-status-msg', t('feeds_refreshed'));
    btn.disabled = false; btn.textContent = originalText;
    loadFeeds(); loadStats();
  });

  // ── STATS TAB ───────────────────────────────────────────
  async function loadStats() {
    const { stats, lastRefresh, iocCounts } = await msg('NW_GET_STATS');
    const t = NehboroI18n.t;
    if (document.getElementById('stat-blocked')) document.getElementById('stat-blocked').textContent  = (stats?.blocked  || 0).toLocaleString();
    if (document.getElementById('stat-warned'))  document.getElementById('stat-warned').textContent   = (stats?.warned   || 0).toLocaleString();
    if (document.getElementById('stat-reported'))document.getElementById('stat-reported').textContent = (stats?.reported || 0).toLocaleString();

    const total = (iocCounts?.domains || 0) + (iocCounts?.urls || 0) + (iocCounts?.ips || 0) + (iocCounts?.ports || 0);
    const iocEl = document.getElementById('stat-iocs');
    if (iocEl) iocEl.textContent = total.toLocaleString();

    const iocBadge = document.getElementById('engine-ioc-count');
    if (iocBadge) iocBadge.textContent = total > 0 ? total.toLocaleString() : '-';

    const coverageEl = document.getElementById('feed-coverage');
    if (coverageEl && iocCounts) {
      coverageEl.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;">
          <span>🌐 <strong>${(iocCounts.domains||0).toLocaleString()}</strong> ${t('domains')}</span>
          <span>🔗 <strong>${(iocCounts.urls||0).toLocaleString()}</strong> ${t('urls')}</span>
          <span>🖥️ <strong>${(iocCounts.ips||0).toLocaleString()}</strong> ${t('ips')}</span>
          <span>🔌 <strong>${(iocCounts.ports||0).toLocaleString()}</strong> ${t('ports')}</span>
        </div>
        ${lastRefresh ? `<div style="color:var(--muted);font-size:10px;margin-top:6px;font-family:var(--mono);">${t('last_refresh')}: ${new Date(lastRefresh).toLocaleString()}</div>` : ''}`;
    }
  }

  // ── SETTINGS TAB ────────────────────────────────────────
  async function loadSettings() {
    const { settings } = await msg('NW_GET_SETTINGS');
    const t = NehboroI18n.t;
    const whitelist = settings?.nehboro_whitelist || [];
    const thresholds = settings?.nehboro_thresholds || {};

    document.getElementById('threshold-warn').value = thresholds.warn ?? 45;
    document.getElementById('threshold-block').value = thresholds.block ?? 79;
    document.getElementById('toggle-notifications').checked = thresholds.showBanners !== false;
    document.getElementById('toggle-auto-report').checked = thresholds.autoReport !== false;

    const silentEl = document.getElementById('toggle-silent-mode');
    const silentStatus = document.getElementById('silent-mode-status');
    if (silentEl) {
      silentEl.checked = !!thresholds.silentMode;
      if (silentStatus) silentStatus.style.display = thresholds.silentMode ? 'block' : 'none';
    }

    const container = document.getElementById('whitelist-list');
    if (!container) return;

    container.innerHTML = whitelist.length === 0
      ? `<div style="color:var(--muted);font-size:12px;">${t('no_trusted_domains')}</div>`
      : whitelist.map(domain => `
          <div class="feed-item">
            <div class="feed-info"><div class="feed-name">${esc(domain)}</div></div>
            <button class="btn-remove" data-domain="${esc(domain)}">${t('remove')}</button>
          </div>`).join('');

    container.querySelectorAll('.btn-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        await msg('NW_REMOVE_WHITELIST', { domain: btn.dataset.domain });
        showMsg('settings-msg', `${btn.dataset.domain} ${t('remove')}.`);
        loadSettings();
      });
    });
  }

  document.getElementById('toggle-silent-mode')?.addEventListener('change', async (e) => {
    const t = NehboroI18n.t;
    const silentMode = e.target.checked;
    const { settings } = await msg('NW_GET_SETTINGS');
    const thresholds = settings?.nehboro_thresholds || {};
    thresholds.silentMode = silentMode;
    if (silentMode) {
      thresholds.showBanners = false;
    }
    await msg('NW_SAVE_THRESHOLDS', { thresholds });
    const silentStatus = document.getElementById('silent-mode-status');
    if (silentStatus) silentStatus.style.display = silentMode ? 'block' : 'none';
    showMsg('threshold-msg', silentMode ? t('silent_mode_on') : t('silent_mode_off'));
    loadSettings();
  });

  document.getElementById('btn-save-thresholds')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    const warn = parseInt(document.getElementById('threshold-warn').value) || 45;
    const block = parseInt(document.getElementById('threshold-block').value) || 79;
    const showBanners = document.getElementById('toggle-notifications').checked;
    const autoReport = document.getElementById('toggle-auto-report').checked;
    const silentMode = document.getElementById('toggle-silent-mode')?.checked || false;
    if (warn >= block) { showMsg('threshold-msg', t('warning_must_lower'), 'var(--red)'); return; }
    await msg('NW_SAVE_THRESHOLDS', { thresholds: { warn, block, showBanners, autoReport, silentMode } });
    showMsg('threshold-msg', t('settings_saved'));
  });

  document.getElementById('btn-export-logs')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    const result = await msg('NW_EXPORT_SCAN_HISTORY');
    if (!result?.data || result.data.length === 0) {
      showMsg('export-msg', t('no_scan_history'), 'var(--muted)');
      return;
    }
    const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `nehboro_scans_${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
    showMsg('export-msg', `Exported ${result.data.length} scan(s).`);
  });

  document.getElementById('btn-clear-stats')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    if (!confirm(t('reset_stats_confirm'))) return;
    await msg('NW_CLEAR_STATS');
    showMsg('export-msg', t('stats_cleared'));
    loadStats();
  });

  document.getElementById('btn-report-page')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    if (!activeTab?.url) return;
    const btn = document.getElementById('btn-report-page');
    const originalText = btn.textContent;
    btn.disabled = true; btn.textContent = '⏳ ' + t('sending') + '…';

    let findings = [], score = 0, meta = {};
    try {
      const resp = await msg('NW_GET_SCAN', { hostname: currentHostname });
      if (resp?.scan) {
        findings = resp.scan.findings || [];
        score    = resp.scan.score || 0;
        meta     = resp.scan.meta || {};
      }
    } catch {}

    const result = await msg('NW_COMMUNITY_REPORT', {
      url: activeTab.url,
      findings,
      score,
      meta,
    });
    if (result?.ok) {
      showMsg('settings-msg', '✅ ' + t('report_sent'));
    } else if (result?.queued) {
      showMsg('settings-msg', '📥 ' + t('queued'), 'var(--accent-yellow)');
    } else {
      showMsg('settings-msg', '✅ ' + t('reported'), 'var(--accent-green)');
    }
    btn.disabled = false; btn.textContent = originalText;
  });

  document.getElementById('btn-trust-domain')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    if (!currentHostname) return;
    await msg('NW_WHITELIST_DOMAIN', { domain: currentHostname });
    showMsg('settings-msg', t('domain_trusted').replace('{domain}', currentHostname));
    loadSettings();
  });

  // ── SCORES TAB ─────────────────────────────────────────
  let detectionsList = [];
  let customScores = {};

  async function loadScores() {
    const t = NehboroI18n.t;
    const container = document.getElementById('score-list');
    const countEl   = document.getElementById('scores-count');
    if (!container) return;

    const stored = await chrome.storage.local.get('nehboro_custom_scores');
    customScores = stored.nehboro_custom_scores || {};

    try {
      const result = await chrome.tabs.sendMessage(activeTab.id, { type: 'NW_GET_DETECTIONS' });
      if (result?.detections) detectionsList = result.detections;
    } catch {}

    if (detectionsList.length === 0) {
      detectionsList = [
        { id:'CLICKFIX_FULL_SEQUENCE', name:'ClickFix Full Sequence', description:'Complete open-paste-execute instruction sequence', defaultScore:45, tags:['clickfix','critical'] },
        { id:'CLICKFIX_PARTIAL', name:'ClickFix Partial Sequence', description:'Partial open-paste-execute sequence (2 of 3 parts)', defaultScore:25, tags:['clickfix'] },
        { id:'POWERSHELL_ENCODED', name:'PowerShell Encoded Command', description:'Encoded PowerShell with download/execution patterns', defaultScore:40, tags:['clickfix','malware','critical'] },
        { id:'POWERSHELL_PARTIAL', name:'PowerShell Suspicious Pattern', description:'Partial PowerShell patterns', defaultScore:20, tags:['clickfix','malware'] },
        { id:'LOLBIN_IN_CONTEXT', name:'LOLBin with Instructions', description:'Living-off-the-land binary alongside execution instructions', defaultScore:35, tags:['clickfix','malware'] },
        { id:'LOLBIN_COMMAND', name:'LOLBin Command References', description:'Multiple living-off-the-land binary commands in page', defaultScore:25, tags:['malware'] },
        { id:'FAKE_CLOUDFLARE_DOMAIN', name:'Fake Cloudflare Domain', description:'Typosquatted Cloudflare domain', defaultScore:38, tags:['clickfix','phishing'] },
        { id:'FAKE_CLOUDFLARE_TEXT', name:'Fake CAPTCHA Text', description:'Multiple fake CAPTCHA text signals', defaultScore:8, tags:['clickfix','social-engineering'] },
        { id:'FAKE_MEETING', name:'Fake Video Conference', description:'Fake video conferencing interface', defaultScore:28, tags:['clickfix','social-engineering'] },
        { id:'FAKE_UPDATE', name:'Fake Windows Update', description:'Fake Windows Update screen', defaultScore:30, tags:['clickfix','social-engineering'] },
        { id:'MACOS_SHELL', name:'macOS Shell Attack', description:'macOS shell attack patterns', defaultScore:48, tags:['clickfix','malware'] },
        { id:'STEGANOGRAPHY', name:'Steganography Payload', description:'.NET image manipulation steganography', defaultScore:48, tags:['malware','evasion'] },
        { id:'WINHTTP_FULL', name:'WinHttp VBScript Payload', description:'WinHttp VBScript download/execute', defaultScore:50, tags:['malware','critical'] },
        { id:'WINHTTP_PARTIAL', name:'WinHttp/XMLHTTP Pattern', description:'WinHttp/XMLHTTP alongside instructions', defaultScore:22, tags:['malware'] },
        { id:'DNS_CLICKFIX', name:'DNS ClickFix (nslookup C2)', description:'nslookup-based payload delivery', defaultScore:45, tags:['clickfix','malware','critical'] },
        { id:'WEBDAV_MOUNT', name:'WebDAV Share Mount', description:'WebDAV share-mount signals', defaultScore:38, tags:['malware','clickfix'] },
        { id:'FINGER_ABUSE', name:'finger.exe Abuse / CrashFix', description:'finger.exe abuse or CrashFix lure', defaultScore:35, tags:['malware','clickfix'] },
        { id:'CONSENTFIX', name:'OAuth ConsentFix', description:'OAuth ConsentFix token theft', defaultScore:42, tags:['phishing','clickfix'] },
        { id:'FILEFIX', name:'FileFix (Explorer Address Bar)', description:'Paste command into Explorer address bar', defaultScore:38, tags:['clickfix'] },
        { id:'HEX_IP', name:'Hex/Decimal Encoded IP', description:'Hex/decimal-encoded IP address', defaultScore:30, tags:['malware','evasion'] },
        { id:'LLM_ARTIFACT_ABUSE', name:'AI Artifact Abuse', description:'AI artifact delivering malicious instructions', defaultScore:32, tags:['clickfix','social-engineering'] },
        { id:'FAKE_SOFTWARE_DL', name:'Fake Software Download', description:'Fake software download lure', defaultScore:25, tags:['social-engineering'] },
        { id:'OBFUSCATION_HEAVY', name:'Heavy JS Obfuscation', description:'Heavy JavaScript obfuscation patterns', defaultScore:28, tags:['malware','evasion'] },
        { id:'OBFUSCATION', name:'JS Obfuscation Patterns', description:'JavaScript obfuscation patterns (eval, hex strings, _0x vars)', defaultScore:12, tags:['malware','evasion'] },
        { id:'URGENCY', name:'Urgency Manipulation', description:'Urgency/scarcity manipulation phrases', defaultScore:6, tags:['social-engineering'] },
        { id:'SUSPICIOUS_TERMS', name:'Suspicious Keyword Accumulation', description:'High density of security-sensitive terms', defaultScore:2, tags:['heuristic'] },
        { id:'PHISHING_IMPERSONATION', name:'Brand Impersonation + Login', description:'Page impersonates a major brand with login form', defaultScore:35, tags:['phishing','critical'] },
        { id:'SUSPICIOUS_REDIRECT', name:'Suspicious Meta Redirect', description:'Meta refresh redirect to different domain', defaultScore:18, tags:['phishing'] },
        { id:'FAKE_SOCIAL_PROOF', name:'Fake Social Proof', description:'Fake user count or social proof claims', defaultScore:12, tags:['social-engineering'] },
        { id:'SUSPICIOUS_HOST', name:'Suspicious Hosting + Credentials', description:'Credential form on free/suspicious hosting', defaultScore:20, tags:['phishing'] },
        { id:'CLIPBOARD_HIJACK', name:'Clipboard Hijack (Runtime)', description:'Suspicious clipboard write at runtime', defaultScore:40, tags:['clickfix','malware','critical'] },
        { id:'CLIPBOARD_SOURCE', name:'Clipboard Write in Source', description:'Clipboard API calls in page source', defaultScore:10, tags:['clickfix','malware'] },
        { id:'LOOKALIKE_HOMOGRAPH', name:'Homograph Domain Attack', description:'Domain uses character substitution to impersonate', defaultScore:40, tags:['phishing','critical'] },
        { id:'LOOKALIKE_TYPOSQUAT', name:'Typosquat Domain', description:'Domain 1-2 chars from a major brand', defaultScore:35, tags:['phishing'] },
        { id:'LOOKALIKE_BRAND_SUBSTRING', name:'Brand Name in Domain', description:'Domain contains brand name but is not official', defaultScore:10, tags:['phishing'] },
        { id:'DATA_URI_PAYLOAD', name:'Data URI Payload', description:'Suspicious data: URI with executable content', defaultScore:25, tags:['malware','evasion'] },
        { id:'CRYPTO_WALLET_PHISHING', name:'Crypto Wallet Phishing', description:'Seed phrase / private key harvesting', defaultScore:45, tags:['phishing','critical'] },
        { id:'CRYPTO_WALLET', name:'Crypto Wallet Connect Lure', description:'Multiple crypto wallets with connect/sign functionality', defaultScore:12, tags:['phishing','crypto'] },
        { id:'FORM_EXTERNAL_ACTION', name:'Form Posts to External Domain', description:'Credential form posts to different domain', defaultScore:25, tags:['phishing'] },
        { id:'CREDENTIAL_EXFIL_FETCH', name:'Credential Exfil via Fetch/XHR', description:'Form data sent to external endpoint', defaultScore:22, tags:['phishing','malware'] },
        { id:'HIDDEN_CONTENT', name:'Hidden Malicious Content', description:'Suspicious commands hidden via CSS', defaultScore:20, tags:['evasion','clickfix'] },
        { id:'SUSPICIOUS_TLD', name:'High-Risk TLD', description:'Domain uses TLD common in phishing', defaultScore:8, tags:['phishing','heuristic'] },
        { id:'BASE64_PAYLOAD', name:'Large Base64 Payload', description:'Suspicious large base64-encoded string', defaultScore:15, tags:['malware','evasion'] },
        { id:'EVAL_DYNAMIC', name:'Dynamic Code Execution', description:'eval() or Function() with obfuscated content', defaultScore:15, tags:['malware','evasion'] },
        { id:'FAKE_DOWNLOAD_BUTTON', name:'Fake Download Button', description:'Download button linking to suspicious file', defaultScore:18, tags:['social-engineering','malware'] },
        { id:'FAKE_ERROR_PAGE', name:'Fake Error / BSOD Page', description:'Fake browser error or system crash page', defaultScore:30, tags:['social-engineering','tech-support-scam'] },
        { id:'PUNYCODE_DOMAIN', name:'Punycode/IDN Domain', description:'Domain uses Punycode encoding', defaultScore:20, tags:['phishing'] },
        { id:'FAKE_ANTIVIRUS', name:'Fake Antivirus Scan', description:'Fake antivirus or malware scan page', defaultScore:35, tags:['social-engineering','scam'] },
        { id:'TECH_SUPPORT_SCAM', name:'Tech Support Scam', description:'Tech support scam with phone + urgency', defaultScore:40, tags:['social-engineering','scam','critical'] },
        { id:'EXTERNAL_SCRIPT_OVERLOAD', name:'Excessive External Scripts', description:'Many external script domains on credential page', defaultScore:12, tags:['heuristic','malware'] },
        { id:'CRYPTO_ADDRESS_SWAP', name:'Crypto Address in Clipboard Context', description:'Crypto address near clipboard API', defaultScore:2, tags:['malware','crypto'] },
        { id:'CRYPTO_ADDRESSES_LISTED', name:'Multiple Crypto Wallet Addresses', description:'Page lists multiple cryptocurrency wallet addresses', defaultScore:18, tags:['malware','crypto'] },
        { id:'FAKE_COUNTDOWN', name:'Fake Countdown Timer', description:'Countdown timer with threat context', defaultScore:10, tags:['social-engineering'] },
        { id:'SUSPICIOUS_POPUP', name:'Suspicious window.open', description:'Suspicious popup or window.open call', defaultScore:12, tags:['phishing','heuristic'] },
        { id:'PASSWORD_AUTOCOMPLETE', name:'Password Field Autocomplete Abuse', description:'Hidden password field capturing autofill', defaultScore:25, tags:['phishing'] },
        { id:'WINDOW_OPENER_ABUSE', name:'window.opener Abuse', description:'Reverse tabnabbing via window.opener', defaultScore:22, tags:['phishing'] },
        { id:'KEYLOGGER_PATTERN', name:'Keylogger Pattern', description:'Captures keystrokes and sends externally', defaultScore:35, tags:['malware','phishing','critical'] },
        { id:'IFRAME_INJECTION', name:'Hidden Iframe Injection', description:'Dynamically injected hidden iframe', defaultScore:18, tags:['malware','phishing'] },
        { id:'FORMJACKING', name:'Formjacking / Skimmer', description:'Payment card skimmer patterns', defaultScore:40, tags:['malware','critical'] },
        { id:'SEO_POISONING', name:'SEO Poisoning / Cloaking', description:'Referrer-based content switching', defaultScore:15, tags:['evasion','heuristic'] },
        { id:'MSEDGE_KIOSK', name:'Edge Kiosk Mode Phishing', description:'msedge --kiosk used for fake fullscreen login', defaultScore:50, tags:['phishing','clickfix','critical'] },
        { id:'BROWSER_LOCK', name:'Browser Lock / Fullscreen Abuse', description:'Fullscreen API, history traps, or popstate locks', defaultScore:30, tags:['social-engineering','scam'] },
        { id:'VISUAL_BRAND_IMPERSONATION', name:'Visual Brand Impersonation', description:'Page visually mimics a brand (colors, logos, favicon) on non-official domain', defaultScore:6, tags:['phishing','visual','critical'] },
        { id:'FAVICON_BRAND_MISMATCH', name:'Favicon Brand Mismatch', description:'Favicon loads from brand CDN on non-official domain', defaultScore:20, tags:['phishing','visual'] },
        { id:'LOGIN_FORM_VISUAL', name:'Suspicious Login Form Layout', description:'Centered narrow login form typical of phishing pages', defaultScore:8, tags:['phishing','visual','heuristic'] },
        { id:'BRAND_ASSET_THEFT', name:'Brand Asset Loading', description:'Page loads images/CSS/fonts from brand CDN it does not belong to', defaultScore:10, tags:['phishing','visual'] },
        { id:'FAKE_ERROR_CODE', name:'Fake Windows Error Code', description:'Fake MS-xxxx, 0x errors, DLL errors', defaultScore:30, tags:['social-engineering','tech-support-scam'] },
        { id:'DATA_THEFT_SCARE', name:'Data Theft Scare Tactic', description:'Claims personal data is being stolen', defaultScore:25, tags:['social-engineering','tech-support-scam'] },
        { id:'DIALOG_SPAM', name:'Alert Dialog Spam', description:'Alert/confirm dialog loops to trap users', defaultScore:25, tags:['social-engineering','tech-support-scam'] },
        { id:'SCAM_PHONE_PROMINENT', name:'Prominent Scam Phone Number', description:'Phone number repeated, toll-free, or styled as CTA', defaultScore:20, tags:['social-engineering','tech-support-scam'] },
        { id:'FAKE_OS_UI', name:'Fake System UI Overlay', description:'Fake Windows dialogs or OS notifications in HTML', defaultScore:10, tags:['social-engineering','tech-support-scam'] },
        { id:'FAKE_URL_BAR', name:'Fake URL Bar / BitB Attack', description:'Fake browser URL bar as image (Browser-in-Browser)', defaultScore:40, tags:['phishing','social-engineering','critical'] },
        { id:'IP_GEOLOCATION_SCARE', name:'IP/Location Scare Display', description:'Shows user IP/location/ISP to intimidate', defaultScore:22, tags:['social-engineering','tech-support-scam'] },
        { id:'SCAM_MULTILANG', name:'Multilingual Scam Patterns', description:'Tech support scam in French/Spanish/German/Italian', defaultScore:30, tags:['social-engineering','tech-support-scam'] },
        { id:'RAW_IP_HOSTING', name:'Raw IP Address Hosting', description:'Page served from raw IP with suspicious content', defaultScore:15, tags:['phishing','heuristic'] },
        { id:'PRINT_LOOP', name:'Print Dialog Spam', description:'window.print() called in a loop to freeze browser', defaultScore:35, tags:['social-engineering','tech-support-scam','critical'] },
        { id:'NOTIFICATION_SPAM', name:'Notification Permission Spam', description:'Notification.requestPermission() called repeatedly', defaultScore:25, tags:['social-engineering','scam'] },
        { id:'HISTORY_LOOP', name:'History API Loop', description:'pushState/replaceState spam to prevent back navigation', defaultScore:30, tags:['social-engineering','tech-support-scam'] },
        { id:'URL_CREATE_LOOP', name:'createObjectURL Loop', description:'Blob URL creation loop to exhaust resources', defaultScore:30, tags:['malware','tech-support-scam'] },
        { id:'FULLSCREEN_SPAM', name:'Fullscreen Request Spam', description:'requestFullscreen() loop to lock user', defaultScore:30, tags:['social-engineering','tech-support-scam'] },
        { id:'INSECURE_LOGIN', name:'Insecure Login Form (HTTP)', description:'Login form submits credentials over HTTP', defaultScore:25, tags:['phishing','critical'] },
        { id:'SEARCH_HIJACKING', name:'Search Hijacking', description:'Redirects search queries or mimics search results', defaultScore:22, tags:['malware','social-engineering'] },
        { id:'CARD_SKIMMER_ENHANCED', name:'Credit Card Skimmer (Enhanced)', description:'JS intercepting payment card fields or exfiltrating data', defaultScore:40, tags:['malware','critical'] },
        { id:'SCAM_AUDIO', name:'Scam Alarm Audio', description:'Autoplay alarm/warning audio to frighten users', defaultScore:20, tags:['social-engineering','tech-support-scam'] },
        { id:'CLICKFIX_MULTILANG', name:'Multilingual ClickFix Instructions', description:'ClickFix instructions in Spanish/Portuguese/French/German/Italian', defaultScore:40, tags:['clickfix','social-engineering','critical'] },
        { id:'FAKE_BROWSER_ERROR', name:'Fake Browser Update/Error', description:'Fake Chrome/Opera/Edge/Firefox error with fix instructions', defaultScore:35, tags:['clickfix','social-engineering','critical'] },
        { id:'AV_DISMISSAL_PRETEXT', name:'Antivirus Dismissal Pretext', description:'Tells users to ignore antivirus warnings as expected behavior', defaultScore:30, tags:['clickfix','social-engineering','evasion','critical'] },
        { id:'FAKE_VERIFICATION_ID', name:'Fake Verification ID', description:'Fake Cloudflare/reCAPTCHA/brand verification IDs', defaultScore:30, tags:['clickfix','social-engineering','critical'] },
        { id:'CLICKFIX_PRETEXT', name:'ClickFix Pretext / Cover Story', description:'Fake driver update, missing font, BSOD, mic access, shared file pretexts', defaultScore:30, tags:['clickfix','social-engineering','critical'] },
        { id:'DEVICE_CODE_PHISH', name:'Device Code Phishing', description:'Fake verification code page to hijack OAuth/device login', defaultScore:38, tags:['phishing','social-engineering','critical'] },
        { id:'BONUS_CLIPBOARD_INSTRUCTION', name:'Combo: Clipboard + Instructions', description:'Classic ClickFix combination', defaultScore:15, tags:['combo','critical'] },
        { id:'BONUS_LOLBIN_INSTRUCTION', name:'Combo: LOLBin + Instructions', description:'LOLBin + execution instructions', defaultScore:12, tags:['combo'] },
        { id:'BONUS_CAPTCHA_INSTRUCTION', name:'Combo: Fake CAPTCHA + Instructions', description:'CAPTCHA lure + execution instructions', defaultScore:15, tags:['combo','critical'] },
        { id:'BONUS_PS_CLIPBOARD', name:'Combo: PowerShell + Clipboard', description:'Clipboard hijack + encoded PowerShell', defaultScore:20, tags:['combo','critical'] },
        { id:'BONUS_CRYPTO_LOOKALIKE', name:'Combo: Crypto + Lookalike', description:'Crypto phishing on lookalike domain', defaultScore:20, tags:['combo','critical'] },
        { id:'BONUS_SCAM_FULLKIT', name:'Combo: Full Scam kit', description:'Multiple social engineering signals combined', defaultScore:25, tags:['combo','critical'] },
        { id:'BONUS_VISUAL_PHISH', name:'Combo: Visual Impersonation + Login', description:'Visual brand impersonation + credential harvesting', defaultScore:20, tags:['combo','critical'] },
      ];
    }

    renderScores('');
    if (countEl) countEl.textContent = `${detectionsList.length} ${t('detections_registered')}`;
    const detBadge = document.getElementById('engine-det-count');
    if (detBadge) detBadge.textContent = detectionsList.length;
  }

  function renderScores(filter) {
    const t = NehboroI18n.t;
    const container = document.getElementById('score-list');
    if (!container) return;
    const q = filter.toLowerCase();
    const filtered = q ? detectionsList.filter(d =>
      d.name.toLowerCase().includes(q) || d.id.toLowerCase().includes(q) ||
      d.description.toLowerCase().includes(q) || (d.tags||[]).some(t => t.includes(q))
    ) : detectionsList;

    container.innerHTML = filtered.map(d => {
      const current = customScores[d.id] !== undefined ? customScores[d.id] : d.defaultScore;
      const modified = customScores[d.id] !== undefined ? 'modified' : '';
      return `
        <div class="score-item" data-id="${esc(d.id)}">
          <div class="score-header">
            <span class="score-name">${esc(d.name)}</span>
            <input class="score-input ${modified}" type="number" min="0" max="200" value="${current}" data-id="${esc(d.id)}" data-default="${d.defaultScore}">
          </div>
          <div class="score-desc">${esc(d.description)}</div>
          <div class="score-tags">
            ${(d.tags||[]).map(tg => `<span class="score-tag ${tg === 'critical' ? 'critical' : tg === 'combo' ? 'combo' : ''}">${esc(tg)}</span>`).join('')}
            <span class="score-tag">${t('default')}: ${d.defaultScore}</span>
          </div>
        </div>`;
    }).join('');

    container.querySelectorAll('.score-input').forEach(input => {
      input.addEventListener('input', () => {
        const id = input.dataset.id;
        const val = parseInt(input.value);
        const def = parseInt(input.dataset.default);
        if (!isNaN(val) && val !== def) {
          customScores[id] = val;
          input.classList.add('modified');
        } else {
          delete customScores[id];
          input.classList.remove('modified');
        }
      });
    });
  }

  document.getElementById('scores-search')?.addEventListener('input', (e) => {
    renderScores(e.target.value);
  });

  document.getElementById('btn-save-scores')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    await chrome.storage.local.set({ nehboro_custom_scores: customScores });
    const count = Object.keys(customScores).length;
    showMsg('scores-msg', t('saved_count').replace('{count}', count));
  });

  document.getElementById('btn-reset-scores')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    if (!confirm(t('reset_scores_confirm'))) return;
    customScores = {};
    await chrome.storage.local.set({ nehboro_custom_scores: {} });
    renderScores(document.getElementById('scores-search')?.value || '');
    showMsg('scores-msg', t('all_scores_reset'));
  });

  const DEFAULT_MODEL = 'claude-sonnet-4-20250514';

  async function loadAiConfig() {
    const result = await msg('NW_GET_AI_CONFIG');
    const cfg = result?.config || {};
    const keyEl = document.getElementById('ai-api-key');
    const modelEl = document.getElementById('ai-model');
    const customEl = document.getElementById('ai-model-custom');
    const dotEl = document.getElementById('engine-ai-dot');
    const statusEl = document.getElementById('engine-ai-status');
    const aiBtn = document.getElementById('btn-ai-scan');
    if (keyEl && cfg.apiKey) keyEl.value = cfg.apiKey;

    const model = cfg.model || DEFAULT_MODEL;
    if (modelEl) {
      const optValues = [...modelEl.options].map(o => o.value);
      if (optValues.includes(model)) {
        modelEl.value = model;
        if (customEl) customEl.style.display = 'none';
      } else {
        modelEl.value = 'custom';
        if (customEl) { customEl.style.display = ''; customEl.value = model; }
      }
    }

    const enabled = !!(cfg.apiKey);
    if (dotEl) dotEl.classList.toggle('active', enabled);
    if (statusEl) statusEl.textContent = enabled ? 'CLAUDE' : 'OFF';
    if (aiBtn) aiBtn.style.display = enabled ? '' : 'none';
  }

  document.getElementById('ai-model')?.addEventListener('change', (e) => {
    const customEl = document.getElementById('ai-model-custom');
    if (customEl) customEl.style.display = e.target.value === 'custom' ? '' : 'none';
  });

  document.getElementById('btn-save-ai')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    const apiKey = document.getElementById('ai-api-key')?.value?.trim() || '';
    if (!apiKey) { showMsg('ai-config-msg', t('api_key_required'), 'var(--red)'); return; }
    const modelSel = document.getElementById('ai-model')?.value || DEFAULT_MODEL;
    const model = modelSel === 'custom'
      ? (document.getElementById('ai-model-custom')?.value?.trim() || DEFAULT_MODEL)
      : modelSel;
    await msg('NW_SAVE_AI_CONFIG', { apiKey, model });
    showMsg('ai-config-msg', t('claude_ai_enabled').replace('{model}', model));
    loadAiConfig();
  });

  document.getElementById('btn-clear-ai')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    await msg('NW_CLEAR_AI_CONFIG');
    if (document.getElementById('ai-api-key')) document.getElementById('ai-api-key').value = '';
    if (document.getElementById('ai-model')) document.getElementById('ai-model').value = DEFAULT_MODEL;
    const customEl = document.getElementById('ai-model-custom');
    if (customEl) { customEl.value = ''; customEl.style.display = 'none'; }
    showMsg('ai-config-msg', t('claude_api_key_cleared'));
    loadAiConfig();
  });

  async function loadAiResult() {
    if (!currentHostname) return;
    const result = await msg('NW_GET_AI_RESULT', { hostname: currentHostname });
    const aiData = result?.result;
    const container = document.getElementById('ai-result-section');
    const t = NehboroI18n.t;
    if (!container) return;
    if (!aiData || aiData.status === 'ERROR') { container.style.display = 'none'; return; }
    container.style.display = 'block';
    const statusColor = aiData.status === 'DANGEROUS' ? 'var(--red)' : aiData.status === 'SUSPICIOUS' ? 'var(--amber)' : 'var(--green)';
    const conf = aiData.confidence ? `${(aiData.confidence * 100).toFixed(0)}%` : '-';
    container.innerHTML = `
      <div class="section-title"><span class="icon">🤖</span> <span data-i18n="claude_ai_analysis">${t('claude_ai_analysis')}</span> <span class="line"></span></div>
      <div class="engine-card" style="border-left:3px solid ${statusColor};">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
          <span style="font-family:var(--mono);font-weight:700;font-size:13px;color:${statusColor};">${esc(aiData.status)}</span>
          <span style="font-size:10px;color:var(--muted);font-family:var(--mono);">${t('confidence')}: ${conf}</span>
        </div>
        ${aiData.threat && aiData.threat !== 'NONE' ? `<div style="font-size:10px;color:var(--amber);font-family:var(--mono);margin-bottom:4px;">${t('threat')}: ${esc(aiData.threat)}</div>` : ''}
        <div style="font-size:11px;color:var(--muted);line-height:1.5;">${esc(aiData.explanation || '')}</div>
      </div>`;
  }

  document.getElementById('btn-manual-scan')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    if (!activeTab?.id) return;
    const btn = document.getElementById('btn-manual-scan');
    const originalText = btn.textContent;
    btn.disabled = true; btn.textContent = '⟳ ' + t('scanning');
    try {
      const result = await msg('NW_FORCE_SCAN', { tabId: activeTab.id });
      if (result?.error === 'restricted') {
        showMsg('scan-msg', t('cannot_scan_restricted'), 'var(--red)');
      } else if (result?.error) {
        showMsg('scan-msg', t('scan_failed'), 'var(--red)');
      } else if (result?.findings?.length) {
        showMsg('scan-msg', `${t('threat_score')}: ${result.score} - ${result.findings.length} ${t('detections_count')}.`);
        await loadStatus();
      } else {
        showMsg('scan-msg', t('no_threats_found'));
        await loadStatus();
      }
    } catch {
      showMsg('scan-msg', t('cannot_scan'), 'var(--red)');
    }
    btn.disabled = false; btn.textContent = originalText;
  });

  document.getElementById('btn-ai-scan')?.addEventListener('click', async () => {
    const t = NehboroI18n.t;
    if (!activeTab?.id || !currentHostname) return;
    const btn = document.getElementById('btn-ai-scan');
    const scanBtn = document.getElementById('btn-manual-scan');
    const originalText = btn.textContent;
    btn.disabled = true; btn.textContent = '⟳ ' + t('scanning');
    if (scanBtn) scanBtn.disabled = true;

    try {
      const result = await msg('NW_FORCE_SCAN', { tabId: activeTab.id });
      if (result?.error === 'restricted') {
        showMsg('scan-msg', t('cannot_scan_restricted'), 'var(--red)');
        btn.disabled = false; btn.textContent = originalText;
        if (scanBtn) scanBtn.disabled = false;
        return;
      }
      if (result?.findings?.length) showMsg('scan-msg', `${t('heuristic_engine')}: ${result.score} pts, ${result.findings.length} hit(s)`);
      await loadStatus();
    } catch {}

    btn.textContent = '🤖 ' + t('claude_analyzing');
    try {
      const aiResult = await msg('NW_AI_SCAN', { tabId: activeTab.id, url: activeTab.url, hostname: currentHostname });
      if (aiResult?.error) {
        showMsg('scan-msg', `AI: ${aiResult.error}`, 'var(--amber)');
      } else if (aiResult?.result) {
        const st = aiResult.result.status;
        const color = st === 'DANGEROUS' ? 'var(--red)' : st === 'SUSPICIOUS' ? 'var(--amber)' : 'var(--green)';
        showMsg('scan-msg', t('ai_verdict').replace('{verdict}', st), color);
      }
      await loadAiResult();
    } catch {
      showMsg('scan-msg', t('ai_failed'), 'var(--red)');
    }
    btn.disabled = false; btn.textContent = originalText;
    if (scanBtn) scanBtn.disabled = false;
  });

  chrome.runtime.onMessage.addListener((request) => {
    if (request.type === 'NW_AI_RESULT' && request.hostname === currentHostname) loadAiResult();
  });

  await Promise.all([loadStatus(), loadFeeds(), loadScores(), loadStats(), loadSettings(), loadAiConfig(), loadAiResult()]);
})();
