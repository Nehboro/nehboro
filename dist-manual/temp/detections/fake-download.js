(function () {
  NW_register({
    id: 'FAKE_DOWNLOAD_BUTTON', name: 'Fake Download Button',
    description: 'Download button linking to suspicious file type or external host',
    defaultScore: 18, tags: ['social-engineering','malware'],
    detect(ctx) {
      const links = document.querySelectorAll('a[href], button[onclick]');
      const suspiciousExts = /\.(exe|msi|bat|cmd|ps1|vbs|scr|hta|jar|iso|img|dmg)\b/i;
      for (const el of links) {
        const text = (el.textContent || '').toLowerCase();
        const href = el.getAttribute('href') || el.getAttribute('onclick') || '';
        if (/download|install|update|patch|fix/i.test(text) && suspiciousExts.test(href))
          return { description: 'Download button linking to suspicious file type', evidence: `"${text.trim().substring(0, 40)}" → ${href.substring(0, 80)}` };
      }
      return null;
    }
  });
})();
