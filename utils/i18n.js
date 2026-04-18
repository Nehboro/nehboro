// ============================================================
// Nehboro - utils/i18n.js
// Custom translation dictionary and helper
// ============================================================

window.NehboroI18n = (function() {
  const translations = {
    en: {
      // Header & Navigation
      "brand_tag": "Triple-Engine Threat Protection",
      "tab_status": "Shield",
      "tab_feeds": "IOC Feeds",
      "tab_scores": "Heuristic",
      "tab_settings": "Config",
      
      // Status Tab
      "protection_summary": "Protection summary",
      "blocked": "Blocked",
      "warned": "Warned",
      "reported": "Reported",
      "iocs_loaded": "IOCs loaded",
      "scan_btn": "⟳ Scan",
      "ai_scan_btn": "🤖 Scan with AI",
      "actions_page": "Actions for this page",
      "report_page": "Report Page",
      "trust_domain": "✓ Trust Domain",
      "trust_domain_context": "Trust this domain (Nehboro)",
      "scanning": "Scanning...",
      "no_threats": "No Threats Detected",
      "trusted_domain": "Trusted Domain",
      "clean": "CLEAN",
      "pass": "PASS",
      "hit": "HIT",
      "ioc_engine": "IOC Engine",
      "heuristic_engine": "Heuristic Engine",
      "no_feed_match": "No feed match",
      "no_detections": "No detections",
      "detections_count": "Detections",
      "threat_score": "Threat Score",
      "extracted_urls": "Extracted URLs",
      "filter_urls": "Filter URLs...",
      "copy_all": "Copy all",
      
      // IOC Feeds Tab
      "static_ioc_engine": "Static IOC Engine",
      "ioc_info_box": "Focused on known scam and phishing domains, URLs, IPs, and ports - blocked <strong>before page load</strong> using community-maintained threat feeds via declarativeNetRequest rules.",
      "ioc_note": "<strong>Note:</strong> Chrome caps the number of static IOC rules per extension, so this engine is a supplementary layer. The <strong>dynamic heuristic engine</strong> (Dynamic tab) is the main feature - it analyzes every page in real time and catches threats that aren't in any feed yet.",
      "default_feeds": "Default feeds",
      "custom_feeds": "Custom feeds",
      "no_custom_feeds": "No custom feeds added.",
      "add_feed": "Add feed",
      "feed_name": "Feed name",
      "feed_url_placeholder": "https://raw.githubusercontent.com/...",
      "feed_type": "IOC type",
      "domains": "Domains",
      "urls": "URLs",
      "ips": "IP addresses / CIDR",
      "ports": "Ports / Port ranges",
      "add_feed_btn": "+ Add Feed",
      "refresh_now": "⟳ Refresh Now",
      "feed_coverage": "Feed coverage",
      "raw_url": "Raw URL (.txt / .csv / .json)",
      "ioc_type": "IOC type",
      "loading": "Loading...",
      "loading_detections": "Loading detections...",
      "feed_removed": "Feed removed and rules refreshed.",
      "please_enter_url": "Please enter a URL.",
      "invalid_url": "Invalid URL.",
      "adding": "Adding...",
      "feed_added": "Feed added! {total} custom feed(s) active.",
      "error_adding_feed": "Error adding feed.",
      "refreshing": "Refreshing...",
      "feeds_refreshed": "Feeds refreshed!",
      "last_refresh": "Last refresh",
      
      // Dynamic Tab
      "dynamic_analysis_engine": "Dynamic Analysis Engine",
      "search_detections": "Search detections...",
      "dynamic_info_box": "Scans every page <strong>after load</strong> using 94+ heuristic detections: ClickFix sequences, PowerShell payloads, fake CAPTCHAs, clipboard hijacks, credential harvesting, lookalike domains, visual brand impersonation, <strong>tech support scams</strong> (fake errors, dialog spam, phone scams, fake OS UI, data theft scare), <strong>multilingual detection</strong> (EN/FR/ES/DE/IT), Browser-in-Browser attacks, formjacking, and more. Adjust individual detection scores below.",
      "save_scores": "Save Scores",
      "reset_all": "Reset All",
      
      // Config/Settings Tab
      "claude_ai_analysis": "Claude AI Analysis",
      "ai_info_box": "Optional third engine powered by <strong>Anthropic Claude</strong>. Sends page metadata for threat analysis. No raw HTML or user data is sent.",
      "api_key_label": "Anthropic API Key",
      "model_label": "Model",
      "custom_model": "Custom model...",
      "save_ai_btn": "Save Claude API Key",
      "clear_btn": "Clear",
      "thresholds": "Thresholds",
      "warning_threshold": "Warning threshold",
      "block_threshold": "Block threshold",
      "show_banners": "Show warning banners",
      "auto_report": "Auto-report blocked pages",
      "save_btn": "Save",
      "silent_mode": "Silent Mode",
      "silent_mode_info": "<strong>For non-technical users.</strong> Dangerous pages are quietly closed and replaced with a blank tab.",
      "enable_silent_mode": "Enable Silent Mode",
      "silent_mode_active": "Silent mode is active. Block threshold is set to 99. Dangerous pages are closed automatically.",
      "data_section": "Data",
      "export_history": "Export History",
      "reset_stats": "Reset Stats",
      "trusted_domains": "Trusted domains",
      "no_trusted_domains": "No trusted domains yet.",
      "remove": "Remove",
      "settings_saved": "Settings saved.",
      "warning_must_lower": "Warning must be lower than block.",
      "no_scan_history": "No scan history to export.",
      "reset_stats_confirm": "Reset all stats to zero?",
      "stats_cleared": "Stats cleared.",
      "report_this_page": "🚩 Report this page",
      "domain_trusted": "✅ {domain} trusted.",
      "reset_scores_confirm": "Reset all detection scores to defaults?",
      "all_scores_reset": "All scores reset to defaults.",
      "claude_ai_enabled": "Claude AI enabled ({model}).",
      "claude_api_key_cleared": "Claude API key cleared.",
      "confidence": "Confidence",
      "threat": "Threat",
      "explanation": "Explanation",
      "cannot_scan_restricted": "Cannot scan this page (restricted).",
      "scan_failed": "Scan failed - reload and retry.",
      "no_threats_found": "No threats found.",
      "cannot_scan": "Cannot scan this page.",
      "claude_analyzing": "🤖 Claude analyzing...",
      "ai_verdict": "Claude verdict: {verdict}",
      "ai_failed": "AI analysis failed.",
      "language": "Language",
      "threat_score": "Threat score",
      "show_all": "Show all",
      "matched_keywords": "matched keywords",
      "no_custom_feeds": "No custom feeds added.",
      "silent_mode_on": "Silent mode enabled.",
      "silent_mode_off": "Silent mode disabled.",
      "detections_registered": "detections registered",
      "default": "default",
      "saved_count": "Saved! {count} custom score(s) active.",
      "api_key_required": "Enter an Anthropic API key.",
      "api_key_placeholder": "sk-ant-...",
      "model_custom_placeholder": "e.g. claude-sonnet-4-20250514",
      "community_threat_intel": "Community Threat Intelligence",
      "ai_engine": "AI",
      "off": "OFF",
      "english": "English",
      "french": "Français",
      
      // Blocked Page
      "threat_blocked": "Threat Blocked",
      "prevented_access": "Nehboro prevented you from accessing a dangerous page.",
      "blocked_url": "Blocked URL",
      "threat_score_label": "Threat Score",
      "block_desc": "This page exceeded the threat threshold, indicating a high likelihood of phishing, scam, or malware delivery.",
      "go_back": "Go Back",
      "report_threat": "Report Threat",
      "proceed_understand": "I understand the risk - let me proceed",
      "proceed_warning": "Proceeding exposes you to credential theft, malware, or scam. This page was flagged by community threat intelligence and heuristic analysis.",
      "proceed_anyway": "⚠️ Proceed anyway (not recommended)",
      "threat_blocked_desc": "Nehboro prevented you from accessing a dangerous page.",
      "retrieving_url": "Retrieving URL…",
      "threat_description": "This page exceeded the threat threshold, indicating a high likelihood of phishing, scam, or malware delivery.",
      "threat_description_dynamic": "{hostname} was flagged with a threat score of {score} - above the block threshold of {threshold}. This strongly indicates phishing, scam, or malware delivery.",
      "block_at": "Block",
      "detections": "Detections",
      "expand_all": "Expand all",
      "collapse_all": "Collapse all",
      "detection_categories": "Detection categories",
      "proceed_anyway_short": "I understand the risk - let me proceed",
      "matched_content": "Matched content",
      "sending": "Sending",
      "report_sent": "Report Sent",
      "queued": "Queued (offline)",
      "registering_exception": "Registering exception",
      "url_not_available": "URL not available",
      "no_url_to_proceed": "No URL to proceed to",
      "protected_by": "Protected by"
    },
    fr: {
      // Header & Navigation
      "brand_tag": "Protection contre les menaces à triple moteur",
      "tab_status": "Bouclier",
      "tab_feeds": "Flux d'IOC",
      "tab_scores": "Heuristique",
      "tab_settings": "Config",
      
      // Status Tab
      "protection_summary": "Résumé de la protection",
      "blocked": "Bloqués",
      "warned": "Avertis",
      "reported": "Signalés",
      "iocs_loaded": "IOC chargés",
      "scan_btn": "⟳ Analyser",
      "ai_scan_btn": "🤖 Analyser avec l'IA",
      "actions_page": "Actions pour cette page",
      "report_page": "Signaler la page",
      "trust_domain": "✓ Faire confiance",
      "trust_domain_context": "Faire confiance à ce domaine (Nehboro)",
      "scanning": "Analyse en cours...",
      "no_threats": "Aucune menace détectée",
      "trusted_domain": "Domaine de confiance",
      "clean": "PROPRE",
      "pass": "RAS",
      "hit": "ALERTE",
      "ioc_engine": "Moteur IOC",
      "heuristic_engine": "Moteur Heuristique",
      "no_feed_match": "Aucune correspondance",
      "no_detections": "Aucune détection",
      "detections_count": "Détections",
      "threat_score": "Score de menace",
      "extracted_urls": "URLs extraites",
      "filter_urls": "Filtrer les URLs...",
      "copy_all": "Tout copier",
      
      // IOC Feeds Tab
      "static_ioc_engine": "Moteur IOC Statique",
      "ioc_info_box": "Cible les domaines, URLs, IPs et ports connus pour le phishing et les arnaques - bloqués <strong>avant le chargement</strong> via des flux communautaires via les règles declarativeNetRequest.",
      "ioc_note": "<strong>Note :</strong> Chrome limite le nombre de règles statiques. Ce moteur est une couche supplémentaire. Le <strong>moteur heuristique dynamique</strong> (onglet Heuristique) est la fonction principale - il analyse chaque page en temps réel.",
      "default_feeds": "Flux par défaut",
      "custom_feeds": "Flux personnalisés",
      "no_custom_feeds": "Aucun flux personnalisé ajouté.",
      "add_feed": "Ajouter un flux",
      "feed_name": "Nom du flux",
      "feed_url_placeholder": "https://raw.githubusercontent.com/...",
      "feed_type": "Type d'IOC",
      "domains": "Domaines",
      "urls": "URLs",
      "ips": "Adresses IP / CIDR",
      "ports": "Ports / Plages de ports",
      "add_feed_btn": "+ Ajouter le flux",
      "refresh_now": "⟳ Actualiser maintenant",
      "feed_coverage": "Couverture des flux",
      "raw_url": "URL brute (.txt / .csv / .json)",
      "ioc_type": "Type d'IOC",
      "loading": "Chargement...",
      "loading_detections": "Chargement des détections...",
      "feed_removed": "Flux supprimé et règles actualisées.",
      "please_enter_url": "Veuillez entrer une URL.",
      "invalid_url": "URL invalide.",
      "adding": "Ajout en cours...",
      "feed_added": "Flux ajouté ! {total} flux personnalisé(s) actif(s).",
      "error_adding_feed": "Erreur lors de l'ajout du flux.",
      "refreshing": "Actualisation en cours...",
      "feeds_refreshed": "Flux actualisés !",
      "last_refresh": "Dernière actualisation",
      
      // Dynamic Tab
      "dynamic_analysis_engine": "Moteur d'Analyse Dynamique",
      "search_detections": "Rechercher des détections...",
      "dynamic_info_box": "Analyse chaque page <strong>après chargement</strong> via 94+ détections heuristiques : séquences ClickFix, payloads PowerShell, faux CAPTCHAs, détournement de presse-papiers, vol d'identifiants, domaines similaires, usurpation visuelle de marque, <strong>arnaques au support technique</strong> (faux messages d'erreur, spam de dialogues, arnaques téléphoniques, faux UI système, chantage au vol de données), <strong>détection multilingue</strong> (EN/FR/ES/DE/IT), attaques Browser-in-Browser, formjacking, etc. Ajustez les scores ci-dessous.",
      "save_scores": "Enregistrer les scores",
      "reset_all": "Tout réinitialiser",
      
      // Config/Settings Tab
      "claude_ai_analysis": "Analyse IA Claude",
      "ai_info_box": "Troisième moteur optionnel via <strong>Anthropic Claude</strong>. Envoie les métadonnées de la page pour analyse. Aucun HTML brut ou donnée utilisateur n'est envoyé.",
      "api_key_label": "Clé API Anthropic",
      "model_label": "Modèle",
      "custom_model": "Modèle personnalisé...",
      "save_ai_btn": "Enregistrer la clé API",
      "clear_btn": "Effacer",
      "thresholds": "Seuils",
      "warning_threshold": "Seuil d'avertissement",
      "block_threshold": "Seuil de blocage",
      "show_banners": "Afficher les bannières",
      "auto_report": "Auto-signalement des pages bloquées",
      "save_btn": "Enregistrer",
      "silent_mode": "Mode Silencieux",
      "silent_mode_info": "<strong>Pour les utilisateurs non-techniques.</strong> Les pages dangereuses sont fermées silencieusement et remplacées par un onglet vide.",
      "enable_silent_mode": "Activer le mode silencieux",
      "silent_mode_active": "Le mode silencieux est actif. Le seuil de blocage est à 99. Les pages dangereuses sont fermées automatiquement.",
      "data_section": "Données",
      "export_history": "Exporter l'historique",
      "reset_stats": "Réinitialiser les stats",
      "trusted_domains": "Domaines de confiance",
      "no_trusted_domains": "Aucun domaine de confiance pour le moment.",
      "remove": "Supprimer",
      "settings_saved": "Paramètres enregistrés.",
      "warning_must_lower": "L'avertissement doit être inférieur au blocage.",
      "no_scan_history": "Aucun historique à exporter.",
      "reset_stats_confirm": "Réinitialiser toutes les statistiques à zéro ?",
      "stats_cleared": "Statistiques effacées.",
      "report_this_page": "🚩 Signaler cette page",
      "domain_trusted": "✅ {domain} est désormais de confiance.",
      "reset_scores_confirm": "Réinitialiser tous les scores de détection ?",
      "all_scores_reset": "Tous les scores ont été réinitialisés.",
      "claude_ai_enabled": "IA Claude activée ({model}).",
      "claude_api_key_cleared": "Clé API Claude effacée.",
      "confidence": "Confiance",
      "threat": "Menace",
      "explanation": "Explication",
      "cannot_scan_restricted": "Impossible d'analyser cette page (restreinte).",
      "scan_failed": "L'analyse a échoué - rechargez et réessayez.",
      "no_threats_found": "Aucune menace trouvée.",
      "cannot_scan": "Impossible d'analyser cette page.",
      "claude_analyzing": "🤖 Claude analyse en cours...",
      "ai_verdict": "Verdict de Claude : {verdict}",
      "ai_failed": "L'analyse IA a échoué.",
      "language": "Langue",
      "threat_score": "Score de menace",
      "show_all": "Afficher tout",
      "matched_keywords": "mots-clés trouvés",
      "no_custom_feeds": "Aucun flux personnalisé ajouté.",
      "silent_mode_on": "Mode silencieux activé.",
      "silent_mode_off": "Mode silencieux désactivé.",
      "detections_registered": "détections enregistrées",
      "default": "défaut",
      "saved_count": "Enregistré ! {count} score(s) personnalisé(s) actif(s).",
      "api_key_required": "Veuillez entrer une clé API Anthropic.",
      "api_key_placeholder": "sk-ant-...",
      "model_custom_placeholder": "ex: claude-sonnet-4-20250514",
      "community_threat_intel": "Intelligence communautaire sur les menaces",
      "ai_engine": "IA",
      "off": "DÉSACTIVÉ",
      "english": "English",
      "french": "Français",
      
      // Blocked Page
      "threat_blocked": "Menace Bloquée",
      "prevented_access": "Nehboro vous a empêché d'accéder à une page dangereuse.",
      "blocked_url": "URL Bloquée",
      "threat_score_label": "Score de Menace",
      "block_desc": "Cette page a dépassé le seuil de menace, indiquant une forte probabilité de phishing, d'arnaque ou de malware.",
      "go_back": "Retourner",
      "report_threat": "Signaler la menace",
      "proceed_understand": "Je comprends les risques - continuer",
      "proceed_warning": "Continuer vous expose au vol de vos identifiants, à des logiciels malveillants ou à des arnaques. Cette page a été signalée par l'intelligence communautaire sur les menaces et l'analyse heuristique.",
      "proceed_anyway": "⚠️ Continuer quand même (non recommandé)",
      "threat_blocked_desc": "Nehboro vous a empêché d'accéder à une page dangereuse.",
      "retrieving_url": "Récupération de l'URL…",
      "threat_description": "Cette page a dépassé le seuil de menace, indiquant une forte probabilité de phishing, d'arnaque ou de malware.",
      "threat_description_dynamic": "{hostname} a été signalé avec un score de menace de {score} - au-dessus du seuil de blocage de {threshold}. Cela indique fortement du phishing, une arnaque ou la livraison de malware.",
      "block_at": "Seuil",
      "detections": "Détections",
      "expand_all": "Tout afficher",
      "collapse_all": "Tout réduire",
      "detection_categories": "Catégories de détection",
      "proceed_anyway_short": "Je comprends les risques - continuer",
      "matched_content": "Contenu correspondant",
      "sending": "Envoi en cours",
      "report_sent": "Signalement envoyé",
      "queued": "En attente (hors ligne)",
      "registering_exception": "Enregistrement de l'exception",
      "url_not_available": "URL non disponible",
      "no_url_to_proceed": "Aucune URL vers laquelle continuer",
      "protected_by": "Protégé par"
    }
  };
 streams: {} 

  let currentLang = 'en';

  function init(lang) {
    if (translations[lang]) {
      currentLang = lang;
    }
  }

  function t(key, placeholders = {}) {
    if (!translations[currentLang]) return key;
    let val = translations[currentLang][key] || translations['en'][key] || key;
    
    // Simple placeholder replacement: {name} -> placeholders.name
    Object.keys(placeholders).forEach(p => {
      val = val.replace(new RegExp(`\\{${p}\\}`, 'g'), placeholders[p]);
    });
    return val;
  }

  function applyTranslations(container = document) {
    const _t = t;
    // Standard translations
    container.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = _t(key);
      if (val !== key) {
        // If it looks like HTML, use innerHTML, otherwise textContent
        if (val.includes('<') && val.includes('>')) {
          el.innerHTML = val;
        } else {
          if (el.childNodes.length <= 1) {
            el.textContent = val;
          } else {
            // Respect existing child structure (e.g. icons) if only updating leading text
            const textNode = [...el.childNodes].find(n => n.nodeType === 3);
            if (textNode) textNode.textContent = val;
          }
        }
      }
    });

    // Placeholders
    container.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = _t(key);
      if (val !== key) el.placeholder = val;
    });

    // Language selector sync
    const langSelect = container.querySelector('#select-lang');
    if (langSelect) langSelect.value = currentLang;
  }

  function getLanguage() {
    return currentLang;
  }

  return {
    init,
    t,
    applyTranslations,
    getLanguage,
    availableLanguages: ['en', 'fr']
  };
})();
