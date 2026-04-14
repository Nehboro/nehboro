// ============================================================
// Nehboro - utils/patterns.js  v2
// All 45 ClickGrab techniques, context-aware scoring.
// WARN=45, BLOCK=79 - requires corroborating signals.
// ============================================================

var NW_PATTERNS = NW_PATTERNS || {

  THRESHOLD: { WARN: 45, BLOCK: 79 },

  SCORES: {
    FEED_MATCH:                        100,
    CLIPBOARD_LIVE_PAYLOAD:             70,
    CLICKFIX_FULL_SEQUENCE:             45,
    POWERSHELL_ENCODED:                 40,
    STEGANOGRAPHY:                      48,
    WINHTTP_FULL:                       50,
    MACOS_SHELL:                        48,
    FAKE_CLOUDFLARE_DOMAIN:             38,
    LOLBIN_IN_CONTEXT:                  35,
    DNS_CLICKFIX:                       35,
    WEBDAV_MOUNT:                       35,
    CONSENTFIX:                         38,
    FINGER_ABUSE:                       32,
    CRASHFIX:                           30,
    PHISHING_IMPERSONATION:             35,
    CLICKFIX_PARTIAL:                   25,
    CLIPBOARD_SOURCE:                   18,
    POWERSHELL_PARTIAL:                 18,
    OBFUSCATION_HEAVY:                  18,
    LLM_ARTIFACT_ABUSE:                 18,
    HEX_IP:                             25,
    FILEFIX:                            25,
    SUSPICIOUS_HOST:                    20,
    FAKE_CLOUDFLARE_TEXT:               12,
    FAKE_MEETING:                       15,
    FAKE_UPDATE:                        15,
    FAKE_SOFTWARE_DL:                   15,
    WINHTTP_PARTIAL:                    15,
    SUSPICIOUS_REDIRECT:                12,
    FAKE_SOCIAL_PROOF:                   8,
    URGENCY:                             5,  // per phrase, min 3 phrases
    SUSPICIOUS_TERM:                     2,  // per term, min 8 terms, max 20
    // Combination bonuses
    BONUS_CLIPBOARD_INSTRUCTION:        20,
    BONUS_LOLBIN_INSTRUCTION:           15,
    BONUS_CAPTCHA_INSTRUCTION:          12,
    BONUS_PS_CLIPBOARD:                 20, // clipboard write + encoded PS = definitive ClickFix
  },

  // ── ClickFix instruction parts ────────────────────────────
  CF_OPEN: [
    /press\s+(?:the\s+)?(?:windows|win)\s*(?:key\s*)?[+&]\s*r\b/i,
    /(?:windows|win)\s*\+\s*r\b/i,
    /open\s+(?:the\s+)?run\s+(?:dialog|box|window)/i,
    /open\s+(?:a\s+)?(?:command\s+prompt|terminal|powershell|file\s+explorer)/i,
    /launch\s+(?:a\s+)?(?:terminal|command\s+prompt|cmd)\b/i,
    /press\s+(?:the\s+)?(?:windows|win)\s*\+\s*x.*?then.*?\bi\b/i,
    /(?:windows|win)\s*(?:key\s*)?\+\s*x\b/i,              // standalone Win+X (Image 7)
    /(?:command|cmd|⌘)\s*\+\s*space/i,
    /open\s+(?:spotlight|terminal\.app)/i,
    /spotlight\s+search/i,                                  // "Spotlight Search" (Image 3)
    /search\s+for\s+(?:the\s+)?(?:\*\*)?terminal(?:\*\*)?/i, // "Search for Terminal" (Image 3)
    /type\s+terminal\s+(?:and\s+)?press\s+enter/i,
    /(?:ctrl|control)\s*\+\s*(?:alt|option)\s*\+\s*t\b/i,
    /select(?:ione)?\s+['"]?windows\s+powershell\s*\(?admin\)?['"]?/i, // "Seleccione 'Windows PowerShell (Admin)'" (Image 1)
    /choose\s+(?:terminal|powershell)/i,                    // "choose Terminal/PowerShell" (Image 7)
  ],
  CF_PASTE: [
    /(?:ctrl|control)\s*\+\s*v\b/i,
    /(?:command|cmd|⌘)\s*\+\s*v\b/i,
    /paste\s+(?:it|the\s+command|below|this|that)/i,
    /\bctrl\s*\+\s*v\b/i,
  ],
  CF_EXECUTE: [
    /press\s+enter/i,
    /click\s+(?:ok|run|execute|yes|confirm)\b/i,
    /hit\s+enter/i,
    /then\s+(?:press\s+)?enter/i,
  ],

  // ── LOLBin patterns (all ClickGrab techniques) ────────────
  LOLBIN_ALL: [
    // Scripting
    /\bpowershell(?:\.exe)?\b/i, /\bcmd(?:\.exe)?\s+\/c\b/i,
    /\bwscript(?:\.exe)?\b/i,   /\bcscript(?:\.exe)?\b/i,
    /\bmshta(?:\.exe)?\b/i,     /\bosascript\b/i,
    // Download/decode
    /\bcertutil(?:\.exe)?\b/i,  /\bcertreq(?:\.exe)?\b/i,
    /\bbitsadmin(?:\.exe)?\b/i, /\bftp(?:\.exe)?\b/i,
    /\bnslookup(?:\.exe)?\b/i,  /\bfinger(?:\.exe)?\b/i,
    // Build/assembly
    /\bmsbuild(?:\.exe)?\b/i,   /\bregasm(?:\.exe)?\b/i,
    /\bregsvcs(?:\.exe)?\b/i,   /\bregsvr32(?:\.exe)?\b/i,
    /\brundll32(?:\.exe)?\b/i,  /\binstallutil(?:\.exe)?\b/i,
    // UI tools with dialogs
    /\bcompMgmtLauncher(?:\.exe)?\b/i, /\bdxdiag(?:\.exe)?\b/i,
    /\bfileHistory(?:\.exe)?\b/i,      /\bMRT(?:\.exe)?\b/i,
    /\beventvwr(?:\.exe)?\b/i,  /\bcolorcpl(?:\.exe)?\b/i,
    /\bcredwiz(?:\.exe)?\b/i,   /\bdcomcnfg(?:\.exe)?\b/i,
    /\bperfmon(?:\.exe)?\b/i,   /\btaskmgr(?:\.exe)?\b/i,
    /\bmsra(?:\.exe)?\b/i,      /\bfsquirt(?:\.exe)?\b/i,
    // Extract/install
    /\bwextract(?:\.exe)?\b/i,  /\biexpress(?:\.exe)?\b/i,
    /\bwusa(?:\.exe)?\b/i,      /\bmsiexec(?:\.exe)?\b/i,
    // Shell/Windows features
    /\bforfiles(?:\.exe)?\b/i,  /\bwt(?:\.exe)?\b/i,
    /\bconhost(?:\.exe)?\b/i,   /\blaunchWinApp(?:\.exe)?\b/i,
    /\bssh(?:\.exe)?\b/i,
    /\bnet\s+use\b/i,           /\bdavwwwroot\b/i,
    /shell:startup\b/i,         /search-ms:/i,
    /ms-word:|ms-excel:|ms-powerpoint:/i,
    /dfshim\.dll\b/i,
  ],

  // ── PowerShell encoded ───────────────────────────────────
  // High-confidence PS patterns - require >=3 for ENCODED verdict.
  // Each pattern here requires actual payload/download CONTEXT, not just keywords.
  // iex(), -WindowStyle, -ExecutionPolicy alone are too common on security sites.
  PS_ENCODED: [
    /-(?:e|enc|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i,   // base64 payload present
    /\[convert\]::frombase64string/i,
    /FromBase64String\s*\([^)]{8,}/i,                            // non-trivial decode
    /DownloadString\s*\(['"]https?:\/\//i,                     // download from URL
    /DownloadFile\s*\(['"]https?:\/\//i,
    /New-Object\s+Net\.WebClient.*(?:\.Download|\.OpenRead)/i,
    /\bIWR\b\s+https?:\/\/[^\s'"]{10,}/i,                   // IWR with actual URL
    /Invoke-WebRequest\s+.*https?:\/\/[^\s'"]{10,}/i,
    /System\.Net\.WebClient.*\.(?:DownloadString|DownloadFile)/i,
    /Start-BitsTransfer\s+.*https?:\/\//i,
  ],

  PS_PARTIAL: [
    /-(?:e|enc|encode|encodedcommand)\s+[A-Za-z0-9+/=]{4,}/i,    // encoded cmd (any length)
    /\biex\s*\(/i,
    /\binvoke-expression\b/i,
    /-WindowStyle\s+(?:Hidden|0)\b/i,
    /-ExecutionPolicy\s+(?:Bypass|Unrestricted)\b/i,
    /\bpowershell(?:\.exe)?\s+.*-(?:nop|noprofile)\b/i,
    /Start-Process\s+.*powershell/i,
    /\bAdd-Type\b.*-TypeDefinition/i,
    /Invoke-WebRequest\b/i,
    /New-Object\s+Net\.WebClient/i,
    /System\.Net\.WebClient/i,
  ],

  // ── Runtime clipboard dangerous payload patterns ──────────
  CLIPBOARD_DANGEROUS: [
    /powershell/i, /cmd\.exe/i, /mshta/i, /wscript/i,
    /certutil/i, /rundll32/i, /regsvr32/i, /msbuild/i,
    /forfiles/i, /iex\s*\(/i, /invoke-expression/i,
    /-encodedcommand/i, /downloadstring/i,
    /system\.net\.webclient/i,
    /curl\s+.*\|\s*(?:ba)?sh/i, /osascript/i,
    /nslookup\s+.*\d{1,3}\.\d/i, /net\s+use\s+[A-Z]:/i,
    /finger\s+\S+@\S+/i, /wt\.exe/i,
    /\.ps1\b/i, /\.hta\b/i, /\.vbs\b/i,
  ],

  // ── Clipboard in source (static scan) ────────────────────
  CLIPBOARD_SOURCE: [
    /navigator\.clipboard\.writeText\s*\(/i,
    /document\.execCommand\s*\(\s*['"]copy['"]/i,
    /clipboardData\.setData\s*\(/i,
    /window\.__clipboard\s*=/i,
    /setClipboard\s*\(/i, /copyToClipboard\s*\(/i,
    /stageClipboard\s*\(/i,
    /commandToRun\s*=\s*[`'"]/i,
    /textToCopy\s*=\s*[`'"]/i,
  ],

  // ── Fake CAPTCHA text ─────────────────────────────────────
  CAPTCHA_TEXT: [
    /verif(?:y(?:ing)?|ication)\s+(?:you\s+are|that\s+you(?:'re)?)\s+human/i,
    /i\s+am\s+not\s+a\s+robot/i,
    /checking\s+(?:your\s+)?browser/i,
    /checking\s+if\s+the\s+site\s+connection\s+is\s+secure/i,
    /this\s+process\s+is\s+automatic/i,
    /one\s+more\s+step/i,
    /please\s+complete\s+the\s+security\s+check/i,
    /ddos\s+protection\s+by\s+cloudflare/i,
    /performance\s+&(?:amp;)?\s+security\s+by\s+cloudflare/i,
    /ray\s+id:\s*[a-f0-9]{16}/i,
    /your\s+browser\s+will\s+redirect/i,
    /additional\s+verification\s+required/i,
    /complete\s+(?:these\s+)?verification\s+steps/i,
    /to\s+better\s+prove\s+you\s+are\s+not\s+a\s+robot/i,
    /verification\s+steps?\s*:/i,
    /prove\s+(?:that\s+)?you\s+are\s+(?:not\s+a\s+robot|human)/i,
    /robot\s+or\s+human\s*\??/i,
    /(?:check|click|tick)\s+(?:the\s+)?box\s+to\s+confirm\s+(?:that\s+)?you(?:'re|\s+are)\s+human/i,
    /press\s+(?:&\s+)?hold\s+(?:the\s+)?windows\s+key/i,
    /in\s+the\s+(?:run|verification)\s+(?:box|dialog|window)/i,
  ],

  // ── Cloudflare typosquats ─────────────────────────────────
  CF_DOMAINS: [
    /cloudfarev\./i, /cloudflarev\./i, /cloudflre\./i, /cloudf1are\./i,
    /cl0udflare\./i, /cloudflaire\./i, /cloudflare-verify\./i,
    /cloudflare-check\./i, /cf-challenge\./i, /cloudflare-security\./i,
    /newcloudflare\./i, /cfverify\./i,
  ],

  // ── Fake meeting ──────────────────────────────────────────
  FAKE_MEETING: [
    /can[''`]?t\s+join\s+(?:the\s+)?meeting/i,
    /microphone\s+(?:not\s+)?(?:found|detected|access|working)/i,
    /camera\s+(?:not\s+)?(?:found|detected|access|working)/i,
    /gogl-meet\.|meet\.conference|googlemeet\.|google-meet\./i,
    /zoom-call\.|zoomcall\.|fake-zoom\./i,
  ],

  // ── Fake Windows Update ───────────────────────────────────
  FAKE_UPDATE: [
    /windows\s+update\s+(?:is\s+)?(?:required|needed|available|failed)/i,
    /please\s+wait\s+while\s+we\s+(?:install|update|configure)/i,
    /your\s+(?:pc|computer)\s+will\s+restart/i,
    /configuring\s+windows/i, /getting\s+windows\s+ready/i,
    /working\s+on\s+updates/i, /\bkb\d{6,}\b/i,
    /update\s+(?:failed|error)\s*(?:code)?/i,
  ],

  // ── macOS shell attacks ───────────────────────────────────
  MACOS_SHELL: [
    /curl\s+(?:-[a-zA-Z\s]+)*https?:\/\/[^\s'"]+\s*\|\s*(?:ba)?sh\b/i,
    /curl\s+[^|]+\|\s*osascript/i,
    /osascript\s+-e\s+['"`]/i, /do\s+shell\s+script\s+['"`]/i,
    /\/bin\/(?:ba)?sh\s+-c\s+['"`]/i,
    /wget\s+[^|]+\|\s*(?:ba)?sh\b/i,
    /curl\s+[^|]*-H\s+['"]api-key:/i,
    /\/tmp\/osalogging/i,
    /base64\s+-[dD]\s*\|\s*(?:ba)?sh/i,
  ],

  // ── Steganography ─────────────────────────────────────────
  STEGANOGRAPHY: [
    /System\.Drawing\.Bitmap/i, /\bGetPixel\s*\(/i,
    /\bLockBits\s*\(/i, /Image\.FromStream/i,
    /\bBitmapData\b/i, /\bUnlockBits\s*\(/i,
    /\[System\.Drawing/i, /Reflection\.Assembly.*Load/i,
    /\bVirtualAlloc\b/i, /\bCreateThread\b/i,
  ],

  // ── WinHttp VBScript ──────────────────────────────────────
  WINHTTP_FULL: [
    /CreateObject\s*\(\s*['"]WinHttp\.WinHttpRequest/i,
    /WinHttp\.WinHttpRequest\.\d+\.\d+/i,
    /ExecuteGlobal\s+\w+\.ResponseText/i,
    /Execute\s+\w+\.ResponseText/i,
    /wscript\s+\/\/E:VBScript/i,
    /cmd\s*\/c\s+echo\s+Set\s+\w+=CreateObject/i,
  ],
  WINHTTP_PARTIAL: [
    /MSXML2\.XMLHTTP/i, /MSXML2\.ServerXMLHTTP/i,
    /Microsoft\.XMLHTTP/i, /\.ResponseText/i,
    /wscript.*%temp%.*\.vbs/i,
  ],

  // ── DNS ClickFix ─────────────────────────────────────────
  DNS_CLICKFIX: [
    /nslookup\s+\S+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
    /nslookup\s+-type=\w+\s+\S+/i,
    /nslookup[^|]*\|\s*(?:find|findstr|Select-String)/i,
    /for\s+\/f[^%]*%[^%]*in\s*\([^)]*nslookup/i,
  ],

  // ── WebDAV ───────────────────────────────────────────────
  WEBDAV: [
    /net\s+use\s+[A-Z]:\s+(?:https?:\/\/|\\\\.+\\)/i,
    /\/persistent:no\b/i, /net\s+use\s+[A-Z]:\s+\/delete/i,
    /davwwwroot/i, /\\\\[a-z0-9]+@(?:SSL\\|8080\\|443\\)/i,
    /\.asar\b/i,
  ],

  // ── Finger.exe / CrashFix ────────────────────────────────
  FINGER_ABUSE: [
    /finger(?:\.exe)?\s+[^\s]+@[^\s]+/i,
    /copy\s+[^"]*finger\.exe/i, /rename\s+[^"]*finger\.exe/i,
    /%temp%[^"]*\\(?:ct|finger)\.exe/i,
    /\bNexShield\b/i,
    /browser\s+(?:has\s+)?(?:stopped|crashed)\s+(?:abnormally|unexpectedly)/i,
  ],

  // ── ConsentFix ───────────────────────────────────────────
  CONSENTFIX: [
    /localhost:\d+\/(?:redirect|callback|auth)\?code=/i,
    /localhost:\d+[^\s]*access_token=/i,
    /copy.*(?:the\s+)?(?:url|address|link).*(?:from|in).*(?:browser|address\s*bar)/i,
    /paste.*(?:the\s+)?(?:url|address).*(?:below|here|into)/i,
    /\baz\s+login\b/i, /\bdevice\s+code\s+flow\b/i, /\bdevicelogin\b/i,
  ],

  // ── FileFix ──────────────────────────────────────────────
  FILEFIX: [
    /(?:open|click|select)\s+(?:the\s+)?(?:file\s+explorer|explorer|address\s+bar)/i,
    /paste\s+(?:it\s+)?into\s+(?:the\s+)?(?:address\s+bar|explorer)/i,
    /(?:file\s+explorer|control\s+panel).*address\s+bar/i,
    /address\s+bar.*(?:paste|type)\s+.*(?:powershell|cmd|command)/i,
  ],

  // ── Hex-encoded IP ────────────────────────────────────────
  HEX_IP: [
    /mshta\s+['"]?(?:https?:\/\/)?0x[0-9a-fA-F]+(?:\.|0x)/i,
    /(?:https?:\/\/)?(?:0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}/,
    /(?:https?:\/\/)?0x[0-9a-fA-F]{8}(?:\/|:)/,
  ],

  // ── LLM artifact abuse ───────────────────────────────────
  LLM_ARTIFACT: [
    /claude\.site\/[a-zA-Z0-9]+/i,  // unofficial claude.site only
    /chatgpt\.com\/share\/[a-zA-Z0-9-]+/i,
    /chat\.openai\.com\/share\/[a-zA-Z0-9-]+/i,
    /(?:copy|paste)\s+(?:this|the\s+following)\s+(?:command|code)\s+into\s+(?:your\s+)?terminal\s+to\s+(?:install|fix|resolve)/i,
  ],

  // ── Fake software downloads ───────────────────────────────
  FAKE_SOFTWARE: [
    /cleanmymac[^.]*\./i, /\bzkcall\b/i, /zk-call-messenger/i,
    /(?:ledger|exodus|atomic)\s+(?:live|wallet)[^\s]*(?:download|install|update)/i,
    /(?:download|install)\s+(?:the\s+)?(?:latest\s+)?(?:zoom|teams|slack|discord)\s+.*(?:fix|update|patch|repair)/i,
  ],

  // ── Heavy obfuscation ─────────────────────────────────────
  OBFUSCATION: [
    /_0x[a-f0-9]{4,8}\s*=\s*function\s*\(\s*_0x[a-f0-9]+/i,
    /const\s+_0x[a-f0-9]+\s*=\s*\[\s*['""][^'""]{100,}/,
    /setInterval\s*\([^)]*debugger/i,
    /eval\s*\(\s*(?:atob|unescape)\s*\(/i,
    /String\.fromCharCode\s*\([^)]{60,}\)/i,
    /_0x[a-f0-9]+\s*\(\s*_0x[a-f0-9]+\s*\(\s*_0x[a-f0-9]+/,
  ],

  // ── Urgency phrases ───────────────────────────────────────
  URGENCY: [
    /(?:act|respond)\s+(?:now|immediately|urgently)/i,
    /account\s+(?:will\s+be\s+|has\s+been\s+)?(?:suspended|blocked|terminated|disabled)/i,
    /suspicious\s+(?:activity|login|access)\s+(?:detected|found|identified)/i,
    /your\s+(?:computer|pc|device|account)\s+(?:is\s+)?(?:infected|compromised|at\s+risk|hacked)/i,
    /verify\s+your\s+(?:identity|account)\s+(?:now|immediately|to\s+continue)/i,
    /\baction\s+required\b/i,
    /your\s+access\s+(?:has\s+been\s+|will\s+be\s+)?(?:suspended|revoked|blocked)/i,
  ],

  // ── Suspicious keyword set ────────────────────────────────
  SUSPICIOUS_TERMS: new Set([
    'invoke-expression','iex(','downloadstring','invoke-webrequest',
    'system.net.webclient','-encodedcommand','-executionpolicy bypass',
    '-windowstyle hidden','certutil -urlcache','certutil -decode',
    'mshta.exe','regsvr32','rundll32','msbuild.exe','forfiles',
    'wscript.exe','cscript.exe','bitsadmin','installutil','regasm',
    'osascript','curl | bash','curl | sh','/bin/bash -c','do shell script',
    'winhttprequest','executeglobal','xmlhttp','responsetext',
    'system.drawing.bitmap','getpixel(','lockbits(','virtualalloc',
    'createthread','assembly.load','reflection.assembly',
    'lumma','lummac2','redline','vidar','raccoon','amos',
    'nslookup','finger.exe','wt.exe','net use','webdav','davwwwroot',
    'modelorat','mimicrat','odyssey','macsync','shub',
    'crashfix','consentfix','.asar','devicelogin','nexshield','kongtuke',
  ]),

    SAFE_DOMAINS: new Set([
    // 1105 trusted domains - top global websites by traffic
    // Excludes: CDNs, hosting platforms, user-generated content sites, file sharing
    '1password.com','7news.com.au','aa.com','abc.es','abc.net.au','abcnews.go.com',
    'about.gitlab.com','academia.edu','accor.com','accounts.google.com','accuweather.com','acm.org',
    'addons.mozilla.org','adidas.com','admin.microsoft.com','admob.google.com','adobe.com','ads.google.com',
    'adyen.com','ahrefs.com','ai21.com','airbnb.com','airfrance.com','airtable.com',
    'akamai.com','alibaba.com','aliexpress.com','aljazeera.com','allegro.pl','ally.com',
    'amazon.ca','amazon.co.jp','amazon.co.uk','amazon.com','amazon.com.au','amazon.com.br',
    'amazon.com.mx','amazon.de','amazon.es','amazon.fr','amazon.in','amazon.it',
    'amazon.nl','amazon.pl','amazon.se','amazon.sg','amd.com','americanexpress.com',
    'analytics.google.com','anandtech.com','angel.co','angular.io','anilist.co','animate.style',
    'ansa.it','ansible.com','answers.microsoft.com','anthropic.com','any.run','aol.com',
    'apache.org','apartments.com','apnews.com','app.slack.com','app.zoom.us','appetize.io',
    'apple.com','appwrite.io','archive.ph','archlinux.org','argos.co.uk','arstechnica.com',
    'arxiv.org','asahi.com','asana.com','ask.com','asos.com','astro.build',
    'asus.com','atlassian.com','attack.mitre.org','audible.com','aur.archlinux.org','australia.gov.au',
    'auth0.com','aws.amazon.com','aws.training','axios.com','azlyrics.com','azure.microsoft.com',
    'azure.status.microsoft.com','babbel.com','backblaze.com','baidu.com','bananrepublic.com','bandcamp.com',
    'bandsintown.com','bankofamerica.com','bankrate.com','barclays.co.uk','bard.google.com','basecamp.com',
    'bathandbodyworks.com','bbb.org','bbc.co.uk','bbc.com','behance.net','berkeley.edu',
    'bestbuy.com','bhphotovideo.com','bigcommerce.com','bild.de','bilibili.com','binance.com',
    'bing.com','bit.ly','bitbucket.org','bitrise.io','bitwarden.com','bleacherreport.com',
    'bleepingcomputer.com','blibli.com','blizzard.com','bloomberg.com','bluesky.social','bnpparibas.com',
    'bolt.eu','booking.com','box.com','braintreepayments.com','brave.com','brilliant.org',
    'britannica.com','britishairways.com','broadcom.com','brown.edu','browserstack.com','bsky.app',
    'bubble.io','buffer.com','bukalapak.com','bulma.io','bund.de','bundesregierung.de',
    'burgerking.com','business.facebook.com','businessinsider.com','buzzfeed.com','cal.com','calendar.google.com',
    'calendly.com','calm.com','caltech.edu','cam.ac.uk','camelcamelcamel.com','canada.ca',
    'caniuse.com','canva.com','capacitorjs.com','capitalone.com','capterra.com','carousell.com',
    'cashapp.com','cbc.ca','cbsnews.com','cdc.gov','cdiscount.com','certbot.eff.org',
    'challenges.cloudflare.com','channel9.msdn.com','chase.com','chat.google.com','chat.openai.com','chatgpt.com',
    'chewy.com','chickfila.com','chipotle.com','chrome.google.com','circleci.com','cisco.com',
    'citibank.com','claude.ai','cleanup.pictures','clevelandclinic.org','clickup.com','clipchamp.com',
    'cloud.google.com','cloud.oracle.com','cloudflare.com','cmu.edu','cnbc.com','cnet.com',
    'cnn.com','coda.io','code.visualstudio.com','codecademy.com','cohere.com','coinbase.com',
    'colab.research.google.com','collegeboard.org','columbia.edu','commerce.gov','commerzbank.de','commonapp.org',
    'confluence.com','congress.gov','connectedpapers.com','console.anthropic.com','console.aws.amazon.com','console.cloud.google.com',
    'constantcontact.com','context.reverso.net','copr.fedorainfracloud.org','cornell.edu','corriere.it','costco.com',
    'coupang.com','coursera.org','cppreference.com','craigslist.org','crates.io','crazydomains.com',
    'creativecommons.org','creditkarma.com','criterionchannel.com','crowdstrike.com','crunchbase.com','crunchyroll.com',
    'currys.co.uk','cve.org','cypress.io','dailymail.co.uk','dailymotion.com','daraz.pk',
    'dartmouth.edu','darty.com','datadog.com','datastudio.google.com','dbpedia.org','deadline.com',
    'debian.org','deepl.com','deepmind.com','deezer.com','defense.gov','deliveroo.com',
    'dell.com','delta.com','deno.com','depop.com','descript.com','desmos.com',
    'deutschebank.de','devblogs.microsoft.com','developer.android.com','developer.apple.com','developer.chrome.com','developer.mozilla.org',
    'developer.oracle.com','deviantart.com','dhl.com','dhs.gov','dialogflow.cloud.google.com','dictionary.com',
    'digitalocean.com','discogs.com','discord.com','discover.com','disneyplus.com','djangoproject.com',
    'dnsimple.com','docker.com','docs.anthropic.com','docs.github.com','docs.microsoft.com','dominos.com',
    'doordash.com','dot.gov','dotnet.microsoft.com','dribbble.com','drive.google.com','dropbox.com',
    'drugs.com','duckduckgo.com','duke.edu','duolingo.com','dynadot.com','dzen.ru',
    'ea.com','earth.google.com','ebay.co.uk','ebay.com','ebay.com.au','ebay.de',
    'ebay.fr','ec.europa.eu','economist.com','ecosia.org','ed.gov','edx.org',
    'eff.org','elastic.co','electronjs.org','elmundo.es','elpais.com','elsevier.com',
    'emby.media','emirates.com','energy.gov','engadget.com','enom.com','epa.gov',
    'epfl.ch','epicgames.com','espn.com','ethz.ch','etrade.com','etsy.com',
    'eurogamer.net','europa.eu','eventbrite.com','evernote.com','expedia.com','express.co.uk',
    'expressjs.com','extensions.gnome.org','f-droid.org','facebook.com','fast.com','fastapi.tiangolo.com',
    'fastlane.tools','fastly.com','fastweb.com','faz.net','fcc.gov','fda.gov',
    'fedex.com','fedoraproject.org','feedback.azure.com','fi.google.com','fidelity.com','fifa.com',
    'figma.com','finance.yahoo.com','firebase.google.com','firefox.com','fitbit.com','flask.palletsprojects.com',
    'flatpak.org','flickr.com','flightaware.com','flightradar24.com','flipkart.com','flutter.dev',
    'fnac.com','folha.uol.com.br','fontawesome.com','fonts.google.com','forbes.com','fortnite.com',
    'foxnews.com','framer.com','freecodecamp.org','freshdesk.com','fsf.org','ft.com',
    'ftc.gov','funimation.com','g2.com','gamespot.com','gap.com','gatech.edu',
    'gemini.google.com','genius.com','geogebra.org','getbootstrap.com','gettyimages.com','gist.github.com',
    'github.com','gitlab.com','gizmodo.com','glassdoor.com','globo.com','gnu.org',
    'goat.com','godaddy.com','gog.com','golang.org','goodreads.com','goodrx.com',
    'google-analytics.com','google.at','google.be','google.ca','google.ch','google.cl',
    'google.co.id','google.co.in','google.co.jp','google.co.kr','google.co.nz','google.co.th',
    'google.co.uk','google.co.za','google.com','google.com.ar','google.com.au','google.com.br',
    'google.com.co','google.com.eg','google.com.mx','google.com.my','google.com.ng','google.com.pe',
    'google.com.ph','google.com.pk','google.com.sg','google.com.tr','google.com.tw','google.com.ua',
    'google.com.vn','google.cz','google.de','google.dk','google.es','google.fi',
    'google.fr','google.hu','google.ie','google.it','google.nl','google.no',
    'google.pl','google.pt','google.ro','google.ru','google.se','googletagmanager.com',
    'gotomeeting.com','gouv.fr','gov.uk','grab.com','grafana.com','grammarly.com',
    'graphql.org','grubhub.com','gumtree.co.uk','gumtree.com.au','gutenberg.org','hackaday.com',
    'harvard.edu','hasura.io','haveibeenpwned.com','hbomax.com','headspace.com','healthline.com',
    'height.app','help.github.com','help.hulu.com','help.instagram.com','help.netflix.com','help.spotify.com',
    'heroicons.com','heroku.com','hilton.com','hindustantimes.com','hm.com','hollywoodreporter.com',
    'homedepot.com','honey.com','hootsuite.com','hotels.com','hotmail.com','hotwire.com',
    'house.gov','hover.com','howlongtobeat.com','hp.com','hsbc.com','hubspot.com',
    'hud.gov','huffpost.com','huggingface.co','hulu.com','hyatt.com','hybrid-analysis.com',
    'iana.org','ibm.com','icann.org','icloud.com','ieee.org','ifttt.com',
    'ign.com','iheart.com','ihg.com','ikea.com','illinois.edu','ilovepdf.com',
    'imdb.com','imf.org','imperial.ac.uk','impots.gouv.fr','indeed.com','independent.co.uk',
    'india.gov.in','ing.com','insomnia.rest','instacart.com','instagram.com','instructables.com',
    'intel.com','intercom.com','investopedia.com','invisionapp.com','irs.gov','issuu.com',
    'itv.com','java.com','jellyfin.org','jest.io','jetblue.com','jetbrains.com',
    'jira.com','johnlewis.com','jotform.com','jquery.com','jstor.org','jumia.com',
    'justeat.com','justice.gov','justwatch.com','kaggle.com','kakaotalk.com','kapwing.com',
    'kaspersky.com','kayak.com','keep.google.com','keepa.com','kernel.org','khanacademy.org',
    'kijiji.ca','klm.com','kohls.com','kotaku.com','kotlinlang.org','kraken.com',
    'kubernetes.io','labor.gov','lambdatest.com','laravel.com','last.fm','lastpass.com',
    'lazada.com','learn.microsoft.com','leboncoin.fr','lefigaro.fr','lemonde.fr','lenovo.com',
    'leo.org','letsencrypt.org','letterboxd.com','lg.com','liberation.fr','librivox.org',
    'line.me','linear.app','linguee.com','linkedin.com','live.com','livescience.com',
    'lloydsbank.com','localai.io','lodash.com','login.microsoftonline.com','logseq.com','looker.com',
    'loom.com','lowes.com','lse.ac.uk','lucidchart.com','lucide.dev','lufthansa.com',
    'lululemon.com','lyft.com','macys.com','magoosh.com','mail.google.com','mailchimp.com',
    'mainichi.jp','majestic.com','make.com','makerbot.com','malwarebytes.com','mandiant.com',
    'mangadex.org','maps.google.com','mariadb.org','marketingplatform.google.com','marketplace.visualstudio.com','marketwatch.com',
    'marktplaats.nl','marriott.com','mashable.com','mastercard.com','mastodon.social','material.io',
    'mathway.com','maven.org','max.com','mayoclinic.org','mcdonalds.com','mdn.dev',
    'me.com','medicare.gov','medlineplus.gov','meet.google.com','meetup.com','mercadolibre.com',
    'merriam-webster.com','messenger.com','metacritic.com','metro.co.uk','microsoft.com','microsoftonline.com',
    'midjourney.com','minecraft.net','mint.com','miro.com','mirror.co.uk','mit.edu',
    'mixer.com','mlb.com','monday.com','mongodb.com','monster.com','monzo.com',
    'morningstar.com','moz.com','mozilla.org','msn.com','mubi.com','music.apple.com',
    'music.youtube.com','musixmatch.com','myaccount.google.com','myanimelist.net','myfitnesspal.com','mysql.com',
    'n26.com','name.com','namecheap.com','nasa.gov','nationalgeographic.com','nativescript.org',
    'nato.int','nature.com','natwest.com','naver.com','nba.com','nbcnews.com',
    'ndtv.com','neon.tech','nerdwallet.com','netflix.com','newbalance.com','newegg.com',
    'newrelic.com','news.com.au','news.google.com','news.yahoo.co.jp','newyorker.com','nextdoor.com',
    'nextjs.org','nfl.com','nhk.or.jp','nhl.com','nhs.uk','nih.gov',
    'nike.com','nine.com.au','nintendo.com','noaa.gov','nodejs.org','noon.com',
    'nordstrom.com','northwestern.edu','npmjs.com','npr.org','nuget.org','nuxt.com',
    'nvd.nist.gov','nvidia.com','nytimes.com','nyu.edu','obsidian.md','office.com',
    'office365.com','okta.com','oldnavy.com','ollama.com','olx.com','one.google.com',
    'onedrive.live.com','onenote.com','openai.com','openstreetmap.org','opentable.com','opera.com',
    'oracle.com','orbitz.com','osmfoundation.org','otter.ai','otto.de','outlook.com',
    'outlook.office.com','outlook.office365.com','overstock.com','ox.ac.uk','ozon.ru','packagist.org',
    'pagerduty.com','pages.cloudflare.com','pandora.com','papajohns.com','paperswithcode.com','paramountplus.com',
    'parliament.uk','pay.google.com','paypal.com','pbs.org','pcgamer.com','pcmag.com',
    'pcpartpicker.com','peacocktv.com','peloton.com','perplexity.ai','personalcapital.com','pexels.com',
    'phind.com','photopea.com','photos.google.com','php.net','pinterest.com','pixabay.com',
    'pixlr.com','pizzahut.com','planetscale.com','platform.openai.com','play.google.com','playstation.com',
    'playwright.dev','plex.tv','pluto.tv','pnc.com','podcasts.apple.com','politico.com',
    'polygon.com','pons.com','popularmechanics.com','porkbun.com','portal.azure.com','portal.office.com',
    'poshmark.com','postgresql.org','postman.com','postmates.com','prepscholar.com','prezi.com',
    'priceline.com','primevideo.com','princeton.edu','prisma.io','producthunt.com','proton.me',
    'protonmail.com','prusa3d.com','pub.dev','pubmed.ncbi.nlm.nih.gov','puma.com','purdue.edu',
    'pypi.org','python.org','pytorch.org','qantas.com','qualcomm.com','quora.com',
    'qwant.com','radarr.video','rakuten.co.jp','rakuten.com','rbc.ru','reactjs.org',
    'reactnative.dev','realtor.com','reddit.com','redfin.com','redis.io','remix.run',
    'remnote.com','remove.bg','replicate.com','repubblica.it','researchgate.net','retailmenot.com',
    'retool.com','reuters.com','reverb.com','reverso.net','revolut.com','riotgames.com',
    'robinhood.com','roblox.com','roku.com','rollingstone.com','rosettastone.com','rottentomatoes.com',
    'route53.aws','rsync.net','rt.com','ruby-lang.org','rubygems.org','rubyonrails.org',
    'rust-lang.org','rxlist.com','salesforce.com','samsung.com','saucelabs.com','sba.gov',
    'scholar.google.com','scholarships.com','schwab.com','sciencedirect.com','sciencemag.org','scientificamerican.com',
    'scmp.com','screencastify.com','scribd.com','seamless.com','search.brave.com','search.google.com',
    'sec.gov','securelist.com','seekingalpha.com','semanticscholar.org','semrush.com','senate.gov',
    'sendgrid.com','sentry.io','sephora.com','service-public.fr','setlist.fm','shazam.com',
    'shein.com','shopee.com','shopify.com','shutterstock.com','signal.org','signin.aws.amazon.com',
    'similarweb.com','simkl.com','singaporeair.com','sitejabber.com','sketch.com','sky.com',
    'skype.com','skyscanner.com','slack.com','slickdeals.net','slideshare.net','smallpdf.com',
    'smartsheet.com','smh.com.au','snapchat.com','snapdeal.com','social.msdn.microsoft.com','sogou.com',
    'sonarr.tv','songkick.com','sony.com','sophos.com','sorbonne-universite.fr','soundcloud.com',
    'souq.com','sourceforge.net','southwest.com','space.com','speedrun.com','speedtest.net',
    'spiegel.de','splunk.com','splunkcloud.com','sports.yahoo.com','spotify.com','spring.io','springer.com',
    'sproutsocial.com','sqlite.org','square.com','ssa.gov','stability.ai','stackexchange.com',
    'stackoverflow.com','standard.co.uk','standardebooks.org','stanford.edu','starbucks.com','startpage.com',
    'state.gov','status.aws.amazon.com','status.cloud.google.com','statuspage.io','steamcommunity.com','steamdb.info',
    'steampowered.com','stockx.com','store.google.com','store.steampowered.com','straitstimes.com','strava.com',
    'stripe.com','stubhub.com','subito.it','subway.com','sueddeutsche.de','supabase.com',
    'support.apple.com','support.google.com','support.microsoft.com','supremecourt.gov','surveymonkey.com','svelte.dev',
    'swagbucks.com','swagger.io','swift.org','symbolab.com','tagmanager.google.com','tailwindcss.com',
    'target.com','tass.ru','tauri.app','tdbank.com','teams.microsoft.com','teamwork.com',
    'techcommunity.microsoft.com','techcrunch.com','ted.com','telegram.org','telegraph.co.uk','temu.com',
    'tensorflowjs.org','terraform.io','the-scientist.com','theatlantic.com','theguardian.com','thehill.com',
    'thehindu.com','theverge.com','threads.net','threatpost.com','thunderbird.net','ticketmaster.com',
    'ticktick.com','tidal.com','tiktok.com','time.com','timesofindia.indiatimes.com','todoist.com',
    'together.ai','tokopedia.com','tomshardware.com','tradingview.com','trakt.tv','translate.google.com',
    'travisci.com','treasury.gov','trello.com','trendmicro.com','tripadvisor.com','trivago.com',
    'trulia.com','trustpilot.com','tu-muenchen.de','tubi.tv','tutanota.com','tvtime.com',
    'tvtropes.org','twilio.com','twitch.tv','twitter.com','typeform.com','typescriptlang.org',
    'uber.com','ubereats.com','ubisoft.com','ubuntu.com','uchicago.edu','ucl.ac.uk',
    'ucla.edu','udacity.com','udemy.com','ulta.com','umich.edu','un.org',
    'underarmour.com','uniqlo.com','united.com','unsplash.com','uol.com.br','upenn.edu',
    'ups.com','urlhaus.abuse.ch','usa.gov','usatoday.com','usbank.com','usc.edu',
    'userbenchmark.com','usps.com','utexas.edu','uw.edu','v.redd.it','vanguard.com',
    'vanityfair.com','variety.com','venmo.com','vercel.com','viber.com','vice.com',
    'vimeo.com','vinted.com','virustotal.com','visa.com','visualstudio.com','visualstudio.microsoft.com',
    'vitest.dev','vivaldi.com','vk.com','vmware.com','vox.com','vrbo.com',
    'vuejs.org','w3.org','w3schools.com','walmart.com','wasabi.com','washingtonpost.com',
    'wayfair.com','waze.com','weather.com','weather.gov','web.dev','web.telegram.org',
    'web.whatsapp.com','webex.com','webflow.com','webmd.com','wechat.com','weibo.com',
    'wellsfargo.com','wendys.com','whatsapp.com','whitehouse.gov','who.int','wikidata.org',
    'wikihow.com','wikimedia.org','wikipedia.org','wiktionary.org','wildberries.ru','wiley.com',
    'wired.com','wisc.edu','wise.com','wish.com','wolframalpha.com','woocommerce.com',
    'wordreference.com','workers.cloudflare.com','worldbank.org','worldcat.org','wsj.com','wto.org',
    'wunderground.com','x.com','xbox.com','yahoo.co.jp','yahoo.com','yale.edu',
    'yandex.com','yandex.ru','yelp.com','ynab.com','yomiuri.co.jp','you.com',
    'youtube.com','zalando.com','zapier.com','zappos.com','zara.com','zdnet.com',
    'zeit.de','zelle.com','zendesk.com','zillow.com','ziprecruiter.com','zocdoc.com',
    'zoom.us',
  ]),
};

if (typeof window     !== 'undefined') window.NW_PATTERNS     = NW_PATTERNS;
if (typeof module     !== 'undefined') module.exports           = NW_PATTERNS;
if (typeof globalThis !== 'undefined') globalThis.NW_PATTERNS  = NW_PATTERNS;
