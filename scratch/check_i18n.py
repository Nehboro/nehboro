import re
import os

def extract_keys(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    return set(re.findall(r'data-i18n="([^"]+)"', content)) | set(re.findall(r'data-i18n-placeholder="([^"]+)"', content))

def get_js_keys(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    # Find all keys in en: { ... }
    en_block = re.search(r'en:\s*\{(.*?)\},', content, re.DOTALL)
    if not en_block:
        return set()
    return set(re.findall(r'"([^"]+)":', en_block.group(1)))

html_files = [
    'blocked/blocked.html',
    'popup/popup.html'
]

i18n_path = 'utils/i18n.js'
js_keys = get_js_keys(i18n_path)

for html in html_files:
    print(f"--- Checking {html} ---")
    keys = extract_keys(html)
    missing = keys - js_keys
    if missing:
        print(f"Missing keys: {missing}")
    else:
        print("No missing keys found in data-i18n attributes.")

print("\n--- Hardcoded text check (potential missing i18n) ---")
# Check for text nodes that are not inside data-i18n
for html in html_files:
    with open(html, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        # Look for lines with >Text< where Text is not a tag and doesn't have data-i18n
        # This is a bit rough but helps find obvious ones
        matches = re.findall(r'>([^<>{}\n]+)<', line)
        for m in matches:
            text = m.strip()
            if text and len(text) > 3 and 'data-i18n' not in line and '<script' not in line and '<style' not in line:
                 print(f"{html}:{i+1}: {text}")
