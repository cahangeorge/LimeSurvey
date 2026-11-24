#!/bin/sh
set -eu

for file in \
    themes/georgianadaycare/config.xml \
    themes/georgianadaycare/css/georgianadaycare.css \
    themes/georgianadaycare/files/logo.png \
    themes/georgianadaycare/scripts/embed.js \
    themes/georgianadaycare/fonts/nunito-sans-latin-ext-wght.woff2 \
    themes/georgianadaycare/fonts/OFL-Nunito-Sans.txt
do
    [ -f "$file" ] || { printf '%s\n' "missing required theme file: $file" >&2; exit 1; }
done

python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise SystemExit(message)

root = Path('.')
config = ET.parse(root / 'themes/georgianadaycare/config.xml').getroot()
metadata = config.find('metadata')
require(metadata is not None, 'missing theme metadata')

expected_metadata = {
    'name': 'georgianadaycare',
    'type': 'theme',
}
for field, value in expected_metadata.items():
    require(metadata.findtext(field) == value, f'invalid theme metadata: {field}')
require(
    (metadata.findtext('parent') or metadata.findtext('extends')) == 'fruity',
    'invalid theme metadata: parent',
)
require(
    any(version.text == '7.0' for version in config.findall('./compatibility/version')),
    'missing theme compatibility: 7.0',
)
require(
    any(node.text == 'css/georgianadaycare.css' for node in config.findall('./files/css/*')),
    'missing CSS registration',
)
require(
    any(node.text == 'scripts/embed.js' for node in config.findall('./files/js/*')),
    'missing JS registration',
)

expected_hashes = {
    'themes/georgianadaycare/files/logo.png': 'a1f4911d7fa80a02eca80d0db2e184d1bc44f7951c1ae6a1ec8a45dcb68aed81',
    'themes/georgianadaycare/fonts/nunito-sans-latin-wght.woff2': '29e3890496844a9ea81975c52771c587c872b4eb317026422d1995b88d21b57d',
    'themes/georgianadaycare/fonts/nunito-sans-latin-ext-wght.woff2': 'c648ee5bfda70d44b9fb628f4114d1cc4f984d050cbb4881052237ede3638a2e',
    'themes/georgianadaycare/fonts/OFL-Nunito-Sans.txt': 'efbb0c9e864cef973982d9a17567e6be5c3d1759695574586f3f18c7ecca064b',
}
for filename, expected in expected_hashes.items():
    actual = sha256((root / filename).read_bytes()).hexdigest()
    require(actual == expected, f'invalid SHA-256: {filename}')

css = (root / 'themes/georgianadaycare/css/georgianadaycare.css').read_text()
font_faces = re.findall(r'@font-face\s*\{.*?\}', css, re.S)
require(len(font_faces) == 2, 'expected two Nunito Sans font-face declarations')
expected_font_faces = {
    'nunito-sans-latin-wght.woff2': 'U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329,\n\t\tU+2000-206F, U+20AC, U+2122, U+2190, U+2191, U+2192, U+2193, U+2212, U+2215, U+FEFF, U+FFFD',
    'nunito-sans-latin-ext-wght.woff2': 'U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329,\n\t\tU+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F,\n\t\tU+A720-A7FF',
}
for filename, unicode_range in expected_font_faces.items():
    matching = [face for face in font_faces if filename in face]
    require(len(matching) == 1, f'missing local Nunito Sans font-face declaration: {filename}')
    font_face = matching[0]
    for needle in (
        "font-family: 'Nunito Sans';",
        'font-style: normal;',
        'font-weight: 400 900;',
        'font-display: swap;',
        f"src: url('../fonts/{filename}') format('woff2');",
        f'unicode-range:\n\t\t{unicode_range};',
    ):
        require(needle in font_face, f'missing local Nunito Sans font-face declaration: {needle}')
for token, value in {
    '--canvas': '#fffaf4', '--ink': '#253447', '--brand-pink': '#ad125e',
    '--brand-blue': '#126a92', '--sunshine': '#f7dc69', '--pink-wash': '#fce7f0',
    '--blue-wash': '#e8f4fa', '--muted': '#526174', '--border': '#d9dfe5',
    '--white': '#fff',
}.items():
    require(re.search(rf'{re.escape(token)}\s*:\s*{re.escape(value)}\s*;', css), f'missing design token: {token}')
logo = (root / 'themes/georgianadaycare/files/logo.png').read_bytes()
require(logo[:8] == b'\x89PNG\r\n\x1a\n', 'logo is not a PNG')
require(int.from_bytes(logo[16:20], 'big') == 234 and int.from_bytes(logo[20:24], 'big') == 131, 'invalid logo dimensions')
require(logo[25] == 6, 'logo is not RGBA')
logo_rule = re.search(r'\.logo-container\s+\.logo\s*\{([^}]*)\}', css, re.S)
require(logo_rule is not None, 'missing responsive logo sizing')
for property in ('width: min(100%, 234px);', 'height: auto;', 'object-fit: contain;'):
    require(property in logo_rule.group(1), f'missing responsive logo sizing: {property}')
for needle, message in (
    ('Nunito Sans', 'missing Nunito Sans font'),
    ('@media', 'missing responsive rules'),
    (':focus-visible', 'missing visible focus styling'),
    ('prefers-reduced-motion: reduce', 'missing reduced-motion handling'),
):
    require(needle in css, message)

js = (root / 'themes/georgianadaycare/scripts/embed.js').read_text()
message_types = set(re.findall(r"\btype\s*:\s*['\"](georgianadaycare:[^'\"]+)['\"]", js))
require(message_types == {
    'georgianadaycare:ready',
    'georgianadaycare:resize',
    'georgianadaycare:completion',
}, 'invalid theme message types')
for needle, message in (
    ('georgianadaycare:parent-origin:', 'missing iframe name origin contract'),
    ('window.name', 'iframe name origin contract is not read'),
    ('document.referrer', 'missing referrer origin fallback'),
    ("'http:'", 'missing HTTP origin validation'),
    ("'https:'", 'missing HTTPS origin validation'),
    ('.username', 'missing origin username validation'),
    ('.password', 'missing origin password validation'),
    ('.pathname', 'missing origin path validation'),
    ('.search', 'missing origin query validation'),
    ('.hash', 'missing origin hash validation'),
    ('.origin', 'target origin is not normalized'),
):
    require(needle in js, message)
for owner in ('document.documentElement', 'document.body'):
    for metric in ('scrollHeight', 'offsetHeight', 'clientHeight'):
        require(f'{owner}.{metric}' in js, f'missing full-height metric: {owner}.{metric}')
require('Math.ceil' in js and '100000' in js, 'reported height is not rounded and bounded')
require('getBoundingClientRect().height' not in js, 'viewport rectangle must not be the reported height source')
require(not re.search(r"postMessage\s*\((?:[^()\n]|\([^()\n]*\))*?,\s*['\"]\*['\"]\s*\)", js), 'wildcard postMessage target origin')
for pattern in (r'\bFormData\b', r'\bURLSearchParams\b', r'\bJSON\.stringify\b', r'\bserialize\w*\b', r'\.elements\b', r'\.value\b'):
    require(not re.search(pattern, js, re.I), 'theme must not collect or serialize response values')

dockerfile = (root / 'docker/php/Dockerfile').read_text()
require(
    'themes/georgianadaycare /opt/limesurvey-managed-themes/georgianadaycare' in dockerfile,
    'managed theme is not packaged in the image',
)

entrypoint = (root / 'docker/entrypoint.sh').read_text()
for needle in (
    'managed_theme_source=/opt/limesurvey-managed-themes/georgianadaycare',
    'managed_theme_target=/var/www/html/upload/themes/survey/georgianadaycare',
    'managed_theme_staging=/var/www/html/upload/themes/survey/.georgianadaycare.staging.$$',
    'rm -rf "$managed_theme_staging"',
    'rm -rf "$managed_theme_target"',
    'mv "$managed_theme_staging" "$managed_theme_target"',
):
    require(needle in entrypoint, 'managed theme sync is incomplete')
require(
    not re.search(r'rm\s+-rf\s+["\']?/var/www/html/upload/themes/survey["\']?\s*$', entrypoint, re.M),
    'managed theme sync deletes the parent theme directory',
)
PY

printf '%s\n' 'theme package checks passed'
