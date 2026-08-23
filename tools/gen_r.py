"""
Synthesize R.java from the real res tree.

Not a substitute for aapt2 link — it cannot resolve Material's styles, which live
in an AAR this harness does not unpack. What it DOES give is the thing worth
having: every R.<type>.<name> the Kotlin sources reference is checked against a
name that actually exists in res/, so a typo'd or missing resource is a compile
error here exactly as it would be in the real build.
"""
import os, re, sys, xml.etree.ElementTree as ET
from collections import defaultdict

res = sys.argv[1]
out = sys.argv[2]
pkg = sys.argv[3] if len(sys.argv) > 3 else 'com.bestrom.nullroute'

names = defaultdict(set)

# File-based resource types: res/<type>[-qualifier]/<name>.<ext>
for d in sorted(os.listdir(res)):
    p = os.path.join(res, d)
    if not os.path.isdir(p):
        continue
    rtype = d.split('-')[0]
    if rtype in ('values',):
        continue
    for f in os.listdir(p):
        base = f.split('.')[0]
        names[rtype].add(base)

# values/*.xml: <string name=>, <color>, <style>, <dimen>, <bool>, <integer>,
# <string-array>, <attr>, and any <item type=>.
VALUE_TAGS = {
    'string': 'string', 'color': 'color', 'dimen': 'dimen', 'bool': 'bool',
    'integer': 'integer', 'style': 'style', 'string-array': 'array',
    'integer-array': 'array', 'array': 'array', 'attr': 'attr', 'plurals': 'plurals',
}
for d in sorted(os.listdir(res)):
    if not d.startswith('values'):
        continue
    p = os.path.join(res, d)
    if not os.path.isdir(p):
        continue
    for f in os.listdir(p):
        if not f.endswith('.xml'):
            continue
        try:
            root = ET.parse(os.path.join(p, f)).getroot()
        except ET.ParseError as e:
            print(f"  !! {d}/{f}: {e}", file=sys.stderr)
            continue
        for el in root:
            n = el.get('name')
            if not n:
                continue
            n = n.replace('.', '_')
            if el.tag == 'item' and el.get('type'):
                names[el.get('type')].add(n)
            elif el.tag in VALUE_TAGS:
                names[VALUE_TAGS[el.tag]].add(n)

# @+id/ anywhere in the tree, including menus and layouts.
ID_RE = re.compile(r'@\+id/([A-Za-z_][A-Za-z0-9_]*)')
for dirpath, _, files in os.walk(res):
    for f in files:
        if not f.endswith('.xml'):
            continue
        try:
            txt = open(os.path.join(dirpath, f), encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for m in ID_RE.finditer(txt):
            names['id'].add(m.group(1))

os.makedirs(out, exist_ok=True)
path = os.path.join(out, 'R.java')
with open(path, 'w', encoding='utf-8') as fh:
    fh.write('package com.bestrom.nullroute;\npublic final class R {\n')
    v = 0x7f010000
    for rtype in sorted(names):
        if not names[rtype]:
            continue
        fh.write('  public static final class %s {\n' % rtype)
        for n in sorted(names[rtype]):
            v += 1
            fh.write('    public static final int %s=0x%08x;\n' % (n, v))
        fh.write('  }\n')
    fh.write('}\n')

print('R.java: ' + ', '.join('%s=%d' % (t, len(names[t])) for t in sorted(names) if names[t]))
