import re
s = open(r"E:\projects\aetheris_project\.tmp-gateway.js", encoding="utf-8", errors="ignore").read()
# Mobile compact job page actions
for pat in [
    r'Select folder & start',
    r'">Import<',
    r'Import</',
    r'children:"Import"',
    r'," Import"',
    r'Import",',
]:
    print(pat, s.count(pat.replace('\\','')) if False else len(re.findall(pat, s)))

# Find Process button near Import on mobile job
for m in re.finditer(r'.{80}Process.{0,40}Import.{80}', s):
    print('FOUND', m.group(0)[:200])
    print('---')

# How openNativeFolderPicker / folder input click works
for m in re.finditer(r'.{60}webkitdirectory.{0,20}.{0,400}Select extraction', s):
    print('SEL', m.group(0)[:300])
# search for .click() near folderInput or webkitdirectory handler
idx = s.find('className:"fixed left-0 top-0 h-px w-px opacity-0"')
# search backwards for function that clicks P
chunk = s[idx-3000:idx]
# find click patterns
print('clicks near input:', len(re.findall(r'\.click\(\)', chunk)))
for m in re.finditer(r'.{40}\.click\(\).{40}', chunk):
    print(m.group(0))
