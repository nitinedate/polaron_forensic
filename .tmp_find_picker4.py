import re
s = open(r"E:\projects\aetheris_project\.tmp-gateway.js", encoding="utf-8", errors="ignore").read()
# Find It= function near HostEvidence - search for It=e=> or function It or const It=
# From onChange It(O.target.files)
# Find definitions of openNativeFolderPicker-like: setBrowseDialogOpen / folder click
for pat in [r'async function [A-Za-z]+\(\)\{if\(![A-Za-z]+&&![A-Za-z]+&&![A-Za-z]+\)', r'showDirectoryPicker', r'P\.current\?\.click', r'\.current\.click\(\)', r'folderInput']:
    ms=list(re.finditer(pat,s))
    print(pat, len(ms))
    for m in ms[:5]:
        print(' ', s[m.start()-40:m.end()+80][:160])

# Find setBrowseDialogOpen pattern: likely Ce(!0) or similar near Select extraction
idx = s.find('Select extraction directory')
print('\nSelect extraction context:\n', s[idx-400:idx+200])
