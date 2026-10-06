import re
s = open(r"E:\projects\aetheris_project\.tmp-gateway.js", encoding="utf-8", errors="ignore").read()
# Find larger context around first webkitdirectory
idx = s.find('className:"fixed left-0 top-0 h-px w-px opacity-0"')
print("idx", idx)
print(s[idx-800:idx+1200])
