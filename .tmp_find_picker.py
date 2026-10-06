import re
s = open(r"E:\projects\aetheris_project\.tmp-gateway.js", encoding="utf-8", errors="ignore").read()
for m in re.finditer(r".{150}webkitdirectory.{250}", s):
    print(m.group(0))
    print("---")
print("\nImport button contexts:")
for m in re.finditer(r".{30}Import.{30}", s):
    t = m.group(0)
    if "CSV" in t or "package" in t.lower() or "mobile" in t.lower():
        continue
    if "Import" in t and ("FileUp" in t or "folder" in t.lower() or "Process" in t or "jsxs" in t):
        print(t)
print("\nSelect folder contexts:")
for m in re.finditer(r".{40}Select folder.{60}", s):
    print(m.group(0))
