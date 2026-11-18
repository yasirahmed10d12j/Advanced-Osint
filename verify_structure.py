"""Sanity-check that every DOM id used by advanced.js exists in index.html."""
import re

html = open("index.html", encoding="utf-8").read()
js = open("advanced.js", encoding="utf-8").read()

ids_used = set(re.findall(r"\$\('([\w-]+)'\)", js)) | set(re.findall(r"\$\(\"([\w-]+)\"\)", js))
ids_defined = set(re.findall(r'id="([\w-]+)"', html))
missing = sorted(ids_used - ids_defined)
print("IDs referenced by advanced.js:", len(ids_used))
print("Missing:", missing or "none")

tabs = set(re.findall(r'data-tab="([\w-]+)"', html))
sections = set(re.findall(r'id="tab-([\w-]+)"', html))
print("Nav tabs:", sorted(tabs))
print("Sections:", sorted(sections))
print("Unmatched:", sorted(tabs ^ sections) or "none")

assert not missing and not (tabs ^ sections)
print("HTML structure: OK")
