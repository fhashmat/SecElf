#!/usr/bin/env python3

import json
from secelf.stage_c import is_cve_relevant, normalize_package_name

# ✅ Use a real test package name and normalize it
pkg = normalize_package_name("xz-5.6.0-1.el9.x86_64")
print("[TEST] Normalized package:", pkg)

# ✅ Load the test CVE JSON
with open("cvelistV5/cves/2024/3xxx/CVE-2024-3094.json") as f:
    cve_data = json.load(f)

# ✅ Test relevance
is_relevant = is_cve_relevant(cve_data, [pkg], debug=True)
print("[TEST] Relevant?", is_relevant)
