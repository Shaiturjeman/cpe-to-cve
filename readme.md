# CPE-to-CVE Vulnerability Explorer

A lightweight Python CLI that helps security researchers quickly map a **CPE** (Common Platform Enumeration) to its known **CVEs** (Common Vulnerabilities & Exposures) using the public NVD 2.0 API, and surfaces any GitHub‑hosted proof‑of‑concept exploits ranked by repository popularity.

---

## ✨ Key Features

| Capability                  | Description                                                                                         |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| 🔍 **CPE search**           | Lookup matching CPE entries from NVD by keyword and interactively select the exact product/version. |
| 📋 **CVEs fetch**           | Retrieve all CVEs associated with the chosen CPE (CVSS v3.1 base score, description, references).   |
| 📈 **Exploit popularity**   | Detect GitHub references tagged as *Exploit* / *Tool* / *POC* and rank them by ⭐ stars & 🍴 forks.  |
| 🎛️ **CVSS filter**         | Optional on‑the‑fly filtering so you can focus on high‑severity vulnerabilities only.               |
| 🖨️ **Pretty table output** | Fixed‑width table layout for easy terminal reading, with emoji/hieroglyph for star ratings.         |

---

## 🚀 Quick Start

```bash
# Clone the repository
$ git clone https://github.com/Shaiturjeman/cpe-to-cve.git
$ cd cpe-to-cve

# (Optional) create an isolated environment
$ python -m venv venv && source venv/bin/activate

# Install the single runtime dependency
$ pip install requests

# Run the tool (your NVD API key is already hard‑coded in the script)
$ python cpe_to_cve.py
```

---

## ⚙️ Configuration

| Constant           | Default         | Purpose                                                                |
| ------------------ | --------------- | ---------------------------------------------------------------------- |
| `TABLE_WIDTH`      | `100`           | Overall table width in characters.                                     |
| `GITHUB_API_DELAY` | `0.5`           | Seconds to sleep between GitHub API requests (avoids abuse detection). |
| `NVD_API_KEY`      | *set in script* | Personal API key sent in every NVD call.                               |

Edit these constants at the top of \`\` if you need different values.

---

## 🖥️ Example Session

```
$ python cpe_to_cve.py
Enter software/hardware name (e.g., 'log4j') or 'q' to quit: log4j

🔎 Searching for CPEs matching 'log4j'...
FOUND CPEs:
1. Apache Log4j 2.21.0 (cpe:2.3:a:apache:log4j:2.21.0:*)
2. Apache Log4j 1.2.17 (cpe:2.3:a:apache:log4j:1.2.17:*)
Select CPE by number: 1

🌐 Requesting URL: ...
Total CVEs found: 123

🔍 Vulnerabilities found for Apache Log4j 2.21.0:
| CVE ID        | Severity | Description                             |
|---------------|----------|-----------------------------------------|
| CVE-2025-0001 | 9.8      | A deserialization flaw allows...        |
|               |          | GitHub Resources:                       |
|               |          | – POC-log4shell (⭐⭐⭐⭐⭐ — 4,200★, 800🍴) |
--- snip ---
```

---

## 🆘 Troubleshooting

| Symptom                             | Likely Cause                                           | Fix                                                     |
| ----------------------------------- | ------------------------------------------------------ | ------------------------------------------------------- |
| `API Error - Status Code: 429`      | NVD rate limit hit                                     | Wait 60 s or reduce query volume.                       |
| Empty CVE table                     | Selected CPE has no recorded vulnerabilities           | Try a broader CPE or older version.                     |
| GitHub stats show "Unable to fetch" | GitHub unauthenticated rate limit (60 req/hr) exceeded | Raise `GITHUB_API_DELAY` or add a GitHub token in code. |

