# waybackurl_ranker.py

**Version:** 1.2.1

## Overview

**WaybackURL Ranker (WBU Ranker)** is a Python 3 utility designed to help prioritize large lists of URLs obtained from [waybackurls](https://github.com/tomnomnom/waybackurls) based on the risk of sensitive information leakage.

The tool assigns a risk score to each URL by analyzing:

- URL parameters and paths for sensitive keywords (e.g., `password`, `token`, `apikey`).
- Suspicious file extensions (`.env`, `.bak`, `.sql`, `.zip`, `.log`).
- Base64/high-entropy strings in query parameters.
- Path depth (e.g., `/admin/login/reset` scores higher).
- HTTP response status codes (e.g., 200 OK increases score, 404 decreases).
- JavaScript file scanning for secrets/tokens if URL ends in `.js`.
- HTML content scraping for sensitive indicators (e.g., login forms, dashboards).
- Detection of unreachable domains to avoid repeat wasted requests.

With multithreading support, custom filters, and colorized output for fast triage.

---

## Features

- **Keyword-based scoring**
- **Suspicious file extension detection**
- **Entropy-based value matching**
- **HTML page content analysis**
- **JavaScript file analysis**
- **HTTP status scoring**
- **Unreachable domain tracking**
- **Verbose mode for score explanation**
- **Multi-threaded URL processing**
- **Colorized CLI output**
- **Filtering options by score and status**

---

## Usage

```bash
$ python3 waybackurl_ranker.py -h                            

+--------------------------------------------------+
|      WAYBACKURL RANKER — URL Risk Classifier     |
|                    v1.2.1                        |
+--------------------------------------------------+

Usage: waybackurl_ranker.py [-h] [--min-score MIN_SCORE] [--only-200] [--no-reqs] [--no-color] [--threads THREADS] [--verbose] file

```

---

