# waybackurl_ranker.py

**Version:** 1.3.0

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

- Keyword-based scoring
- Suspicious file extension detection
- Entropy-based value matching
- HTML page content analysis
- JavaScript file analysis
- HTTP status scoring
- Unreachable domain tracking
- Verbose mode for score explanation
- Multi-threaded URL processing
- Colorized CLI output
- Filtering options by score and status

---

## Usage

```bash
$  python3 waybackurl_ranker.py -h                                     

+--------------------------------------------------+
|      WAYBACKURL RANKER — URL Risk Classifier     |
|                    v1.3.0                        |
+--------------------------------------------------+

Usage: waybackurl_ranker.py [-h] [--min-score MIN_SCORE] [--only-200] [--no-reqs] [--no-color]
                            [--threads THREADS] [--verbose] [--output OUTPUT]
                            file
```

---

## Options

- -h, --help : Show help message and exit
- --min-score N : Show only URLs with score >= N (default: 0)
- --only-200 : Show only URLs that returned HTTP 200
- --no-reqs : Skip HTTP requests (only keyword scoring)
- --no-color : Disable colored output
- --threads N : Number of concurrent threads (default: 10)
- --verbose : Show detailed scoring reasons per URL
- --output FILE : Save output to specified file instead of printing to console

--- 

## Notes

- Known JavaScript libraries like jQuery, React, Vue, etc., are excluded from JS content inspection to reduce false positives.
- Domains that fail connection or timeout requests are skipped in subsequent requests to speed up scanning.
- Scoring is heuristic and may not always reflect actual sensitivity, use with discretion.
- Also checks for keywords found here: https://github.com/gigachad80/grep-backURLs/blob/main/grep_keywords.txt

## Thanks

- [tomnomnom](https://github.com/tomnomnom) for [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gigachad80](https://github.com/gigachad80) for [https://github.com/gigachad80/grep-backURLs/blob/main/grep_keywords.txt](https://github.com/gigachad80/grep-backURLs/blob/main/grep_keywords.txt)
