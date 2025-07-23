# waybackurl_ranker.py

**Version:** 1.1.0

## Overview

**WaybackURL Ranker** is a Python3 utility designed to help prioritize large lists of URLs obtained from [waybackurls](https://github.com/tomnomnom/waybackurls) based on the risk of sensitive information leakage.

The tool assigns a risk score to each URL by analyzing:

- URL parameters and paths for sensitive keywords (e.g., `password`, `token`, `apikey`).
- HTTP response status codes (e.g., 200 OK increases score, 404 decreases).
- Content indicators found on the page (e.g., login forms, admin panels).
- Suspicious file extensions (`.env`, `.bak`, `.sql`).
- Detection of domains that are unreachable, avoiding repeated wasted requests.

With multi-threading support and filtering options.

---

## Features

- **Keyword-based scoring:** Detects sensitive parameters and path keywords.
- **HTTP status evaluation:** Weighs URLs by response codes.
- **Content analysis:** Scrapes HTML to detect potential login/admin keywords.
- **Domain skipping:** Avoids querying domains that fail DNS resolution.
- **Multi-threaded:** Adjustable concurrency to speed up URL processing.
- **Filtering options:** Filter output by minimum score and status.
- **Colorized output:** Easy-to-read colored scoring output.
- **Simple CLI interface:** Works with Waybackurls or any URL list file.

---

## Requirements

- Python 3.6+
- `requests` library
- `beautifulsoup4` library

Install dependencies via pip:

```bash
pip install requests beautifulsoup4

## Usage

```bash
$ python3 waybackurl_ranker.py -h                            

+---------------------------------------------+
|    WAYBACKURL RANKER — URL Risk Classifier  |
|              v1.1.0                         |
+---------------------------------------------+

Usage: waybackurl_ranker.py [-h] [--min-score MIN_SCORE] [--only-200] [--no-reqs] [--no-color]
                            [--threads THREADS]
                            file
waybackurl_ranker.py: error: the following arguments are required: file

