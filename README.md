# waybackurl_ranker.py

**Version:** 1.4.1

## Overview

**WaybackURL Ranker (WBU Ranker)** is a Python 3 utility designed to help prioritize large lists of URLs obtained from [waybackurls](https://github.com/tomnomnom/waybackurls) based on the risk of sensitive information leakage.

The tool assigns a risk score to each URL by analyzing:

- URL parameters and paths for sensitive keywords (e.g., `password`, `token`, `apikey`).
- Suspicious file extensions (e.g., `.env`, `.bak`, `.sql`, `.zip`, `.log`).
- Base64/high-entropy strings in query parameters.
- Path depth (e.g., `/admin/login/reset` scores higher).
- HTTP response status codes (e.g., 200 OK increases score, 404 decreases).
- JavaScript file scanning for secrets/tokens if URL ends in `.js`.
- HTML content scraping for sensitive indicators (e.g., login forms, dashboards).
- Detection of unreachable domains to avoid repeat wasted requests.

With multithreading support, custom filters, and colorized output for fast triage.

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

## Usage

```bash
$ python3 waybackurl_ranker.py -h                                         

+--------------------------------------------------+
|      WAYBACKURL RANKER — URL Risk Classifier     |
|                    v1.4.1                        |
+--------------------------------------------------+

usage: waybackurl_ranker.py [-h] [--config CONFIG] [--min-score MIN_SCORE] [--only-200] [--no-reqs] [--no-color] [--threads THREADS] [--json] [--verbose] [--output OUTPUT]
                            file

positional arguments:
  file                  Input file with URLs

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to JSON scoring config
  --min-score MIN_SCORE
  --only-200
  --no-reqs
  --no-color
  --threads THREADS
  --json
  --verbose
  --output OUTPUT       Output file path

```

## Options

- -h, --help : Show the help message with usage instructions and exit.
- --config CONFIG : Specify the path to the JSON configuration file that defines scoring rules and patterns.
- --min-score MIN_SCORE : Only display URLs with a score greater than or equal to this minimum threshold.
- --only-200 : Filter results to show only URLs that returned an HTTP 200 status code.
- --no-reqs : Disable sending HTTP requests; scoring will be based solely on URL keyword analysis.
- --no-color : Disable colored output in the terminal for better compatibility or plain text logging.
- --threads THREADS : Set the number of concurrent worker threads for processing URLs (default is 10).
- --json : Output results in JSON format.
- --verbose : Show detailed scoring reasons and breakdown for each URL.
- --output OUTPUT : Save the results to the specified file path instead of printing to standard output.

## Notes

- Known JavaScript libraries like jQuery, React, Vue, etc., are excluded from JS content inspection to reduce false positives.
- Domains that fail connection or timeout requests are skipped in subsequent requests to speed up scanning.
- Scoring is heuristic and may not always reflect actual sensitivity, use with discretion.
- Also checks for keywords found here: https://github.com/gigachad80/grep-backURLs/blob/main/grep_keywords.txt

## Thanks

- [tomnomnom](https://github.com/tomnomnom) for [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gigachad80](https://github.com/gigachad80) for [https://github.com/gigachad80/grep-backURLs/blob/main/grep_keywords.txt](https://github.com/gigachad80/grep-backURLs/blob/main/grep_keywords.txt)
