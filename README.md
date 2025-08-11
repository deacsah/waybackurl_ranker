# WaybackURL Ranker

**Version:** 2.1.2

## Overview

**WaybackURL Ranker (WBUR)** is a Python 3 utility designed to prioritize large URL lists—especially those obtained from [waybackurls](https://github.com/tomnomnom/waybackurls)—by scoring them according to potential risk of sensitive information leakage.

The tool analyzes URLs with heuristic scoring based on:

- URL parameters and paths containing sensitive keywords (e.g., `password`, `token`, `apikey`).
- Suspicious file extensions (like `.env`, `.bak`, `.sql`, `.zip`, `.log`).
- High-entropy (Base64 or similar) strings found in query parameter values.
- Path depth (longer, nested paths score higher).
- HTTP response status codes (e.g., 200 OK adds score; 404 or errors decrease).
- JavaScript file content scanning to detect secrets/tokens if URLs end with `.js` (needs improvement). 
- HTML content scraping for indicators like login forms, dashboards, or error messages.
- Tracking and excluding unreachable or slow-responding domains to avoid wasted retries.
- Batch processing for large inputs with memory-efficient sorting of results.
- Multithreaded URL processing for improved speed.

This helps prioritize URLs that require urgent manual inspection and triage, speeding up security assessments and reconnaissance.

## Usage

    $ python3 waybackurl_ranker.py -h

    +--------------------------------------------------+
    |       WAYBACKURL RANKER                          |
    |       URL Risk Classifier & Score v2.1.2         |
    +--------------------------------------------------+

    usage: waybackurl_ranker.py [-h] [--config CONFIG] [--min-score MIN_SCORE] [--only-200]
                                [--no-reqs] [--no-color] [--threads THREADS] [--json] [--verbose]
                                [--output OUTPUT] [--follow-redirects] [--user-agent USER_AGENT]
                                [--batch-size BATCH_SIZE] file

    positional arguments:
      file                  Input file containing URLs, one per line.

    optional arguments:
      -h, --help            show this help message and exit
      --config CONFIG       Path to scoring config JSON file (default: config.json).
      --min-score MIN_SCORE Only output URLs scoring equal or above this value (default: 0).
      --only-200            Only output URLs with HTTP status code 200.
      --no-reqs             Disable live HTTP requests; score based on URL analysis only.
      --no-color            Disable colored output (useful for plain text logs).
      --threads THREADS     Number of concurrent worker threads (default: 10).
      --json                Output results in JSON format.
      --verbose             Show detailed scoring tags for each URL.
      --output OUTPUT       Output results to specified file instead of stdout.
      --follow-redirects    Follow HTTP redirects on requests (default: off).
      --user-agent USER_AGENT  Custom User-Agent header for HTTP requests (default: recent Chrome).
      --batch-size BATCH_SIZE  Process URLs in memory-efficient batches of this size (disabled by default).


## Example Usage

Single-threaded keyword scoring only with batch processing and output to file:

    python3 waybackurl_ranker.py urls.txt --no-reqs --batch-size 5000 --output results.txt

Process all URLs with live HTTP requests, follow redirects, verbose output, and save JSON output:

    python3 waybackurl_ranker.py urls.txt --follow-redirects --verbose --json --output output.json

Filter to only high-risk URLS with score ≥ 10 and HTTP 200 status:

    python3 waybackurl_ranker.py urls.txt --min-score 10 --only-200

## Notes

- Batch size is **disabled by default** to process all URLs in memory with global sorting. Use batch mode for large files to avoid memory issues.
- Sorting after batch processing ensures global ordering of results by decreasing risk score.
- Large input files will be processed in chunks, with progress counters shown on the terminal.
- Unreachable domains are tracked to skip repeated failed requests.
- Known popular JavaScript libs (e.g., jQuery, React) are excluded from JS pattern matching to reduce false positives.
- Scoring is heuristic and optimized for triage, not definitive vulnerability detection. Always verify manually.
- Configuration is fully customizable via JSON to add keywords, regexes, and scoring weights.

## Installation

- Just clone or download!
- Requires Python 3.7+
- Dependencies (install via pip): pip install requests beautifulsoup4

## Thanks & Credits

- [tomnomnom](https://github.com/tomnomnom) for [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gigachad80](https://github.com/gigachad80) for keyword inspiration from [grep-backURLs](https://github.com/gigachad80/grep-backURLs/blob/main/grep_keywords.txt)

<3
