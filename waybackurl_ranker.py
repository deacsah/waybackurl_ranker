import re
import requests
import sys
import argparse
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import threading

# === Version ===
VERSION = "1.1.0"

# === ASCII Art Banner ===
ASCII_BANNER = rf"""
+---------------------------------------------+
|    WAYBACKURL RANKER — URL Risk Classifier  |
|              v{VERSION}                         |
+---------------------------------------------+
"""

# === ANSI Color Codes ===
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

# === Scoring Definitions ===
KEYWORD_SCORES = {
    10: ['password', 'passwd', 'auth_token'],
    9:  ['token', 'apikey', 'secret', 'jwt', 'access_token', 'authorization'],
    8:  ['email', 'ssn', 'dob', 'phone', 'account_number'],
    7:  ['card', 'cvv', 'iban', 'credit'],
    6:  ['admin', 'config', 'debug', 'root', 'sso'],
    5:  ['staging', 'dev', 'test', 'local'],
    4:  ['file', 'doc', 'pdf', 'download', 'backup', 'export'],
    3:  ['name', 'id', 'user', 'username', 'userid', 'login'],
    2:  ['page', 'search', 'q'],
}

STATUS_SCORE = {
    200: 5,
    401: 4,
    403: 3,
    301: 2,
    302: 2,
    500: 1,
    404: -3,
}

SUSPICIOUS_EXTENSIONS = ['.bak', '.sql', '.zip', '.env', '.log']
EXTENSION_SCORE = 4
HTML_INDICATORS = ['login', 'admin panel', 'reset password', 'dashboard', 'token']

# === Thread-safe tracking of unreachable domains ===
bad_domains = set()
domain_lock = threading.Lock()


# === Keyword-Based Score ===
def keyword_score(url):
    score = 0
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for weight, keywords in KEYWORD_SCORES.items():
        for key in params:
            if any(k in key.lower() for k in keywords):
                score += weight

    for weight, keywords in KEYWORD_SCORES.items():
        for keyword in keywords:
            if keyword in parsed.path.lower():
                score += weight

    if any(url.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        score += EXTENSION_SCORE

    for values in params.values():
        for v in values:
            if re.match(r'^[A-Za-z0-9+/=]{20,}$', v):
                score += 3

    score += max(0, len(parsed.path.strip('/').split('/')) - 2)

    return score


# === HTTP Request + Content Analysis with Domain Skipping ===
def get_http_score(url, analyze_html=False):
    domain = urlparse(url).netloc

    with domain_lock:
        if domain in bad_domains:
            # Skip HTTP check if domain known bad
            return 0, None

    try:
        resp = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        status_mod = STATUS_SCORE.get(resp.status_code, 0)
        content_mod = 0

        if analyze_html and 'text/html' in resp.headers.get('Content-Type', ''):
            soup = BeautifulSoup(resp.text, 'html.parser')
            text = soup.get_text().lower()
            if any(term in text for term in HTML_INDICATORS):
                content_mod += 3

        return status_mod + content_mod, resp.status_code

    except requests.exceptions.RequestException as e:
        # On DNS or connection failure, mark domain bad
        if isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            with domain_lock:
                bad_domains.add(domain)
        return -5, None


# === Colorize output based on score ===
def colorize(text, score, use_color=True):
    if not use_color:
        return text
    if score >= 20:
        return f"{RED}{text}{RESET}"
    elif score >= 10:
        return f"{YELLOW}{text}{RESET}"
    else:
        return f"{GREEN}{text}{RESET}"


# === Process a single URL ===
def process_url(url, use_requests=True, analyze_html=False):
    base_score = keyword_score(url)
    http_score, status = (0, None)

    if use_requests:
        http_score, status = get_http_score(url, analyze_html)

    total = base_score + http_score
    return {
        "url": url,
        "score": total,
        "status": status,
    }


# === Main function ===
def main():
    print(ASCII_BANNER)

    class BannerHelpFormatter(argparse.HelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            return super().add_usage(usage, actions, groups, prefix=prefix or "Usage: ")

    parser = argparse.ArgumentParser(
        description=f"Rank potentially sensitive URLs based on keywords, HTTP status, and content inspection. v{VERSION}",
        formatter_class=BannerHelpFormatter,
        add_help=False
    )

    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    parser.add_argument("file", help="Input file containing one URL per line")
    parser.add_argument("--min-score", type=int, default=0, help="Only show URLs with score >= this value")
    parser.add_argument("--only-200", action="store_true", help="Only show URLs that return HTTP 200")
    parser.add_argument("--no-reqs", action="store_true", help="Don't send HTTP requests (keyword-based only)")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    try:
        with open(args.file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        sys.exit(1)

    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(process_url, url, not args.no_reqs, analyze_html=True)
            for url in urls
        ]
        for future in futures:
            try:
                results.append(future.result())
            except Exception as e:
                print(f"[!] Error processing URL: {e}")

    filtered = [
        r for r in results
        if r["score"] >= args.min_score and (not args.only_200 or r["status"] == 200)
    ]

    filtered.sort(key=lambda r: r["score"], reverse=True)

    print(f"\n{'Score':<7} {'Status':<7} URL")
    print("-" * 100)
    for r in filtered:
        status = r['status'] if r['status'] is not None else '-'
        print(f"{colorize(str(r['score']), r['score'], not args.no_color):<7} {status:<7} {r['url']}")


if __name__ == "__main__":
    main()
