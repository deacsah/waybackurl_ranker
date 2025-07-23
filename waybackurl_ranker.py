import re
import requests
import sys
import argparse
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import threading

# === Version ===
VERSION = "1.3.0"

# === ASCII Art Banner ===
ASCII_BANNER = rf"""
+--------------------------------------------------+
|      WAYBACKURL RANKER — URL Risk Classifier     |
|                    v{VERSION}                        |
+--------------------------------------------------+
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

# Updated HTTP status scores with 200 worth 2 points instead of 5
STATUS_SCORE = {
    200: 2,
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

# JS Patterns and weights combined under one dict
JS_PATTERNS = {
    5: [
        r'(?i)apikey\s*[:=]\s*["\']?[A-Za-z0-9_\-]{10,}["\']?',
        r'(?i)auth(?:orization)?_token\s*[:=]\s*["\']?[A-Za-z0-9_\-]{10,}["\']?'
    ],
    4: [
        r'(?i)(username|user|email)\s*[:=]\s*["\']?[a-z0-9._%+-]+@?[a-z0-9.-]*["\']?',
        r'(?i)password\s*[:=]\s*["\']?.{4,}["\']?'
    ],
    3: [r'(?i)(https?:\/\/)?(www\.)?api\.[\w\/\.-]+'],
    2: [r'(?i)(client_id|client_secret)\s*[:=]'],
}

# Known JS libraries to exclude from JS pattern matches (prevent false positives)
KNOWN_JS_LIBS = ['jquery', 'react', 'vue', 'angular', 'lodash', 'backbone', 'ember', 'moment', 'd3']

# === Thread-safe tracking of unreachable domains ===
bad_domains = set()
domain_lock = threading.Lock()

# === Keyword-Based Score ===
def keyword_score(url):
    score = 0
    reasons = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Improved matching: check whole param keys and path segments exactly for sensitive keywords
    # Check params for exact keyword match (case-insensitive)
    for weight, keywords in KEYWORD_SCORES.items():
        for key in params:
            lower_key = key.lower()
            if any(lower_key == k for k in keywords):
                score += weight
                reasons.append(f"param:{key} (+{weight})")

    # Check path segments for keywords exactly (not substrings)
    path_segments = [seg.lower() for seg in parsed.path.strip('/').split('/')]
    for weight, keywords in KEYWORD_SCORES.items():
        for seg in path_segments:
            if seg in keywords:
                score += weight
                reasons.append(f"path:{seg} (+{weight})")

    if any(url.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        score += EXTENSION_SCORE
        reasons.append(f"suspicious extension (+{EXTENSION_SCORE})")

    for values in params.values():
        for v in values:
            if re.match(r'^[A-Za-z0-9+/=]{20,}$', v):
                score += 3
                reasons.append("high-entropy param value (+3)")

    # path depth = number of segments minus 2, minimum 0
    depth = max(0, len(path_segments) - 2)
    if depth:
        score += depth
        reasons.append(f"path depth +{depth}")

    return score, reasons

# === JavaScript File Inspection ===
def inspect_js(url):
    score = 0
    reasons = []
    try:
        resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200 and 'javascript' in resp.headers.get('Content-Type', ''):
            # Exclude known libraries based on url filename to reduce false positives
            lower_url = url.lower()
            if any(lib in lower_url for lib in KNOWN_JS_LIBS):
                return 0, []  # skip scoring JS libraries

            js = resp.text
            for weight, patterns in JS_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, js):
                        score += weight
                        reasons.append(f"JS match ({pat}) +{weight}")
    except:
        pass
    return score, reasons

# === HTTP Request + Content Analysis with Domain Skipping ===
def get_http_score(url, analyze_html=False):
    domain = urlparse(url).netloc

    with domain_lock:
        if domain in bad_domains:
            return 0, [], None

    try:
        resp = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        status_mod = STATUS_SCORE.get(resp.status_code, 0)
        reasons = [f"HTTP {resp.status_code} (+{status_mod})"] if status_mod else []
        content_mod = 0

        if analyze_html and 'text/html' in resp.headers.get('Content-Type', ''):
            soup = BeautifulSoup(resp.text, 'html.parser')
            text = soup.get_text().lower()
            if any(term in text for term in HTML_INDICATORS):
                content_mod += 3
                reasons.append("HTML indicator match (+3)")

        return status_mod + content_mod, reasons, resp.status_code

    except requests.exceptions.RequestException as e:
        if isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            with domain_lock:
                bad_domains.add(domain)
        return -5, ["request failed (-5)"], None

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
    base_score, base_reasons = keyword_score(url)
    http_score, http_reasons, status = (0, [], None)
    js_score, js_reasons = (0, [])

    if use_requests:
        http_score, http_reasons, status = get_http_score(url, analyze_html)
        if url.lower().endswith(".js"):
            js_score, js_reasons = inspect_js(url)

    total = base_score + http_score + js_score
    reasons = base_reasons + http_reasons + js_reasons

    return {
        "url": url,
        "score": total,
        "status": status,
        "description": "; ".join(reasons) if reasons else "-"
    }

# === Main function ===
def main():
    print(ASCII_BANNER)

    class BannerHelpFormatter(argparse.HelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            return super().add_usage(usage, actions, groups, prefix=prefix or "Usage: ")

    parser = argparse.ArgumentParser(
        description=f"Rank potentially sensitive URLs based on keywords, HTTP status, JS and HTML analysis. v{VERSION}",
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
    parser.add_argument("--verbose", action="store_true", help="Show verbose scoring reasons for each URL")
    parser.add_argument("--output", type=str, default=None, help="Output file path to save results")

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

    filtered.sort(key=lambda r: (-r["score"], r["url"]))

    output_lines = []
    header = f"{'Score':<7} {'Status':<7} URL"
    output_lines.append(header)
    output_lines.append("-" * 120)

    for r in filtered:
        status = r['status'] if r['status'] is not None else '-'
        score = r['score']
        line = f"{str(score):<7} {status:<7} {r['url']}"
        if not args.no_color:
            line = colorize(line, score, True)
        output_lines.append(line)
        if args.verbose:
            verbose_line = f"{'':<15} {r['description']}"
            if not args.no_color:
                verbose_line = colorize(verbose_line, score, True)
            output_lines.append(verbose_line)

    output_text = "\n".join(output_lines)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f_out:
                # Remove ANSI color codes for clean file output
                ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
                clean_text = ansi_escape.sub('', output_text)
                f_out.write(clean_text)
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")
    else:
        print(output_text)


if __name__ == "__main__":
    main()
