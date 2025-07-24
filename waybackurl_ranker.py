import re
import requests
import sys
import argparse
import json
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import threading
import os

VERSION = "1.4.2"

# === ANSI Colors ===
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

# === ASCII Banner ===
ASCII_BANNER = rf"""
+--------------------------------------------------+
|      WAYBACKURL RANKER — URL Risk Classifier     |
|                    v{VERSION}                        |
+--------------------------------------------------+
"""

# === Globals for scoring ===
CONFIG = {}
bad_domains = set()
domain_lock = threading.Lock()

# === Load Scoring Config ===
def load_config(path):
    global CONFIG
    try:
        with open(path, "r") as f:
            CONFIG = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
        sys.exit(1)

# === Keyword Scoring ===
def keyword_score(url):
    score = 0
    tags = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path_segments = [seg.lower() for seg in parsed.path.strip("/").split("/")]

    matched_segments = set()

    for weight, keywords in CONFIG.get("KEYWORD_SCORES", {}).items():
        int_weight = int(weight)
        # Parameter keys
        for key in params:
            if key.lower() in keywords:
                score += int_weight
                tags.append(f"param:{key} (+{weight})")

        # Full path segments
        for seg in path_segments:
            if seg in keywords and seg not in matched_segments:
                score += int_weight
                tags.append(f"path token:{seg} (+{weight})")
                matched_segments.add(seg)

        # Subtoken matching (avoiding double-counting)
        for seg in path_segments:
            if seg in matched_segments:
                continue
            for subtoken in re.split(r'[-_]', seg):
                if subtoken in keywords:
                    score += int_weight
                    tags.append(f"path subtoken:{subtoken} (+{weight})")

    # Extension-based scoring
    for ext, ext_score in CONFIG.get("EXTENSION_SCORES", {}).items():
        if url.lower().endswith(ext):
            score += ext_score
            tags.append(f"extension:{ext} (+{ext_score})")

    # High-entropy param values
    for values in params.values():
        for v in values:
            if re.match(r'^[A-Za-z0-9+/=]{20,}$', v):
                score += 3
                tags.append("high-entropy param value (+3)")

    # Path depth
    depth = max(0, len(path_segments) - 2)
    if depth:
        score += depth
        tags.append(f"path depth +{depth}")

    # Extended regex-based patterns
    for weight, patterns in CONFIG.get("EXTENDED_SENSITIVE_PATTERNS", {}).items():
        for pattern in patterns:
            if re.search(pattern, url):
                score += int(weight)
                tags.append(f"pattern:{pattern} (+{weight})")

    return score, tags

# === JavaScript Scanning ===
def inspect_js(url, user_agent, follow_redirects):
    score = 0
    tags = []
    try:
        resp = requests.get(url, timeout=5, headers={'User-Agent': user_agent}, allow_redirects=follow_redirects)
        if resp.status_code == 200 and 'javascript' in resp.headers.get('Content-Type', ''):
            js = resp.text
            for weight, patterns in CONFIG.get("JS_PATTERNS", {}).items():
                for pat in patterns:
                    if re.search(pat, js):
                        score += int(weight)
                        tags.append(f"JS match ({pat}) +{weight}")
            for weight, patterns in CONFIG.get("EXTENDED_SENSITIVE_PATTERNS", {}).items():
                for pattern in patterns:
                    if re.search(pattern, js):
                        score += int(weight)
                        tags.append(f"JS sensitive pattern ({pattern}) +{weight}")
    except:
        pass
    return score, tags

# === HTTP and HTML analysis ===
def get_http_score(url, user_agent, follow_redirects):
    domain = urlparse(url).netloc
    with domain_lock:
        if domain in bad_domains:
            return 0, [], None

    try:
        resp = requests.get(url, timeout=5, headers={'User-Agent': user_agent}, allow_redirects=follow_redirects)
        code = resp.status_code
        score = CONFIG.get("STATUS_SCORES", {}).get(str(code), 0)
        tags = [f"HTTP {code} (+{score})"] if score else []

        if 'text/html' in resp.headers.get('Content-Type', ''):
            text = BeautifulSoup(resp.text, 'html.parser').get_text().lower()
            html_indicators = CONFIG.get("HTML_INDICATORS", {})
            if isinstance(html_indicators, dict):
                for keyword, val in html_indicators.items():
                    if keyword.lower() in text:
                        score += val
                        tags.append(f"HTML indicator match '{keyword}' (+{val})")
            else:
                for ind in html_indicators:
                    if ind.lower() in text:
                        score += 3
                        tags.append(f"HTML indicator match (+3)")

            for weight, patterns in CONFIG.get("EXTENDED_SENSITIVE_PATTERNS", {}).items():
                for pattern in patterns:
                    if re.search(pattern, resp.text):
                        score += int(weight)
                        tags.append(f"HTML sensitive pattern ({pattern}) +{weight}")

        return score, tags, code

    except requests.exceptions.RequestException:
        with domain_lock:
            bad_domains.add(domain)
        return 0, [], None

# === URL Processor ===
def process_url(url, use_reqs, user_agent, follow_redirects):
    base_score, base_tags = keyword_score(url)
    http_score, http_tags, status = (0, [], None)
    js_score, js_tags = (0, [])

    if use_reqs:
        http_score, http_tags, status = get_http_score(url, user_agent, follow_redirects)
        if url.lower().endswith(".js"):
            js_score, js_tags = inspect_js(url, user_agent, follow_redirects)

    total = base_score + http_score + js_score
    tags = base_tags + http_tags + js_tags

    return {
        "url": url,
        "score": total,
        "status": status,
        "tags": tags
    }

# === Color Output ===
def colorize(text, score, use_color=True):
    if not use_color:
        return text
    if score >= 20:
        return f"{RED}{text}{RESET}"
    elif score >= 10:
        return f"{YELLOW}{text}{RESET}"
    else:
        return f"{GREEN}{text}{RESET}"

# === Main ===
def main():
    print(ASCII_BANNER)

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Input file with URLs")
    parser.add_argument("--config", default="config.json", help="Path to JSON scoring config")
    parser.add_argument("--min-score", type=int, default=0)
    parser.add_argument("--only-200", action="store_true")
    parser.add_argument("--no-reqs", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36", help="Custom User-Agent header")
    args = parser.parse_args()

    load_config(args.config)

    try:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read input: {e}")
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_url, u, not args.no_reqs, args.user_agent, args.follow_redirects) for u in urls]
        for future in futures:
            try:
                results.append(future.result())
            except Exception as e:
                print(f"[!] Error processing URL: {e}")

    filtered = [r for r in results if r['score'] >= args.min_score and (not args.only_200 or r['status'] == 200)]
    filtered.sort(key=lambda r: (-r['score'], r['url']))

    output_lines = []
    if args.json:
        output_data = json.dumps(filtered, indent=2)
        output_lines.append(output_data)
    else:
        if args.verbose:
            header = f"{'Score':<7} {'Status':<7} {'Scoring':<60} URL"
        else:
            header = f"{'Score':<7} {'Status':<7} URL"

        output_lines.append(header)
        output_lines.append("-" * 100)
        for r in filtered:
            if args.verbose:
                tag_str = "; ".join(r['tags'])
                line = f"{r['score']:<7} {str(r['status'] or '-'): <7} {tag_str:<60} {r['url']}"
            else:
                line = f"{r['score']:<7} {str(r['status'] or '-'): <7} {r['url']}"
            output_lines.append(colorize(line, r['score'], use_color=not args.no_color and not args.output and not args.json))

    output_text = "\n".join(output_lines)
    if args.output:
        with open(args.output, "w") as out:
            out.write(output_text)
    else:
        print(output_text)

if __name__ == "__main__":
    main()
