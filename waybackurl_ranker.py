import re
import requests
import sys
import argparse
import json
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import threading
import os
import tempfile

VERSION = "2.1.2"

# === ANSI Colors ===
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

# === ASCII Banner ===
ASCII_BANNER = rf"""
{GREEN}+--------------------------------------------------{GREEN}+
{GREEN}|        WAYBACKURL RANKER                         {GREEN}|
{GREEN}|        URL Risk Classifier & Score v{VERSION:<6}       {GREEN}|
{GREEN}+--------------------------------------------------{GREEN}+
"""

# === Globals for scoring ===
CONFIG = {}
bad_domains = set()
domain_lock = threading.Lock()

# --- Utility functions for colored feedback/progress ---
def print_settings_feedback(args, total_urls):
    print(YELLOW + "="*64 + RESET)
    print(YELLOW + "WAYBACKURL RANKER SETTINGS" + RESET)
    print(f"- Input file:     {CYAN}{args.file}{RESET} ({GREEN}{total_urls} URLs{RESET})")
    print(f"- Config file:    {CYAN}{args.config}{RESET}")
    print(f"- Worker threads: {CYAN}{args.threads}{RESET}")
    if args.no_reqs:
        print(f"- HTTP requests:  {RED}DISABLED (--no-reqs){RESET}")
    else:
        print(f"- HTTP requests:  {GREEN}ENABLED{RESET}")
        print(f"- User-Agent:     {CYAN}{args.user_agent}{RESET}")
        print(f"- Follow redirects: {GREEN if args.follow_redirects else RED}{'YES' if args.follow_redirects else 'NO'}{RESET}")
    print(f"- Output:         {CYAN}{'stdout' if not args.output else args.output}{RESET}")
    print(f"- Colors:         {GREEN if (not args.no_color and not args.output and not args.json) else RED}{'ENABLED' if (not args.no_color and not args.output and not args.json) else 'DISABLED'}{RESET}")
    print(f"- Min score:      {CYAN}{args.min_score}{RESET}")
    print(f"- Only 200:       {GREEN if args.only_200 else RED}{'YES (--only-200)' if args.only_200 else 'NO'}{RESET}")
    print(f"- Format:         {CYAN}{'JSON (--json)' if args.json else 'Text'}{RESET}")
    print(f"- Verbose:        {GREEN if args.verbose else RED}{'YES (--verbose)' if args.verbose else 'NO'}{RESET}")
    if args.batch_size is not None:
        batches = int((total_urls + args.batch_size - 1) / args.batch_size)
        print(f"- Batch size:     {CYAN}{args.batch_size}{RESET} (--batch-size, {CYAN}{batches}{RESET} batches)")
        print(f"{CYAN}-> Batched processing enabled. Will sort output file after processing.{RESET}\n")
    else:
        print(f"{CYAN}-> Classic mode: All URLs processed and sorted in memory for global sort order.{RESET}\n")
    print(YELLOW + "="*64 + RESET)
    if args.batch_size:
        print(f"{CYAN}[*] Processing {total_urls} URLs in batches of {args.batch_size}, {args.threads} worker threads.{RESET}")
        print(f"{CYAN}[*] Output will be sorted after all batches.{RESET}")
    else:
        print(f"{CYAN}[*] Processing all {total_urls} URLs in memory (classic mode, globally sorted).{RESET}")
    print(flush=True)

def print_progress(step_label, current, total):
    percent = (current / total) * 100 if total else 100
    sys.stdout.write(f"\r{CYAN}{step_label}{RESET} {current} of {total} ({percent:.2f}%)")
    sys.stdout.flush()

def load_config(path):
    global CONFIG
    try:
        with open(path, "r") as f:
            CONFIG = json.load(f)
    except Exception as e:
        print(f"{RED}[!] Failed to load config: {e}{RESET}")
        sys.exit(1)

def keyword_score(url):
    score = 0
    tags = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path_segments = [seg.lower() for seg in parsed.path.strip("/").split("/")]
    matched_segments = set()

    for weight, keywords in CONFIG.get("KEYWORD_SCORES", {}).items():
        int_weight = int(weight)
        for key in params:
            if key.lower() in keywords:
                score += int_weight
                tags.append(f"param:{key} (+{weight})")
        for seg in path_segments:
            if seg in keywords and seg not in matched_segments:
                score += int_weight
                tags.append(f"path token:{seg} (+{weight})")
                matched_segments.add(seg)
        for seg in path_segments:
            if seg in matched_segments:
                continue
            for subtoken in re.split(r'[-_]', seg):
                if subtoken in keywords:
                    score += int_weight
                    tags.append(f"path subtoken:{subtoken} (+{weight})")

    for ext, ext_score in CONFIG.get("EXTENSION_SCORES", {}).items():
        if url.lower().endswith(ext):
            score += ext_score
            tags.append(f"extension:{ext} (+{ext_score})")
    for values in params.values():
        for v in values:
            if re.match(r'^[A-Za-z0-9+/=]{20,}$', v):
                score += 3
                tags.append("high-entropy param value (+3)")
    depth = max(0, len(path_segments) - 2)
    if depth:
        score += depth
        tags.append(f"path depth +{depth}")
    for weight, patterns in CONFIG.get("EXTENDED_SENSITIVE_PATTERNS", {}).items():
        for pattern in patterns:
            if re.search(pattern, url):
                score += int(weight)
                tags.append(f"pattern:{pattern} (+{weight})")
    return score, tags

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
    except: pass
    return score, tags

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

def colorize(text, score, use_color=True):
    if not use_color:
        return text
    if score >= 20:
        return f"{RED}{text}{RESET}"
    elif score >= 10:
        return f"{YELLOW}{text}{RESET}"
    else:
        return f"{GREEN}{text}{RESET}"

def print_header(verbose, use_color, output_file=None):
    if verbose:
        header = f"{'Score':<7} {'Status':<7} {'Scoring':<60} URL"
    else:
        header = f"{'Score':<7} {'Status':<7} URL"
    if output_file:
        output_file.write(header + "\n" + ("-" * 100) + "\n")
    else:
        print(colorize(header, 0, use_color=use_color))
        print(colorize("-" * 100, 0, use_color=use_color))

def output_results_batch(results_batch, verbose, use_color, output_file=None):
    results_batch.sort(key=lambda r: (-r['score'], r['url']))
    lines = []
    for r in results_batch:
        if verbose:
            tag_str = "; ".join(r['tags'])
            line = f"{r['score']:<7} {str(r['status'] or '-'): <7} {tag_str:<60} {r['url']}"
        else:
            line = f"{r['score']:<7} {str(r['status'] or '-'): <7} {r['url']}"
        if use_color and not output_file:
            line = colorize(line, r['score'], use_color=True)
        lines.append(line)
    output_text = "\n".join(lines)
    if output_file:
        output_file.write(output_text + "\n")
        output_file.flush()
    else:
        print(output_text)

# ======= SORTING FUNCTIONS WITH PROGRESS BAR ==========

def sort_text_output(input_file_path, output_file_path):
    """Sort by score and then URL for plain text output."""
    def parse_line(line):
        fields = line.strip('\n').split()
        try:
            score = int(fields[0])
            url = fields[-1]
        except Exception:
            return (-float('inf'), "", line)
        return (score, url, line)
    # Count and read lines for progress
    with open(input_file_path, "r", encoding="utf-8") as infile:
        all_lines = [line for line in infile if line.strip() and not set(line.strip()) == {"-"} and not line.lower().startswith("score")]
    total_lines = len(all_lines)
    lines = []
    for idx, line in enumerate(all_lines, 1):
        lines.append(parse_line(line))
        if idx % 1000 == 0 or idx == total_lines:
            print_progress("Reading for sorting:", idx, total_lines)
    print()
    lines.sort(key=lambda x: (-x[0], x[1]))
    with open(output_file_path, "w", encoding="utf-8") as outfile:
        outfile.write(f"{'Score':<7} {'Status':<7} URL\n")
        outfile.write("-" * 100 + "\n")
        for i, (_, _, line) in enumerate(lines, 1):
            outfile.write(line)
            if not line.endswith("\n"): outfile.write("\n")
            if i % 1000 == 0 or i == total_lines:
                print_progress("Writing sorted file:", i, total_lines)
    print()

def sort_json_output(input_file_path, output_file_path):
    """Sort newline-delimited JSON by score/url."""
    objects = []
    with open(input_file_path, "r", encoding="utf-8") as infile:
        all_lines = [line for line in infile if line.strip() and not line.strip() in ("[", "]", ",")]
    total_lines = len(all_lines)
    for idx, line in enumerate(all_lines, 1):
        try:
            obj = json.loads(line.rstrip(","))
            objects.append(obj)
        except Exception:
            continue
        if idx % 1000 == 0 or idx == total_lines:
            print_progress("Reading for sorting:", idx, total_lines)
    print()
    objects.sort(key=lambda r: (-r['score'], r['url']))
    with open(output_file_path, "w", encoding="utf-8") as out:
        out.write("[\n")
        for i, obj in enumerate(objects):
            out.write(json.dumps(obj, indent=2))
            if i < len(objects) - 1:
                out.write(",\n")
            if (i+1) % 1000 == 0 or (i+1) == len(objects):
                print_progress("Writing sorted file:", i+1, len(objects))
        out.write("\n]\n")
    print()

def main():
    print(ASCII_BANNER)
    parser = argparse.ArgumentParser(description="WaybackURL Ranker: Classify and score URLs by risk level.")
    parser.add_argument("file", help="Input file containing URLs to process, one URL per line.")
    parser.add_argument("--config", default="config.json", help="Path to scoring config JSON file (default: %(default)s).")
    parser.add_argument("--min-score", type=int, default=0, help="Only output URLs scoring at least this value (default: %(default)d).")
    parser.add_argument("--only-200", action="store_true", help="Only output URLs with HTTP status code 200.")
    parser.add_argument("--no-reqs", action="store_true", help="Disable all live HTTP requests; only keyword scoring is done.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--threads", type=int, default=10, help="Number of worker threads to use for URL processing (default: %(default)d).")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    parser.add_argument("--verbose", action="store_true", help="Show detailed scoring tags per URL.")
    parser.add_argument("--output", help="Write output to specified file path instead of stdout.")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects on requests (default: not followed).")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36", help="Custom User-Agent header (default: %(default)s).")
    parser.add_argument("--batch-size", type=int, default=None, help="Number of URLs to process per batch; enables batched and memory-efficient mode. Omit for classic mode.")

    args = parser.parse_args()
    load_config(args.config)

    try:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{RED}[!] Failed to read input: {e}{RESET}")
        sys.exit(1)

    print_settings_feedback(args, len(urls))
    use_reqs = not args.no_reqs
    use_color = not args.no_color and not args.output and not args.json

    # ----------- CLASSIC MODE -----------
    if args.batch_size is None:
        all_results = []
        executor = ThreadPoolExecutor(max_workers=args.threads)
        total_urls = len(urls)
        futures = []
        for idx, u in enumerate(urls):
            futures.append(executor.submit(process_url, u, use_reqs, args.user_agent, args.follow_redirects))
            if (idx+1) % 1000 == 0 or (idx+1) == total_urls:
                print_progress("URLs submitted:", idx+1, total_urls)
        print()
        for idx, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
                if result["score"] >= args.min_score and (not args.only_200 or result["status"] == 200):
                    all_results.append(result)
            except Exception as e:
                print(f"{RED}[!] Error processing URL: {e}{RESET}", file=sys.stderr)
            if idx % 1000 == 0 or idx == total_urls:
                print_progress("URLs processed:", idx, total_urls)
        print()
        all_results.sort(key=lambda r: (-r['score'], r['url']))
        if args.output:
            output_file = open(args.output, "w", encoding="utf-8")
        else:
            output_file = None
        if args.json:
            data = json.dumps(all_results, indent=2)
            if output_file:
                output_file.write(data + "\n")
                output_file.close()
            else:
                print(data)
        else:
            print_header(args.verbose, use_color, output_file=output_file)
            output_results_batch(all_results, args.verbose, use_color, output_file=output_file)
            if output_file: output_file.close()

    # ----------- BATCHED MODE -----------
    else:
        # Output to temp file first
        temp_output = tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', delete=False)
        batch_size = args.batch_size
        executor = ThreadPoolExecutor(max_workers=args.threads)
        total_urls = len(urls)
        processed_url_count = 0

        # Write header if not JSON
        if not args.json:
            temp_output.write(f"{'Score':<7} {'Status':<7} URL\n")
            temp_output.write("-" * 100 + "\n")

        for i in range(0, total_urls, batch_size):
            batch_urls = urls[i:i + batch_size]
            futures = []
            for u in batch_urls:
                futures.append(executor.submit(process_url, u, use_reqs, args.user_agent, args.follow_redirects))
            batch_results = []
            for idx, future in enumerate(as_completed(futures), 1):
                try:
                    res = future.result()
                    if res["score"] >= args.min_score and (not args.only_200 or res["status"] == 200):
                        batch_results.append(res)
                except Exception as e:
                    print(f"{RED}[!] Error processing URL: {e}{RESET}", file=sys.stderr)
                processed_url_count += 1
                print_progress("URLs processed:", processed_url_count, total_urls)
            print()
            # Write each line immediately as newline-JSON or plain text
            if args.json:
                for idx, res in enumerate(batch_results):
                    out_line = json.dumps(res, indent=2)
                    if not out_line.endswith("\n"): out_line += "\n"
                    temp_output.write(out_line)
            else:
                output_results_batch(batch_results, args.verbose, use_color=False, output_file=temp_output)
            temp_output.flush()
        executor.shutdown(wait=True)
        temp_output.close()
        print(f"\n{CYAN}[*] URLs processed! Now sorting output file for global order.{RESET}")

        # Now sort the temp output file and write result to proper destination
        if args.output:
            output_file_path = args.output
        else:
            output_file_path = None  # We'll print to stdout

        sorted_file = tempfile.NamedTemporaryFile(delete=False, mode='w+', encoding='utf-8')
        sorted_path = sorted_file.name
        sorted_file.close()

        # Use appropriate sorter
        if args.json:
            sort_json_output(temp_output.name, sorted_path)
        else:
            sort_text_output(temp_output.name, sorted_path)

        # Output sorted results to the final output or stdout
        with open(sorted_path, "r", encoding="utf-8") as fin:
            if output_file_path:
                with open(output_file_path, "w", encoding="utf-8") as fout:
                    for idx, line in enumerate(fin):
                        fout.write(line)
                        if idx and idx % 1000 == 0:
                            print_progress("Final output (sorted):", idx, processed_url_count)
                    print()
            else:
                for idx, line in enumerate(fin):
                    print(line, end="")
                    if idx and idx % 1000 == 0:
                        print_progress("Final output (sorted):", idx, processed_url_count)
                print()
        os.remove(temp_output.name)
        os.remove(sorted_path)

    print(GREEN + "[*] All done.\n" + RESET)

if __name__ == "__main__":
    main()
