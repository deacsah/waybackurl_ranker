import re
import requests
import sys
import argparse
import json
import heapq
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import threading
import os
import tempfile

VERSION = "2.2.1"

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
    print(f"- Colors:         {GREEN if (not args.no_color) else RED}{'ENABLED' if (not args.no_color) else 'DISABLED'}{RESET}")
    print(f"- Min score:      {CYAN}{args.min_score}{RESET}")
    print(f"- Only 200:       {GREEN if args.only_200 else RED}{'YES (--only-200)' if args.only_200 else 'NO'}{RESET}")
    print(f"- Format:         {CYAN}{'JSON (--json)' if args.json else 'Text'}{RESET}")
    print(f"- Verbose:        {GREEN if args.verbose else RED}{'YES (--verbose)' if args.verbose else 'NO'}{RESET}")
    if args.batch_size is not None:
        batches = int((total_urls + args.batch_size - 1) / args.batch_size)
        # Removed trailing newline here to avoid blank line
        print(f"- Batch size:     {CYAN}{args.batch_size}{RESET} (--batch-size, {CYAN}{batches}{RESET} batches)")
        print(f"{CYAN}-> Batched processing enabled with external merge sort to handle large input.{RESET}")
    else:
        print(f"{CYAN}-> Classic mode: All URLs processed and sorted in memory for global sort order.{RESET}")
    print(YELLOW + "="*64 + RESET)
    if args.batch_size:
        print(f"{CYAN}[*] Processing {total_urls} URLs in batches of {args.batch_size}, {args.threads} worker threads.{RESET}")
        print(f"{CYAN}[*] Output will be merged from sorted chunks after batch processing.{RESET}")
    else:
        print(f"{CYAN}[*] Processing all {total_urls} URLs in memory (classic mode, globally sorted).{RESET}")
    print(flush=True)

def print_progress(step_label, current, total):
    try:
        percent = (current / total) * 100 if total else 100
        status = f"{current} of {total} ({percent:.2f}%)"
    except Exception:
        # If total is not numeric (like "?" etc), fallback gracefully
        status = f"{current} of {total}"
    sys.stdout.write(f"\r{CYAN}{step_label}{RESET} {status}")
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
        if use_color:
            line = colorize(line, r['score'], use_color=True)
        lines.append(line)
    output_text = "\n".join(lines)
    if output_file:
        output_file.write(output_text + "\n")
        output_file.flush()
    else:
        print(output_text)

def parse_text_line(line):
    fields = line.strip('\n').split()
    try:
        score = int(fields[0])
    except Exception:
        score = -float('inf')
    url = fields[-1] if len(fields) > 0 else ""
    return (score, url, line)

def write_sorted_chunk_file_text(results, file_path, verbose):
    results.sort(key=lambda r: (-r['score'], r['url']))
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(f"{'Score':<7} {'Status':<7} URL\n")
        f.write("-" * 100 + "\n")
        for r in results:
            if verbose:
                tag_str = "; ".join(r['tags'])
                line = f"{r['score']:<7} {str(r['status'] or '-'): <7} {tag_str:<60} {r['url']}\n"
            else:
                line = f"{r['score']:<7} {str(r['status'] or '-'): <7} {r['url']}\n"
            f.write(line)

def write_sorted_chunk_file_json(results, file_path):
    results.sort(key=lambda r: (-r['score'], r['url']))
    with open(file_path, "w", encoding="utf-8") as f:
        for r in results:
            json.dump(r, f, indent=2)
            f.write("\n")

def iter_file_lines_skipping_header(fp):
    first_line = True
    second_line = True
    for line in fp:
        if first_line:
            first_line = False
            continue
        if second_line:
            second_line = False
            continue
        yield line.rstrip('\n')

def merge_sorted_text_chunks(chunk_files, final_out, verbose, use_color):
    file_iters = []
    files = []
    try:
        for chunk in chunk_files:
            f = open(chunk, "r", encoding="utf-8")
            files.append(f)
            file_iters.append(iter_file_lines_skipping_header(f))

        def wrapped_iter(it):
            for line in it:
                score, url, _ = parse_text_line(line)
                yield ((-score, url), line)

        wrapped_iters = [wrapped_iter(it) for it in file_iters]

        merged_iter = heapq.merge(*wrapped_iters)

        header_line = f"{'Score':<7} {'Status':<7} URL\n"
        separator_line = "-" * 100 + "\n"
        final_out.write(header_line)
        final_out.write(separator_line)

        count = 0
        for _, line in merged_iter:
            out_line = line
            if use_color:
                score, _, _ = parse_text_line(line)
                out_line = colorize(line, score, use_color=True)
            final_out.write(out_line + "\n")
            count += 1
            if count % 1000 == 0:
                print_progress("Writing merged output:", count, "?")
    finally:
        for f in files:
            f.close()

def merge_sorted_json_chunks(chunk_files, final_out):
    fps = [open(cf, "r", encoding="utf-8") for cf in chunk_files]

    def gen_file(fp, i):
        for line in fp:
            try:
                obj = json.loads(line.strip())
                key = (-obj['score'], obj['url'])
                yield (key, obj, i)
            except Exception:
                continue

    gens = [gen_file(fp, idx) for idx, fp in enumerate(fps)]

    heap = []
    for idx, g in enumerate(gens):
        try:
            item = next(g)
            heap.append(item)
        except StopIteration:
            pass
    heapq.heapify(heap)

    final_out.write("[\n")
    first = True
    count = 0
    while heap:
        key, obj, idx = heapq.heappop(heap)
        if not first:
            final_out.write(",\n")
        else:
            first = False
        json.dump(obj, final_out, indent=2)
        count += 1
        if count % 1000 == 0:
            print_progress("Writing merged output:", count, "?")
        try:
            item = next(gens[idx])
            heapq.heappush(heap, item)
        except StopIteration:
            continue
    final_out.write("\n]\n")

    for fp in fps:
        fp.close()

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
    parser.add_argument("--batch-size", type=int, default=None, help="Number of URLs to process in each batch; enables memory-efficient external merge sort mode.")

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
    use_color = not args.no_color

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
        # New line before final message to ensure no line overwrite with carriage return
        print()
        print(GREEN + "[*] All done.\n" + RESET)
        return

    # ----------- BATCHED MODE WITH EXTERNAL MERGE SORT -----------
    batch_size = args.batch_size
    total_urls = len(urls)
    executor = ThreadPoolExecutor(max_workers=args.threads)
    processed_url_count = 0
    sorted_chunk_files = []

    for i in range(0, total_urls, batch_size):
        batch_urls = urls[i:i + batch_size]
        futures = [executor.submit(process_url, u, use_reqs, args.user_agent, args.follow_redirects) for u in batch_urls]
        batch_results = []
        for idx, future in enumerate(as_completed(futures), 1):
            try:
                res = future.result()
                if res["score"] >= args.min_score and (not args.only_200 or res["status"] == 200):
                    batch_results.append(res)
            except Exception as e:
                print(f"{RED}[!] Error processing URL: {e}{RESET}", file=sys.stderr)
            processed_url_count += 1
            if processed_url_count % 1000 == 0 or processed_url_count == total_urls:
                print_progress("URLs processed:", processed_url_count, total_urls)
        print()

        chunk_file = tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8')
        chunk_file_path = chunk_file.name
        chunk_file.close()

        if args.json:
            write_sorted_chunk_file_json(batch_results, chunk_file_path)
        else:
            write_sorted_chunk_file_text(batch_results, chunk_file_path, args.verbose)

        sorted_chunk_files.append(chunk_file_path)

    executor.shutdown(wait=True)
    print(f"\n{CYAN}[*] All batches processed. Starting merge of {len(sorted_chunk_files)} sorted chunks...{RESET}")

    if args.output:
        final_output = open(args.output, "w", encoding="utf-8")
        final_output_is_file = True
    else:
        final_output = sys.stdout
        final_output_is_file = False

    if args.json:
        merge_sorted_json_chunks(sorted_chunk_files, final_output)
    else:
        merge_sorted_text_chunks(sorted_chunk_files, final_output, args.verbose, use_color)

    if final_output_is_file:
        final_output.close()

    for fpath in sorted_chunk_files:
        try:
            os.remove(fpath)
        except Exception:
            pass

    # New line before final done message to avoid overwrite with carriage returns from progress
    print()
    print(GREEN + "[*] All done.\n" + RESET)

if __name__ == "__main__":
    main()
