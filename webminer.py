#!/usr/bin/env python3
"""
HTTP GET/POST parameter and header discovery tool.
"""

import argparse
import difflib
import ipaddress
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter


# --- Candidate wordlists -----------------------------------------------
# Default candidates now live in dedicated files under wordlists/, so
# they can be edited, extended, or swapped (e.g. for Arjun's default
# list or SecLists' burp-parameter-names.txt) without touching the
# script. These small embedded lists are only a last-resort fallback
# if the wordlist files are missing.

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PARAMS_FILE = SCRIPT_DIR / "wordlists" / "params.txt"
DEFAULT_HEADERS_FILE = SCRIPT_DIR / "wordlists" / "headers.txt"

FALLBACK_PARAMS = [
    "debug", "test", "admin", "api", "format", "lang", "callback",
    "output", "limit", "offset", "page", "sort", "filter", "search",
    "query", "id", "token", "redirect", "url", "path",
]

FALLBACK_HEADERS = [
    "X-Requested-With", "X-API-Version", "X-Debug", "X-Forwarded-For",
    "X-Real-IP", "X-Original-URL", "X-Environment", "X-API-Key",
    "Accept-Language",
]

# Values to try per candidate — increases the chance a parameter that
# only reacts to specific values (e.g. a boolean gate) gets triggered.
PROBE_VALUES = ["1", "true", "0", "false", "test_marker_xyz123"]

# Serializes console output across worker threads so lines from
# different candidates don't interleave mid-line.
PRINT_LOCK = threading.Lock()


def safe_print(*args, **kwargs):
    with PRINT_LOCK:
        print(*args, **kwargs)


class HTTPDetector:

    def __init__(self, url, timeout=10, delay=0.3, method="GET",
                 baseline_samples=3, similarity_threshold=0.98,
                 length_tolerance=5, confirm_retries=2, threads=1,
                 proxy=None, insecure=False):
        self.url = url
        self.timeout = timeout
        self.delay = delay
        self.method = method.upper()
        self.baseline_samples = max(1, baseline_samples)
        self.similarity_threshold = similarity_threshold
        self.length_tolerance = length_tolerance
        self.confirm_retries = confirm_retries
        self.threads = max(1, threads)

        self.session = requests.Session()
        self.session.trust_env = False

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        if insecure:
            self.session.verify = False
            # requests warns loudly on every single insecure request;
            # one notice up front is enough for an interception proxy
            # (e.g. Burp/ZAP) with an unimported CA.
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning
            )

        # Enough connections in the pool to keep every worker thread
        # from queuing on the same handful of sockets.
        adapter = HTTPAdapter(pool_connections=self.threads,
                               pool_maxsize=self.threads)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Patterns stripped out before diffing, so known-dynamic content
        # (timestamps, CSRF tokens, nonces) doesn't generate noise.
        self._noise_patterns = [
            re.compile(rb"\d{10,13}"),                       # unix ts / ms
            re.compile(rb"csrf[-_]?token[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
                       re.IGNORECASE),
            re.compile(rb"nonce[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
                       re.IGNORECASE),
            re.compile(rb"[0-9a-f]{32,64}"),                 # hex tokens/hashes
        ]

    # --- candidate loading -------------------------------------------

    @staticmethod
    def _read_wordlist(path):
        with open(path, "r", encoding="utf-8") as file:
            return [
                line.strip()
                for line in file
                if line.strip() and not line.startswith("#")
            ]

    def load_candidates(self, filename, default_file, fallback):
        """Load candidates from a user-supplied file if given, otherwise
        from the bundled default wordlist file, falling back to a small
        embedded list if even that is missing."""

        target = filename or default_file

        try:
            candidates = self._read_wordlist(target)
            return candidates if candidates else fallback

        except FileNotFoundError:
            if filename:
                print(f"[!] File not found: {filename}. "
                      "Using built-in fallback candidates.")
            else:
                print(f"[!] Default wordlist not found: {target}. "
                      "Using built-in fallback candidates.")
            return fallback

    # --- request helpers ----------------------------------------------

    def _send(self, params=None, headers=None):
        kwargs = dict(timeout=self.timeout, allow_redirects=False)
        if params is not None:
            if self.method == "GET":
                kwargs["params"] = params
            else:
                kwargs["data"] = params
        if headers:
            kwargs["headers"] = headers

        if self.method == "GET":
            return self.session.get(self.url, **kwargs)
        return self.session.post(self.url, **kwargs)

    def _normalize(self, body: bytes) -> bytes:
        cleaned = body
        for pattern in self._noise_patterns:
            cleaned = pattern.sub(b"", cleaned)
        return cleaned

    def _similarity(self, a: bytes, b: bytes) -> float:
        if not a and not b:
            return 1.0
        matcher = difflib.SequenceMatcher(None, a, b)
        return matcher.ratio()

    # --- baseline -------------------------------------------------------

    def get_baseline(self):
        """Retrieve multiple baseline responses to characterize normal
        variance before any candidate is tested."""

        print(f"[*] Retrieving {self.baseline_samples} baseline "
              f"response(s) to calibrate noise tolerance...")

        samples = []
        for i in range(self.baseline_samples):
            response = self._send()
            samples.append(response)
            if i < self.baseline_samples - 1:
                time.sleep(self.delay)

        lengths = [len(r.content) for r in samples]
        statuses = {r.status_code for r in samples}
        normalized_bodies = [self._normalize(r.content) for r in samples]

        # Natural variance observed across the baseline samples.
        length_min, length_max = min(lengths), max(lengths)
        observed_spread = length_max - length_min

        # Minimum pairwise similarity among baseline samples — tells us
        # how "different" two legitimate responses can look even with
        # nothing changed.
        min_self_similarity = 1.0
        for i in range(len(normalized_bodies)):
            for j in range(i + 1, len(normalized_bodies)):
                sim = self._similarity(normalized_bodies[i],
                                        normalized_bodies[j])
                min_self_similarity = min(min_self_similarity, sim)

        if len(statuses) > 1:
            print(f"[!] Warning: baseline status code is unstable "
                  f"({statuses}). Results may be unreliable.")

        baseline = {
            "status": samples[-1].status_code,
            "statuses_seen": statuses,
            "length": lengths[-1],
            "length_min": length_min,
            "length_max": length_max,
            "observed_spread": observed_spread,
            "reference_body": normalized_bodies[-1],
            "min_self_similarity": min_self_similarity,
            "headers": dict(samples[-1].headers),
        }

        print(f"    Status: {baseline['status']}"
              + (" (unstable!)" if len(statuses) > 1 else ""))
        print(f"    Body length: {baseline['length']} bytes "
              f"(observed range: {length_min}-{length_max})")
        print(f"    Minimum self-similarity across baseline samples: "
              f"{min_self_similarity:.4f}")
        print()

        return baseline

    # --- comparison -----------------------------------------------------

    def compare(self, baseline, response):
        """Compare response characteristics against calibrated baseline,
        tolerating the variance already observed between baseline
        samples themselves."""

        differences = []

        status = response.status_code
        length = len(response.content)
        normalized = self._normalize(response.content)

        # Status: only flag if it's outside the set seen in baseline.
        if status not in baseline["statuses_seen"]:
            differences.append(
                f"Status: {baseline['status']} -> {status}"
            )

        # Length: tolerate the spread already observed in baseline,
        # plus a small fixed tolerance.
        allowed_spread = baseline["observed_spread"] + self.length_tolerance
        if abs(length - baseline["length"]) > allowed_spread:
            differences.append(
                f"Body length: {baseline['length']} -> {length} "
                f"(outside tolerance of +/-{allowed_spread})"
            )

        # Content similarity: compare against baseline's reference body,
        # using a threshold adjusted for the baseline's own noise floor.
        similarity = self._similarity(baseline["reference_body"], normalized)
        effective_threshold = min(self.similarity_threshold,
                                   baseline["min_self_similarity"])
        if similarity < effective_threshold:
            differences.append(
                f"Content similarity: {similarity:.4f} "
                f"(threshold: {effective_threshold:.4f})"
            )

        return differences

    def confirm(self, probe_fn, baseline):
        """Re-run a candidate probe multiple times; only treat it as a
        hit if the difference reproduces consistently (filters out
        one-off noise: transient errors, race conditions, A/B content)."""

        hits = 0
        all_differences = []

        for _ in range(self.confirm_retries):
            response = probe_fn()
            differences = self.compare(baseline, response)
            if differences:
                hits += 1
                all_differences.append(differences)
            time.sleep(self.delay)

        # Require the difference to show up on every retry attempt.
        return hits == self.confirm_retries, all_differences

    # --- probing ----------------------------------------------------

    def test_parameter(self, baseline, parameter):
        """Test a single parameter, trying several probe values and
        confirming any apparent hit before reporting it."""

        for value in PROBE_VALUES:
            try:
                def probe():
                    return self._send(params={parameter: value})

                response = probe()
                differences = self.compare(baseline, response)

                if not differences:
                    time.sleep(self.delay)
                    continue

                confirmed, all_diffs = self.confirm(probe, baseline)

                if confirmed:
                    lines = [f"[+] Likely recognized parameter: "
                             f"{parameter}={value}"]
                    lines += [f"    {d}" for d in all_diffs[-1]]
                    safe_print("\n".join(lines))
                    break  # no need to try other values for this param
                else:
                    safe_print(f"[~] Unconfirmed (noise?): "
                               f"{parameter}={value} -- skipped")

                time.sleep(self.delay)

            except requests.RequestException as error:
                safe_print(f"[!] Error testing parameter {parameter}: {error}")

    def test_header(self, baseline, header):
        """Test a single HTTP header, confirming any apparent hit."""

        try:
            def probe():
                return self._send(headers={header: "test_marker_xyz123"})

            response = probe()
            differences = self.compare(baseline, response)

            if not differences:
                time.sleep(self.delay)
                return

            confirmed, all_diffs = self.confirm(probe, baseline)

            if confirmed:
                lines = [f"[+] Likely recognized header: {header}"]
                lines += [f"    {d}" for d in all_diffs[-1]]
                safe_print("\n".join(lines))
            else:
                safe_print(f"[~] Unconfirmed (noise?): "
                           f"header {header} -- skipped")

            time.sleep(self.delay)

        except requests.RequestException as error:
            safe_print(f"[!] Error testing header {header}: {error}")

    # --- orchestration ------------------------------------------------

    def _run_pool(self, items, worker_fn, baseline):
        """Run worker_fn(baseline, item) for each item, in parallel if
        self.threads > 1. A failure in one worker doesn't stop the rest."""

        if self.threads == 1:
            for item in items:
                worker_fn(baseline, item)
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(worker_fn, baseline, item): item
                for item in items
            }
            for future in as_completed(futures):
                item = futures[future]
                try:
                    future.result()
                except Exception as error:  # noqa: BLE001 - surface and continue
                    safe_print(f"[!] Unexpected error on {item!r}: {error}")

    def run(self, params, headers):

        baseline = self.get_baseline()

        print("=" * 60)
        print(f"[*] Testing {len(params)} parameter(s) via {self.method} "
              f"({self.threads} thread(s))")
        print("=" * 60)

        self._run_pool(params, self.test_parameter, baseline)

        print()
        print("=" * 60)
        print(f"[*] Testing {len(headers)} HTTP header(s) "
              f"({self.threads} thread(s))")
        print("=" * 60)

        self._run_pool(headers, self.test_header, baseline)

        print()
        print("[*] Scan completed.")


def main():

    parser = argparse.ArgumentParser(
        description="HTTP Parameter and Header Discovery Tool "
                    "(authorized testing only)"
    )

    parser.add_argument("-u", "--url", required=True,
                         help="Target application URL")
    parser.add_argument("-p", "--params",
                         help="File containing parameter names")
    parser.add_argument("-H", "--headers",
                         help="File containing HTTP header names")
    parser.add_argument("-m", "--method", default="GET",
                         choices=["GET", "POST"],
                         help="HTTP method to use (default: GET)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                         help="HTTP request timeout (default: 10s)")
    parser.add_argument("-d", "--delay", type=float, default=0.3,
                         help="Delay between requests (default: 0.3s)")
    parser.add_argument("--baseline-samples", type=int, default=3,
                         help="Number of baseline requests to calibrate "
                              "noise tolerance (default: 3)")
    parser.add_argument("--similarity-threshold", type=float, default=0.98,
                         help="Minimum content similarity ratio before "
                              "flagging a difference (default: 0.98)")
    parser.add_argument("--confirm-retries", type=int, default=2,
                         help="Times a candidate hit must reproduce "
                              "before being reported (default: 2)")
    parser.add_argument("-w", "--threads", type=int, default=1,
                         help="Number of candidates to test in parallel "
                              "(default: 1, sequential)")
    parser.add_argument("-x", "--proxy",
                         help="HTTP(S) proxy to route requests through, "
                              "e.g. http://127.0.0.1:8080 (Burp/ZAP)")
    parser.add_argument("-k", "--insecure", action="store_true",
                         help="Disable TLS certificate verification "
                              "(useful with an interception proxy whose "
                              "CA isn't trusted)")

    args = parser.parse_args()

    if args.threads < 1:
        print("[!] --threads must be >= 1")
        sys.exit(1)

    detector = HTTPDetector(
        args.url,
        timeout=args.timeout,
        delay=args.delay,
        method=args.method,
        baseline_samples=args.baseline_samples,
        similarity_threshold=args.similarity_threshold,
        confirm_retries=args.confirm_retries,
        threads=args.threads,
        proxy=args.proxy,
        insecure=args.insecure,
    )

    params = detector.load_candidates(
        args.params, DEFAULT_PARAMS_FILE, FALLBACK_PARAMS
    )
    headers = detector.load_candidates(
        args.headers, DEFAULT_HEADERS_FILE, FALLBACK_HEADERS
    )

    print("[*] HTTP Surface Detector")
    print(f"[*] Target: {args.url}")
    print(f"[*] Method: {args.method}")
    print(f"[*] Threads: {args.threads}")
    if args.proxy:
        print(f"[*] Proxy: {args.proxy}"
              + (" (TLS verification disabled)" if args.insecure else ""))
    print(f"[*] Parameters to test: {len(params)}")
    print(f"[*] Headers to test: {len(headers)}")
    print()

    try:
        detector.run(params, headers)

    except (ValueError, requests.RequestException) as error:
        print(f"[!] Fatal error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
