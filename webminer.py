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
from urllib3.exceptions import NewConnectionError


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
PROBE_VALUES = ["1", "true", "false", "test_marker_xyz123","'"]

# User-Agent sent with every request (can be overridden with --user-agent).
DEFAULT_USER_AGENT = ("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:157.0) "
                      "Gecko/20100101 Firefox/157.0")

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
                 proxy=None, insecure=False,
                 user_agent=DEFAULT_USER_AGENT, http_version="auto"):
        self.url = url
        self.timeout = timeout
        self.delay = delay
        self.method = method.upper()
        self.baseline_samples = max(1, baseline_samples)
        self.similarity_threshold = similarity_threshold
        self.length_tolerance = length_tolerance
        self.confirm_retries = confirm_retries
        self.threads = max(1, threads)
        self.user_agent = user_agent
        self.http_version = http_version   # "auto" | "1.1" | "2"
        self._proxy = proxy
        self._insecure = insecure

        # Protocol actually in use. "auto" starts on HTTP/1.1 (requests)
        # and only switches to HTTP/2 (httpx) if 1.1 can't be used.
        self.protocol = "1.1"
        self._h2_client = None

        self.session = requests.Session()
        self.session.trust_env = False

        # Session-level header: applied to every request (baseline,
        # probes, confirmations). Per-request headers are merged on top.
        self.session.headers["User-Agent"] = user_agent

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

    def load_candidates(self, filename, default_file, fallback,
                        case_insensitive=False):
        """Merge candidates from every source: the user-supplied file (if
        any), the bundled default wordlist, and the embedded fallback
        list. Duplicates are removed, keeping the first occurrence so the
        user's own entries come first. HTTP header names are
        case-insensitive, so they are deduplicated ignoring case."""

        sources = []
        if filename:
            sources.append(("user file", filename))
        sources.append(("default wordlist", default_file))

        merged = []
        for label, path in sources:
            try:
                merged += self._read_wordlist(path)
            except FileNotFoundError:
                print(f"[!] {label} not found: {path}")

        merged += fallback

        seen = set()
        unique = []
        for item in merged:
            key = item.lower() if case_insensitive else item
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)

        removed = len(merged) - len(unique)
        if removed:
            print(f"[*] Removed {removed} duplicate candidate(s)")
        return unique

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

        if self.protocol == "2":
            return self._send_h2(kwargs)

        if self.method == "GET":
            return self.session.get(self.url, **kwargs)
        return self.session.post(self.url, **kwargs)

    # --- HTTP/2 support (httpx, only used as a fallback) --------------

    def _switch_to_h2(self):
        """Build an HTTP/2-only httpx client and make it the active one."""

        try:
            import httpx
            import h2  # noqa: F401 - httpx needs it for http2=True
        except ImportError:
            raise ValueError(
                "HTTP/2 needs the 'httpx' and 'h2' packages: "
                "pip install 'httpx[http2]'"
            ) from None

        kwargs = dict(
            http1=False, http2=True,
            verify=not self._insecure,
            trust_env=False,
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": self.user_agent},
            limits=httpx.Limits(max_connections=self.threads,
                                max_keepalive_connections=self.threads),
        )
        if self._proxy:
            try:
                self._h2_client = httpx.Client(proxy=self._proxy, **kwargs)
            except TypeError:  # httpx < 0.26
                self._h2_client = httpx.Client(proxies=self._proxy, **kwargs)
        else:
            self._h2_client = httpx.Client(**kwargs)

        self.protocol = "2"

    def _send_h2(self, kwargs):
        import httpx

        request_kwargs = {"headers": kwargs.get("headers")}
        params = kwargs.get("params")
        data = kwargs.get("data")

        if params is not None:
            # httpx replaces the URL's own query string when params= is
            # given (requests appends); merge so behaviour stays the same.
            request_kwargs["params"] = httpx.URL(self.url).params.merge(params)
        if data is not None:
            request_kwargs["data"] = data

        try:
            return self._h2_client.request(self.method, self.url,
                                           **request_kwargs)
        except httpx.HTTPError as error:
            # Keep the rest of the script on a single exception type.
            raise requests.RequestException(
                f"{error.__class__.__name__}: {error}") from error

    @staticmethod
    def _protocol_label(response):
        version = getattr(response, "http_version", None)  # httpx
        if version:
            return version
        raw = getattr(getattr(response, "raw", None), "version", None)
        return {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(raw, "HTTP/1.1")

    def _first_baseline_request(self):
        """Send the very first request and settle on a protocol.

        auto: HTTP/1.1 first; fall back to HTTP/2 if the connection is
        refused/reset at protocol level or the server answers 505.
        1.1 / 2: no negotiation, use exactly what was asked."""

        if self.http_version == "2":
            self._switch_to_h2()
            return self._send()

        if self.http_version == "1.1":
            return self._send()

        original_error = None
        original_response = None
        try:
            response = self._send()
        except (requests.exceptions.SSLError,
                requests.exceptions.ProxyError,
                requests.exceptions.Timeout):
            raise  # not a protocol problem; HTTP/2 wouldn't help
        except requests.ConnectionError as error:
            # Refused connection / DNS failure: the host is simply not
            # reachable, HTTP/2 won't change that.
            cause = getattr(error.args[0], "reason", None) if error.args \
                else None
            if isinstance(cause, NewConnectionError):
                raise
            original_error = error
            reason = (f"HTTP/1.1 connection dropped by server "
                      f"({error.__class__.__name__})")
        else:
            if response.status_code != 505:
                return response
            original_response = response
            reason = "server answered 505 (HTTP Version Not Supported)"

        print(f"[!] {reason}; falling back to HTTP/2...")
        try:
            self._switch_to_h2()
        except ValueError as missing:
            # No HTTP/2 stack installed: keep what HTTP/1.1 gave us.
            print(f"[!] {missing}")
            if original_error is not None:
                raise original_error
            self.protocol = "1.1"
            return original_response
        return self._send()

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
            if i == 0:
                response = self._first_baseline_request()
                print(f"    Protocol: "
                      f"{self._protocol_label(response)}")
            else:
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

    parser.add_argument("-A", "--user-agent", default=DEFAULT_USER_AGENT,
                         help="User-Agent header sent with every request "
                              "(default: Firefox 157 on Ubuntu)")

    parser.add_argument("--http-version", choices=["auto", "1.1", "2"],
                         default="auto",
                         help="HTTP version: auto = HTTP/1.1, falling back "
                              "to HTTP/2 only if 1.1 fails (default); "
                              "1.1 or 2 to force one (HTTP/2 needs "
                              "httpx[http2])")

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
        user_agent=args.user_agent,
        http_version=args.http_version,
    )

    params = detector.load_candidates(
        args.params, DEFAULT_PARAMS_FILE, FALLBACK_PARAMS
    )
    headers = detector.load_candidates(
        args.headers, DEFAULT_HEADERS_FILE, FALLBACK_HEADERS,
        case_insensitive=True,
    )

    print("[*] HTTP Surface Detector")
    print(f"[*] Target: {args.url}")
    print(f"[*] Method: {args.method}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] User-Agent: {args.user_agent}")
    print(f"[*] HTTP version: {args.http_version}")
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
