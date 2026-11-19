#!/usr/bin/env python3
"""
FuzzProbe - HTTP Parameter Fuzzer
=================================
Finds hidden parameters in web applications.

For every name in a wordlist, FuzzProbe sends one request carrying a
unique marker value and compares the response with a baseline request
(no extra parameters). A parameter is reported as a candidate when the
response changes in length, reflects the marker, contains error text,
changes status code, or returns different JSON keys.

Author : Husnain Ghaffar
Project: PNY Trainings - Cyber Security Department (Final Project)
Use    : ONLY on systems you own or have written permission to test
         (lab apps such as Juice Shop / DVWA in Docker).
"""

import argparse
import json
import random
import string
import sys
import time

import requests

# Words that suggest the application reacted badly to our input.
ERROR_KEYWORDS = [
    "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
    "exception", "stack trace", "traceback", "fatal error",
    "warning:", "undefined index", "error in your", "unclosed quotation",
]

# Special values used by the value-fuzzing (stretch) stage.
FUZZ_VALUES = ["'", '"', "<fuzzprobe>", "../", "1 OR 1=1",
               "{{7*7}}", ";id", "-1", "0", "999999999"]


def make_marker(index):
    """Build a marker value that is unique for every single request."""
    rand = "".join(random.choices(string.ascii_lowercase, k=6))
    return f"fzp{index}{rand}"


def fetch(session, url, method, params, timeout):
    """Send one request and return its status, length, time and body.

    Returns None when the request itself fails (timeout, refused, ...)
    so a network error never crashes the scan.
    """
    try:
        start = time.time()
        if method == "POST":
            resp = session.post(url, data=params, timeout=timeout)
        else:
            resp = session.get(url, params=params, timeout=timeout)
        elapsed = time.time() - start
        return {
            "status": resp.status_code,
            "length": len(resp.content),
            "time": round(elapsed, 3),
            "body": resp.text,
        }
    except requests.RequestException as exc:
        print(f"    [!] request failed: {exc.__class__.__name__}")
        return None


def json_keys(body):
    """Return the set of keys of a JSON body, or None if it is not JSON."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    keys = set()

    def walk(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                keys.add(key)
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return keys


def compare(baseline, test, marker):
    """Compare one test response with the baseline.

    Returns a list of trigger names; an empty list means 'no change'.
    """
    triggers = []
    if test["status"] != baseline["status"]:
        triggers.append(f"status {baseline['status']}->{test['status']}")
    if test["length"] != baseline["length"]:
        triggers.append(f"length {baseline['length']}->{test['length']}")
    if marker and marker in test["body"]:
        triggers.append("marker reflected")
    body_low = test["body"].lower()
    base_low = baseline["body"].lower()
    for word in ERROR_KEYWORDS:
        if word in body_low and word not in base_low:
            triggers.append(f"error keyword: {word}")
            break
    base_keys = json_keys(baseline["body"])
    test_keys = json_keys(test["body"])
    if base_keys is not None and test_keys is not None and base_keys != test_keys:
        added = sorted(test_keys - base_keys)
        removed = sorted(base_keys - test_keys)
        parts = []
        if added:
            parts.append("+" + ", ".join(added[:5]))
        if removed:
            parts.append("-" + ", ".join(removed[:5]))
        triggers.append(f"json keys changed ({' '.join(parts)})")
    return triggers


def load_wordlist(path):
    """Read parameter names, skipping blanks and comment lines."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return [line.strip() for line in handle
                if line.strip() and not line.startswith("#")]


def save_state(path, next_index):
    """Save scan progress so a stopped run can resume later."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"next_index": next_index}, handle)


def load_state(path):
    """Return the saved next index, or 0 when there is no state file."""
    try:
        with open(path, encoding="utf-8") as handle:
            return int(json.load(handle).get("next_index", 0))
    except (OSError, ValueError):
        return 0


def fuzz_values(session, args, baseline, param):
    """Stretch: test one found parameter with special-character values."""
    findings = []
    normal = fetch(session, args.url, args.method, {param: "fuzzprobe"}, args.timeout)
    if normal is None:
        return findings
    for value in FUZZ_VALUES:
        test = fetch(session, args.url, args.method, {param: value}, args.timeout)
        if test is None:
            continue
        triggers = compare(normal, test, value if len(value) > 3 else None)
        if triggers:
            findings.append({"value": value, "triggers": triggers,
                             "length": test["length"], "status": test["status"]})
        time.sleep(args.delay)
    return findings


def build_report(args, baseline, results, errors, started):
    """Create the text report that is printed and saved to a file."""
    lines = []
    lines.append("=" * 64)
    lines.append("FuzzProbe - HTTP Parameter Fuzzer - Scan Report")
    lines.append("=" * 64)
    lines.append(f"Target      : {args.url}")
    lines.append(f"Method      : {args.method}")
    lines.append(f"Wordlist    : {args.wordlist}")
    lines.append(f"Delay       : {args.delay}s   Timeout: {args.timeout}s")
    lines.append(f"Started     : {started}")
    lines.append("")
    lines.append("[Baseline] (request with no extra parameters)")
    lines.append(f"  Status: {baseline['status']}   "
                 f"Length: {baseline['length']} bytes   "
                 f"Time: {baseline['time']}s")
    lines.append("")
    lines.append(f"[Candidate parameters] {len(results)} found")
    for item in results:
        lines.append(f"  * {item['param']}")
        lines.append(f"      baseline : status {baseline['status']}, "
                     f"length {baseline['length']}")
        lines.append(f"      test     : status {item['status']}, "
                     f"length {item['length']}, time {item['time']}s")
        lines.append(f"      marker   : {item['marker']}")
        lines.append(f"      triggers : {', '.join(item['triggers'])}")
        for finding in item.get("value_fuzz", []):
            lines.append(f"      value-fuzz: {finding['value']!r} -> "
                         f"{', '.join(finding['triggers'])} "
                         f"(status {finding['status']}, length {finding['length']})")
    lines.append("")
    lines.append(f"[Summary] candidates: {len(results)}   "
                 f"request errors logged: {errors}")
    lines.append("Note: run only on lab systems you own (Juice Shop / DVWA).")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="FuzzProbe - find hidden parameters in a web application")
    parser.add_argument("-u", "--url", required=True, help="target URL")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="file with one parameter name per line")
    parser.add_argument("-d", "--delay", type=float, default=0.5,
                        help="delay between requests in seconds (default 0.5)")
    parser.add_argument("-m", "--method", choices=["GET", "POST"],
                        default="GET", help="HTTP method (default GET)")
    parser.add_argument("-o", "--output", default="fuzzprobe_report.txt",
                        help="report file (default fuzzprobe_report.txt)")
    parser.add_argument("-t", "--timeout", type=float, default=10,
                        help="per-request timeout in seconds (default 10)")
    parser.add_argument("--fuzz-values", action="store_true",
                        help="stretch: value-fuzz every candidate parameter")
    parser.add_argument("--resume", action="store_true",
                        help="stretch: resume from the saved wordlist position")
    args = parser.parse_args()

    names = load_wordlist(args.wordlist)
    state_file = "fuzzprobe_state.json"
    start_at = load_state(state_file) if args.resume else 0
    if start_at:
        print(f"[*] Resuming at wordlist position {start_at}")

    session = requests.Session()
    session.headers.update({"User-Agent": "FuzzProbe/1.0"})

    started = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[*] Target   : {args.url}")
    print("[*] Fetching baseline ...")
    baseline = fetch(session, args.url, args.method, {}, args.timeout)
    if baseline is None:
        print("[!] Baseline request failed - check the URL and the lab app.")
        sys.exit(1)
    print(f"[*] Baseline : status {baseline['status']}, "
          f"length {baseline['length']}, time {baseline['time']}s")
    print(f"[*] Testing {len(names) - start_at} parameters "
          f"(delay {args.delay}s) ...")

    results, errors = [], 0
    try:
        for index in range(start_at, len(names)):
            name = names[index]
            marker = make_marker(index)
            test = fetch(session, args.url, args.method,
                         {name: marker}, args.timeout)
            if test is None:
                errors += 1
            else:
                triggers = compare(baseline, test, marker)
                if triggers:
                    print(f"  [+] {name:<18} {', '.join(triggers)}")
                    results.append({
                        "param": name, "marker": marker,
                        "status": test["status"], "length": test["length"],
                        "time": test["time"], "triggers": triggers,
                    })
            save_state(state_file, index + 1)
            time.sleep(args.delay)
    except KeyboardInterrupt:
        print(f"\n[!] Stopped by user. Progress saved - "
              f"rerun with --resume to continue.")

    if args.fuzz_values and results:
        print("[*] Value-fuzzing candidate parameters ...")
        for item in results:
            item["value_fuzz"] = fuzz_values(session, args, baseline,
                                             item["param"])

    report = build_report(args, baseline, results, errors, started)
    print("\n" + report)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(report + "\n")
    print(f"\n[*] Report saved to {args.output}")
    try:
        import os
        os.remove(state_file)
    except OSError:
        pass


if __name__ == "__main__":
    main()
