#!/usr/bin/env python3
"""
PersonaX - a Sherlock-style OSINT tool.

Find anyone's digital footprint. Searches for a given username across many
websites and reports where a matching public profile exists. Useful for
checking your OWN footprint or for authorized OSINT research.

Usage:
    python personax.py <username> [username2 ...]
    python personax.py johndoe --timeout 8 --output results.txt
    python personax.py johndoe --found-only
"""

import argparse
import concurrent.futures
import difflib
import json
import os
import sys
import time
import uuid

import requests

# A realistic User-Agent avoids some sites blocking default python-requests.
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
    )
}

# ANSI colors (enabled on Windows 10+ terminals).
GREEN, RED, YELLOW, CYAN, DIM, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[0m"
)


def load_sites(path):
    """Load the site definitions from sites.json next to this script."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _fetch(url, timeout):
    """GET a URL, returning the response or None on any network error."""
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException:
        return None


def _normalize(text, token):
    """
    Prepare a page body for comparison: lowercase, drop the username token so
    two pages differ only by their real structure, and trim for speed.
    """
    return text.lower().replace(token.lower(), "")[:4000]


def check_site(name, info, username, timeout):
    """
    Check a single site for the username using adaptive detection.

    Strategy (in order of reliability):
      1. Explicit `errorText` in sites.json  -> most reliable.
      2. Control probe: request a random username that cannot exist. Comparing
         the real response against this control removes "soft 404" false
         positives (sites that return 200 OK for everything).

    Returns a dict with status = "found" | "not_found" | "error" and a
    `confidence` = "high" | "medium".
    """
    url = info["url"].format(username)
    resp = _fetch(url, timeout)
    if resp is None:
        return {"site": name, "url": url, "status": "error", "detail": "request failed"}

    check_type = info.get("check", "status")

    # 1a) Explicit "not found" string -> highly reliable (needs a normal page).
    if check_type == "error" and "errorText" in info:
        if resp.status_code != 200:
            # e.g. HTTP 429 rate-limit: we can't trust the body, so don't guess.
            return {"site": name, "url": url, "status": "error",
                    "detail": f"HTTP {resp.status_code}"}
        found = info["errorText"] not in resp.text
        return _result(name, url, found, "high", resp.status_code)

    # 1b) Explicit "exists" marker -> for sites that 200 for everyone but show a
    #     distinctive string only on real profiles (e.g. Telegram, Pinterest).
    if check_type == "presence" and "successText" in info:
        if resp.status_code != 200:
            return _result(name, url, False, "high", resp.status_code)
        found = info["successText"] in resp.text
        return _result(name, url, found, "high", resp.status_code)

    # If the profile page itself isn't OK, the account almost certainly doesn't exist.
    if resp.status_code != 200:
        return _result(name, url, False, "high", resp.status_code)

    # 2) Control probe with an impossible username.
    control_name = "no" + uuid.uuid4().hex[:16]
    control = _fetch(info["url"].format(control_name), timeout)

    # Control request failed -> fall back to plain status (best effort).
    if control is None:
        return _result(name, url, True, "medium", resp.status_code)

    # Site returns 404 for the fake user but 200 for ours -> reliable hit.
    if control.status_code != 200:
        return _result(name, url, True, "high", resp.status_code)

    # Both return 200 -> "soft 404" site. Use extra signals.
    # Signal A: did the real request stay on the username's URL, or redirect
    # away to a login/home page (as non-existent profiles usually do)?
    redirected_away = username.lower() not in resp.url.lower()
    control_same_dest = resp.url.lower() == control.url.lower()
    if redirected_away or control_same_dest:
        return _result(name, url, False, "high", resp.status_code)

    # Signal B: compare page bodies. A real profile differs from the generic
    # "no such user" template; a missing profile looks nearly identical to it.
    ratio = difflib.SequenceMatcher(
        None, _normalize(control.text, control_name), _normalize(resp.text, username)
    ).ratio()
    found = ratio < 0.90
    return _result(name, url, found, "medium", resp.status_code)


def _result(name, url, found, confidence, code):
    return {
        "site": name,
        "url": url,
        "status": "found" if found else "not_found",
        "confidence": confidence,
        "code": code,
    }


def hunt(username, sites, timeout, workers):
    """Check every site for one username, concurrently."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(check_site, name, info, username, timeout): name
            for name, info in sites.items()
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    # Sort: found first, then alphabetical by site.
    results.sort(key=lambda r: (r["status"] != "found", r["site"].lower()))
    return results


def print_results(username, results, found_only):
    print(f"\n{CYAN}=== Results for '{username}' ==={RESET}")
    found_count = 0
    for r in results:
        if r["status"] == "found":
            found_count += 1
            # Mark lower-confidence (soft-404 heuristic) hits with a '?'.
            tag = f"{GREEN}[+]{RESET}" if r.get("confidence") == "high" else f"{YELLOW}[?]{RESET}"
            note = "" if r.get("confidence") == "high" else f" {DIM}(likely){RESET}"
            print(f"  {tag} {r['site']:<14} {r['url']}{note}")
        elif found_only:
            continue
        elif r["status"] == "error":
            print(f"  {YELLOW}[!]{RESET} {r['site']:<14} {DIM}error: {r['detail']}{RESET}")
        else:
            print(f"  {RED}[-]{RESET} {r['site']:<14} {DIM}not found{RESET}")
    print(f"\n{CYAN}Found {found_count} of {len(results)} sites.{RESET}")
    return found_count


def save_results(path, username, results):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"=== Results for '{username}' ===\n")
        for r in results:
            if r["status"] == "found":
                fh.write(f"[+] {r['site']}: {r['url']}\n")
        fh.write("\n")


def main():
    parser = argparse.ArgumentParser(
        prog="personax",
        description="PersonaX - find anyone's digital footprint across many websites.",
    )
    parser.add_argument("usernames", nargs="+", help="One or more usernames to search.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-site timeout in seconds (default 8).")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent requests (default 20).")
    parser.add_argument("--found-only", action="store_true", help="Only print sites where the username was found.")
    parser.add_argument("--output", help="Append found results to this file.")
    args = parser.parse_args()

    # Enable ANSI colors on Windows terminals.
    if os.name == "nt":
        os.system("")

    sites_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sites.json")
    sites = load_sites(sites_path)

    print(f"{CYAN}PersonaX{RESET} - checking {len(sites)} sites per username")
    print(f"{DIM}Use responsibly: research your own footprint or authorized targets only.{RESET}")

    for username in args.usernames:
        start = time.time()
        results = hunt(username, sites, args.timeout, args.workers)
        print_results(username, results, args.found_only)
        print(f"{DIM}(took {time.time() - start:.1f}s){RESET}")
        if args.output:
            save_results(args.output, username, results)
            print(f"{DIM}Saved found results to {args.output}{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
