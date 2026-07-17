#!/usr/bin/env python3
"""
Username Hunter - a Sherlock-style OSINT tool.

Searches for a given username across many websites and reports where a
matching public profile exists. Useful for checking your OWN digital
footprint or for authorized OSINT research.

Usage:
    python hunter.py <username> [username2 ...]
    python hunter.py johndoe --timeout 8 --output results.txt
    python hunter.py johndoe --found-only
"""

import argparse
import concurrent.futures
import json
import os
import sys
import time

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


def check_site(name, info, username, timeout):
    """
    Check a single site for the username.

    Returns a dict describing the result:
        status = "found" | "not_found" | "error"
    """
    url = info["url"].format(username)
    try:
        resp = requests.get(
            url, headers=HEADERS, timeout=timeout, allow_redirects=True
        )
    except requests.exceptions.RequestException as exc:
        return {"site": name, "url": url, "status": "error", "detail": str(exc)}

    check_type = info.get("check", "status")

    if check_type == "status":
        # A 200 OK generally means the profile page exists.
        found = resp.status_code == 200
    elif check_type == "error":
        # The page always returns 200; presence is decided by an error string.
        found = info["errorText"] not in resp.text
    else:
        found = False

    return {
        "site": name,
        "url": url,
        "status": "found" if found else "not_found",
        "code": resp.status_code,
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
            print(f"  {GREEN}[+]{RESET} {r['site']:<14} {r['url']}")
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
        description="Hunt for a username across many websites (Sherlock-style)."
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

    print(f"{CYAN}Username Hunter{RESET} - checking {len(sites)} sites per username")
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
