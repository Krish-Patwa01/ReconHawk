#!/usr/bin/env python3
"""
ReconHawk - an all-in-one domain OSINT & reconnaissance toolkit.

Gather public information about a domain from a simple numbered menu.
Every check uses free, public sources and needs NO API key.

Use only on domains you own or are authorized to test.

Usage:
    python reconhawk.py
    python reconhawk.py example.com   (optional: pre-fill the target)

Author:  Krishna Patwa
GitHub:  https://github.com/Krish-Patwa01/
LinkedIn: https://www.linkedin.com/in/krishna-patwa/
"""

__author__ = "Krishna Patwa"

import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

try:
    import dns.resolver
    import dns.reversename
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

try:
    import whois as whois_lib
    HAVE_WHOIS = True
except ImportError:
    HAVE_WHOIS = False


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------

GREEN, RED, YELLOW, CYAN, BLUE, DIM, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m",
    "\033[94m", "\033[2m", "\033[1m", "\033[0m",
)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
    )
}

BANNER = rf"""{CYAN}
   ____                       _   _                _
  |  _ \ ___  ___ ___  _ __  | | | | __ ___      _| | __
  | |_) / _ \/ __/ _ \| '_ \ | |_| |/ _` \ \ /\ / / |/ /
  |  _ <  __/ (_| (_) | | | ||  _  | (_| |\ V  V /|   <
  |_| \_\___|\___\___/|_| |_||_| |_|\__,_| \_/\_/ |_|\_\
{RESET}{DIM}  All-in-One Domain OSINT & Reconnaissance Toolkit - no API key needed{RESET}
{DIM}  Made by {RESET}{BOLD}Krishna Patwa{RESET}{DIM}   GitHub: {RESET}{CYAN}github.com/Krish-Patwa01{RESET}{DIM}   LinkedIn: {RESET}{CYAN}linkedin.com/in/krishna-patwa{RESET}
"""

MENU = f"""
  {BOLD}[1]{RESET}  WHOIS Lookup
  {BOLD}[2]{RESET}  DNS Records (A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, CAA, DS, DNSKEY, PTR)
  {BOLD}[3]{RESET}  Subdomain Enumeration (crt.sh)
  {BOLD}[4]{RESET}  SSL / TLS Certificate Info
  {BOLD}[5]{RESET}  HTTP Security Headers
  {BOLD}[6]{RESET}  IP Geolocation
  {BOLD}[7]{RESET}  Port Scan (common ports)
  {BOLD}[8]{RESET}  Wayback Machine snapshots
  {BOLD}[9]{RESET}  robots.txt / sitemap.xml
  {BOLD}[10]{RESET} Technology Profiler (Wappalyzer-style)
  {DIM}-------------------------------------------------{RESET}
  {BOLD}{GREEN}[11]{RESET} Run ALL of the above
  {BOLD}{YELLOW}[S]{RESET}  Save results to JSON
  {BOLD}{CYAN}[T]{RESET}  Change target domain
  {BOLD}{RED}[0]{RESET}  Exit
"""


def title(text):
    print(f"\n{BLUE}{BOLD}==[ {text} ]{'=' * max(0, 46 - len(text))}{RESET}")


def ok(label, value=""):
    print(f"  {GREEN}+{RESET} {label}{(': ' + str(value)) if value != '' else ''}")


def info(label, value=""):
    print(f"  {CYAN}-{RESET} {label}{(': ' + str(value)) if value != '' else ''}")


def warn(text):
    print(f"  {YELLOW}!{RESET} {text}")


def err(text):
    print(f"  {RED}x{RESET} {text}")


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def clean_domain(raw):
    """Strip scheme, path, port and junk, leaving a bare hostname."""
    raw = (raw or "").strip().lower()
    raw = re.sub(r"^[a-z]+://", "", raw)   # drop http:// https://
    raw = raw.split("/")[0]                # drop any path
    raw = raw.split(":")[0]                # drop any :port
    raw = raw.lstrip("*.")                 # drop wildcard prefix
    # Keep only valid hostname characters. This also drops copy-paste noise:
    # BOM / zero-width chars, and the "ï»¿" a UTF-8 BOM decodes to on Windows.
    raw = re.sub(r"[^a-z0-9.-]", "", raw)
    return raw.strip(".-")


def resolve_ip(domain):
    """Return the primary A-record IP for a domain, or None."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


# ---------------------------------------------------------------------------
# Recon modules  -- each returns a JSON-serialisable dict for saving
# ---------------------------------------------------------------------------

def do_whois(domain):
    title("WHOIS Lookup")
    if not HAVE_WHOIS:
        err("python-whois not installed  (pip install python-whois)")
        return {"error": "python-whois not installed"}
    try:
        w = whois_lib.whois(domain)
    except Exception as exc:  # library raises many different errors
        err(f"WHOIS failed: {exc}")
        return {"error": str(exc)}

    def first(v):
        """Some fields come back as a list of duplicates; take the first."""
        return v[0] if isinstance(v, list) and v else v

    def field(key):
        """Fetch a parsed field as a clean string, or None."""
        v = first(w.get(key)) if isinstance(w, dict) else None
        return str(v).strip() if v not in (None, "") else None

    def as_list(v):
        if not v:
            return []
        return list(dict.fromkeys(v)) if isinstance(v, list) else [v]

    def clean_status(v):
        """Keep just the EPP status code (drop the trailing URL) and dedupe.

        WHOIS returns each status twice - from the registry and the registrar -
        with slightly different URL formatting, so dedupe on the code itself.
        """
        seen = {}
        for s in as_list(v):
            code = str(s).split()[0].strip() if s else ""
            if code:
                seen.setdefault(code, code)
        return list(seen.values())

    # python-whois doesn't expose every field as structured data, so also scan
    # the raw WHOIS response for the ones it misses (IANA ID, abuse contacts...).
    raw = getattr(w, "text", "") or ""

    def raw_field(label):
        m = re.search(rf"(?im)^\s*{re.escape(label)}\s*:\s*(.+?)\s*$", raw)
        return m.group(1).strip() if m else None

    data = {
        "domain_name": field("domain_name"),
        "registry_domain_id": raw_field("Registry Domain ID"),
        "registrar": field("registrar"),
        "registrar_iana_id": raw_field("Registrar IANA ID"),
        "registrar_url": field("registrar_url"),
        "whois_server": field("whois_server"),
        "abuse_email": raw_field("Registrar Abuse Contact Email"),
        "abuse_phone": raw_field("Registrar Abuse Contact Phone"),
        "creation_date": field("creation_date"),
        "updated_date": field("updated_date"),
        "expiration_date": field("expiration_date"),
        "status": clean_status(w.get("status")) if isinstance(w, dict) else [],
        "dnssec": field("dnssec"),
        "name_servers": sorted({n.upper() for n in as_list(w.get("name_servers"))}),
        "registrant_name": field("name"),
        "registrant_org": field("org"),
        "registrant_address": field("address"),
        "registrant_city": field("city"),
        "registrant_state": field("state"),
        "registrant_postal_code": field("registrant_postal_code"),
        "registrant_country": field("country"),
        "emails": as_list(w.get("emails")) if isinstance(w, dict) else [],
    }

    if not data["registrar"] and not data["name_servers"]:
        warn("No WHOIS data returned (domain may be private or unregistered).")
        return data

    # --- Domain ---
    ok("Domain", data["domain_name"] or domain.upper())
    if data["registry_domain_id"]:
        info("Registry Domain ID", data["registry_domain_id"])
    ok("Registered On", data["creation_date"] or "-")
    ok("Expires On", data["expiration_date"] or "-")
    ok("Updated On", data["updated_date"] or "-")
    for st in data["status"]:
        info("Status", st)
    if data["dnssec"]:
        info("DNSSEC", data["dnssec"])
    for ns in data["name_servers"]:
        info("Name Server", ns)

    # --- Registrar ---
    print(f"  {DIM}--- Registrar ---{RESET}")
    ok("Registrar", data["registrar"] or "-")
    if data["registrar_iana_id"]:
        info("IANA ID", data["registrar_iana_id"])
    if data["registrar_url"]:
        info("URL", data["registrar_url"])
    if data["whois_server"]:
        info("WHOIS Server", data["whois_server"])
    if data["abuse_email"]:
        info("Abuse Email", data["abuse_email"])
    if data["abuse_phone"]:
        info("Abuse Phone", data["abuse_phone"])

    # --- Registrant / contacts ---
    contact_bits = [data["registrant_name"], data["registrant_org"],
                    data["registrant_address"], data["registrant_city"],
                    data["registrant_state"], data["registrant_postal_code"],
                    data["registrant_country"]]
    if any(contact_bits):
        print(f"  {DIM}--- Registrant Contact ---{RESET}")
        if data["registrant_name"]:
            ok("Name", data["registrant_name"])
        if data["registrant_org"]:
            ok("Org", data["registrant_org"])
        if data["registrant_address"]:
            info("Street", data["registrant_address"])
        if data["registrant_city"]:
            info("City", data["registrant_city"])
        if data["registrant_state"]:
            info("State", data["registrant_state"])
        if data["registrant_postal_code"]:
            info("Postal Code", data["registrant_postal_code"])
        if data["registrant_country"]:
            info("Country", data["registrant_country"])

    for em in data["emails"]:
        info("Email", em)
    return data


# Record types queried directly against the domain name.
DNS_TYPES = [
    "A",       # IPv4 address
    "AAAA",    # IPv6 address
    "CNAME",   # canonical name / alias
    "MX",      # mail exchange servers
    "NS",      # authoritative name servers
    "SOA",     # start of authority (zone master info)
    "TXT",     # arbitrary text (SPF, DKIM, DMARC...)
    "SRV",     # service locations
    "CAA",     # certificate authority authorization
    "DS",      # DNSSEC delegation signer
    "DNSKEY",  # DNSSEC public signing keys
]


def do_dns(domain):
    title("DNS Records")
    if not HAVE_DNS:
        err("dnspython not installed  (pip install dnspython)")
        return {"error": "dnspython not installed"}
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    for rtype in DNS_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            values = [r.to_text() for r in answers]
            records[rtype] = values
            for v in values:
                ok(rtype, v)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

    # PTR is a reverse record: it lives in the in-addr.arpa zone, not under the
    # domain name. Resolve the domain's IP(s), then look up their PTR pointer.
    ptr_values = []
    for ip in records.get("A", []) + records.get("AAAA", []):
        try:
            rev = dns.reversename.from_address(ip)
            for r in resolver.resolve(rev, "PTR"):
                val = r.to_text()
                ptr_values.append(val)
                ok("PTR", f"{ip} -> {val}")
        except Exception:
            pass
    if ptr_values:
        records["PTR"] = ptr_values

    if not records:
        warn("No DNS records resolved.")
    return records


def _clean_subs(names, domain):
    """Normalise an iterable of hostnames down to real subdomains of `domain`."""
    out = set()
    for name in names:
        name = str(name).strip().lstrip("*.").lower()
        name = name.split("@")[-1]  # some sources prefix an email local part
        if name.endswith("." + domain) and name != domain and " " not in name:
            out.add(name)
    return out


def _subs_crtsh(domain):
    """crt.sh certificate transparency logs (flaky - retry a few times)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    last = "no response"
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=HEADERS, timeout=25)
            if resp.status_code == 200 and resp.text.strip():
                names = []
                for entry in resp.json():
                    names.extend(str(entry.get("name_value", "")).splitlines())
                return _clean_subs(names, domain), None
            last = f"HTTP {resp.status_code}"
        except Exception as exc:
            last = str(exc).split("(")[0].strip()
        if attempt < 2:
            time.sleep(2)  # brief back-off; crt.sh is often overloaded
    return set(), last


def _subs_hackertarget(domain):
    """HackerTarget hostsearch API - returns 'host,ip' lines (free, no key)."""
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                            headers=HEADERS, timeout=15)
        if resp.status_code == 200 and "," in resp.text and "error" not in resp.text.lower():
            names = [line.split(",")[0] for line in resp.text.splitlines()]
            return _clean_subs(names, domain), None
        return set(), f"HTTP {resp.status_code}"
    except Exception as exc:
        return set(), str(exc).split("(")[0].strip()


def _subs_otx(domain):
    """AlienVault OTX passive DNS (free, no key)."""
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            names = [r.get("hostname", "") for r in resp.json().get("passive_dns", [])]
            return _clean_subs(names, domain), None
        return set(), f"HTTP {resp.status_code}"
    except Exception as exc:
        return set(), str(exc).split("(")[0].strip()


def _subs_certspotter(domain):
    """Cert Spotter issuances API (free tier, no key)."""
    try:
        resp = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}"
            "&include_subdomains=true&expand=dns_names",
            headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            names = []
            for entry in resp.json():
                names.extend(entry.get("dns_names", []))
            return _clean_subs(names, domain), None
        return set(), f"HTTP {resp.status_code}"
    except Exception as exc:
        return set(), str(exc).split("(")[0].strip()


SUBDOMAIN_SOURCES = [
    ("crt.sh", _subs_crtsh),
    ("HackerTarget", _subs_hackertarget),
    ("AlienVault OTX", _subs_otx),
    ("CertSpotter", _subs_certspotter),
]


def do_subdomains(domain):
    title("Subdomain Enumeration")
    all_subs = set()
    # Query every source in parallel so one slow/dead source can't hold us up.
    with ThreadPoolExecutor(max_workers=len(SUBDOMAIN_SOURCES)) as pool:
        futures = {pool.submit(fn, domain): name for name, fn in SUBDOMAIN_SOURCES}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                found, error = fut.result()
            except Exception as exc:
                found, error = set(), str(exc)
            if error:
                warn(f"{name}: {error}")
            else:
                ok(name, f"{len(found)} found")
                all_subs |= found

    subs = sorted(all_subs)
    if subs:
        print(f"  {DIM}--- {len(subs)} unique subdomains ---{RESET}")
        for s in subs:
            info("sub", s)
    else:
        warn("No subdomains found across any source.")
    return {"count": len(subs), "subdomains": subs}


def do_ssl(domain):
    title("SSL / TLS Certificate Info")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
    except Exception as exc:
        err(f"TLS connection failed: {exc}")
        return {"error": str(exc)}

    def name_from(field):
        return dict(x[0] for x in field) if field else {}

    subject = name_from(cert.get("subject"))
    issuer = name_from(cert.get("issuer"))
    not_after = cert.get("notAfter")
    sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]

    days_left = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    ok("Subject CN", subject.get("commonName", "-"))
    ok("Issuer", issuer.get("organizationName", issuer.get("commonName", "-")))
    ok("TLS Version", proto)
    ok("Valid From", cert.get("notBefore", "-"))
    ok("Valid Until", not_after or "-")
    if days_left is not None:
        if days_left < 0:
            err(f"Certificate EXPIRED {abs(days_left)} days ago!")
        elif days_left < 15:
            warn(f"Expires in {days_left} days.")
        else:
            ok("Days remaining", days_left)
    if sans:
        info("SANs", f"{len(sans)} domains")
        for s in sans[:25]:
            info("  san", s)
    return {
        "subject_cn": subject.get("commonName"),
        "issuer": issuer.get("organizationName", issuer.get("commonName")),
        "tls_version": proto,
        "valid_from": cert.get("notBefore"),
        "valid_until": not_after,
        "days_remaining": days_left,
        "sans": sans,
    }


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (forces HTTPS)",
    "content-security-policy": "CSP (blocks injected content)",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "Referrer leakage control",
    "permissions-policy": "Browser feature control",
}


def do_headers(domain):
    title("HTTP Security Headers")
    try:
        resp = requests.get(f"https://{domain}", headers=HEADERS,
                            timeout=10, allow_redirects=True)
    except Exception as exc:
        err(f"Request failed: {exc}")
        return {"error": str(exc)}

    got = {k.lower(): v for k, v in resp.headers.items()}
    ok("Status", resp.status_code)
    if got.get("server"):
        info("Server", got["server"])
    if got.get("x-powered-by"):
        info("X-Powered-By", got["x-powered-by"])

    present, missing = {}, []
    for h, desc in SECURITY_HEADERS.items():
        if h in got:
            present[h] = got[h]
            ok(desc, "present")
        else:
            missing.append(h)
            warn(f"Missing: {desc}")
    return {
        "status_code": resp.status_code,
        "server": got.get("server"),
        "x_powered_by": got.get("x-powered-by"),
        "present": present,
        "missing": missing,
    }


def do_geoip(domain):
    title("IP Geolocation")
    ip = resolve_ip(domain)
    if not ip:
        err("Could not resolve domain to an IP.")
        return {"error": "resolution failed"}
    ok("IP Address", ip)
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone,reverse",
            timeout=10,
        )
        data = resp.json()
    except Exception as exc:
        err(f"Geolocation lookup failed: {exc}")
        return {"ip": ip, "error": str(exc)}

    if data.get("status") != "success":
        warn("Geolocation service returned no data.")
        return {"ip": ip}
    ok("Country", data.get("country", "-"))
    ok("Region", data.get("regionName", "-"))
    ok("City", data.get("city", "-"))
    ok("ISP", data.get("isp", "-"))
    ok("Org", data.get("org", "-"))
    ok("ASN", data.get("as", "-"))
    if data.get("reverse"):
        info("Reverse DNS", data["reverse"])
    info("Coordinates", f"{data.get('lat')}, {data.get('lon')}")
    info("Timezone", data.get("timezone", "-"))
    data["ip"] = ip
    return data


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-sub", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def _check_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.2)
    try:
        return port if s.connect_ex((ip, port)) == 0 else None
    except OSError:
        return None
    finally:
        s.close()


def do_ports(domain):
    title("Port Scan (common ports)")
    ip = resolve_ip(domain)
    if not ip:
        err("Could not resolve domain to an IP.")
        return {"error": "resolution failed"}
    info("Scanning", f"{ip}  ({len(COMMON_PORTS)} common ports)")
    open_ports = []
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(_check_port, ip, p): p for p in COMMON_PORTS}
        for fut in as_completed(futures):
            port = fut.result()
            if port:
                open_ports.append(port)
    open_ports.sort()
    if open_ports:
        for p in open_ports:
            ok(f"Port {p}", COMMON_PORTS[p])
    else:
        warn("No common ports found open (host may be firewalled).")
    return {"ip": ip, "open_ports": {p: COMMON_PORTS[p] for p in open_ports}}


def do_wayback(domain):
    title("Wayback Machine snapshots")
    result = {}
    # Newest available snapshot.
    try:
        resp = requests.get(
            f"http://archive.org/wayback/available?url={domain}",
            headers=HEADERS, timeout=12,
        )
        snap = resp.json().get("archived_snapshots", {}).get("closest")
        if snap:
            ok("Latest snapshot", snap.get("timestamp"))
            info("URL", snap.get("url"))
            result["latest"] = snap
        else:
            warn("No snapshot found for this domain.")
    except Exception as exc:
        err(f"Wayback lookup failed: {exc}")
        return {"error": str(exc)}

    # Total capture count.
    try:
        cdx = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}"
            "&output=json&fl=timestamp&limit=100000&showResumeKey=false",
            headers=HEADERS, timeout=20,
        ).json()
        count = max(0, len(cdx) - 1)  # first row is the header
        ok("Total captures", count)
        result["total_captures"] = count
        if count:
            info("First seen", cdx[1][0])
            info("Last seen", cdx[-1][0])
            result["first_seen"] = cdx[1][0]
            result["last_seen"] = cdx[-1][0]
    except Exception:
        pass
    return result


def do_robots(domain):
    title("robots.txt / sitemap.xml")
    result = {"robots": None, "sitemaps": [], "disallow": []}
    # robots.txt
    try:
        r = requests.get(f"https://{domain}/robots.txt", headers=HEADERS, timeout=10)
        if r.status_code == 200 and "<html" not in r.text.lower()[:200]:
            ok("robots.txt", "found")
            result["robots"] = r.text[:4000]
            disallow = re.findall(r"(?i)^\s*Disallow:\s*(\S+)", r.text, re.M)
            sitemaps = re.findall(r"(?i)^\s*Sitemap:\s*(\S+)", r.text, re.M)
            result["disallow"] = disallow
            result["sitemaps"] = sitemaps
            for d in disallow[:30]:
                info("Disallow", d)
            for sm in sitemaps:
                ok("Sitemap listed", sm)
        else:
            warn(f"robots.txt not found (HTTP {r.status_code}).")
    except Exception as exc:
        err(f"robots.txt request failed: {exc}")

    # Fall back to the default sitemap location.
    if not result["sitemaps"]:
        try:
            s = requests.get(f"https://{domain}/sitemap.xml", headers=HEADERS, timeout=10)
            if s.status_code == 200 and "<" in s.text[:100]:
                ok("sitemap.xml", "found at default location")
                locs = re.findall(r"<loc>(.*?)</loc>", s.text)
                result["sitemaps"] = [f"https://{domain}/sitemap.xml"]
                info("URLs in sitemap", len(locs))
                for u in locs[:15]:
                    info("  url", u)
            else:
                warn("No sitemap.xml at default location.")
        except Exception:
            warn("Could not fetch sitemap.xml.")
    return result


# Wappalyzer-style fingerprints. Each entry may match on:
#   html    - regexes searched in the page body
#   headers - regexes searched in a "name: value" blob of response headers
#   cookies - regexes searched against the set of cookie names
#   version - regex whose first group extracts a version (from headers + html)
TECH_SIGNATURES = [
    # --- CMS ---
    {"name": "WordPress", "cat": "CMS",
     "html": [r"/wp-content/", r"/wp-includes/", r'content="WordPress'],
     "version": r"WordPress[ /]?([0-9][0-9.]*)"},
    {"name": "Joomla", "cat": "CMS", "html": [r"/media/jui/", r"Joomla!"]},
    {"name": "Drupal", "cat": "CMS",
     "html": [r"/sites/all/", r"Drupal.settings"], "headers": [r"x-generator:\s*drupal"]},
    {"name": "Shopify", "cat": "CMS / eCommerce",
     "html": [r"cdn\.shopify\.com", r"Shopify\."], "headers": [r"x-shopid:", r"x-shopify"]},
    {"name": "Wix", "cat": "CMS",
     "html": [r"static\.wixstatic\.com"], "headers": [r"x-wix-request-id:"]},
    {"name": "Squarespace", "cat": "CMS", "html": [r"static1\.squarespace\.com"]},
    {"name": "Ghost", "cat": "CMS", "html": [r'content="Ghost', r"ghost\.io"]},
    {"name": "Webflow", "cat": "CMS", "html": [r"assets\.website-files\.com", r"data-wf-"]},
    {"name": "Magento", "cat": "CMS / eCommerce",
     "html": [r"/static/version\d", r"\bMagento\b", r"/mage/cookies"]},

    # --- JavaScript frameworks / libraries ---
    {"name": "React", "cat": "JavaScript",
     "html": [r"data-reactroot", r"react(\.production|\.development)?\.min\.js", r"__REACT_DEVTOOLS"]},
    {"name": "Next.js", "cat": "JavaScript",
     "html": [r"/_next/", r"__NEXT_DATA__"], "headers": [r"x-powered-by:\s*next\.js"]},
    {"name": "Vue.js", "cat": "JavaScript", "html": [r"data-v-[0-9a-f]{8}", r"vue(\.min)?\.js", r"__VUE__"]},
    {"name": "Nuxt.js", "cat": "JavaScript", "html": [r"/_nuxt/", r"__NUXT__"]},
    {"name": "Angular", "cat": "JavaScript", "html": [r"ng-version=", r"angular(\.min)?\.js"]},
    {"name": "jQuery", "cat": "JavaScript",
     "html": [r"jquery[.\-][0-9.]+(\.min)?\.js", r"jquery(\.min)?\.js"],
     "version": r"jquery[.\-]([0-9][0-9.]*)"},
    {"name": "Gatsby", "cat": "JavaScript", "html": [r"___gatsby", r"/page-data/"]},
    {"name": "Svelte", "cat": "JavaScript", "html": [r"svelte-[0-9a-z]+"]},
    {"name": "Alpine.js", "cat": "JavaScript", "html": [r"alpinejs", r"\sx-data="]},

    # --- UI / CSS frameworks ---
    {"name": "Bootstrap", "cat": "UI framework",
     "html": [r"bootstrap(\.min)?\.(css|js)"], "version": r"bootstrap[@/\-]?([0-9][0-9.]*)"},
    {"name": "Tailwind CSS", "cat": "UI framework", "html": [r"tailwind(\.min)?\.css", r"\btw-[a-z]"]},
    {"name": "Font Awesome", "cat": "UI framework", "html": [r"font-?awesome"]},
    {"name": "Bulma", "cat": "UI framework", "html": [r"bulma(\.min)?\.css"]},

    # --- Web servers ---
    {"name": "Nginx", "cat": "Web server", "headers": [r"server:\s*nginx"], "version": r"nginx/([0-9][0-9.]*)"},
    {"name": "Apache", "cat": "Web server", "headers": [r"server:\s*apache"], "version": r"apache/([0-9][0-9.]*)"},
    {"name": "Microsoft IIS", "cat": "Web server",
     "headers": [r"server:.*iis"], "version": r"iis/([0-9][0-9.]*)"},
    {"name": "LiteSpeed", "cat": "Web server", "headers": [r"server:\s*litespeed"]},
    {"name": "OpenResty", "cat": "Web server", "headers": [r"server:\s*openresty"]},
    {"name": "Caddy", "cat": "Web server", "headers": [r"server:\s*caddy"]},

    # --- Languages / backend frameworks ---
    {"name": "PHP", "cat": "Programming language",
     "headers": [r"x-powered-by:.*php"], "cookies": [r"PHPSESSID"], "version": r"php/([0-9][0-9.]*)"},
    {"name": "ASP.NET", "cat": "Framework",
     "headers": [r"x-powered-by:.*asp\.net", r"x-aspnet-version:"], "cookies": [r"ASP\.NET_SessionId"]},
    {"name": "Java", "cat": "Programming language", "cookies": [r"JSESSIONID"]},
    {"name": "Laravel", "cat": "Framework", "cookies": [r"laravel_session", r"XSRF-TOKEN"]},
    {"name": "Ruby on Rails", "cat": "Framework",
     "cookies": [r"_rails", r"_session_id"], "headers": [r"x-powered-by:.*phusion passenger"]},
    {"name": "Django", "cat": "Framework", "cookies": [r"csrftoken", r"django"]},
    {"name": "Express", "cat": "Framework", "headers": [r"x-powered-by:\s*express"]},
    {"name": "Flask", "cat": "Framework", "headers": [r"server:.*werkzeug"]},

    # --- CDN / hosting / proxy ---
    {"name": "Cloudflare", "cat": "CDN", "headers": [r"server:\s*cloudflare", r"cf-ray:"]},
    {"name": "Fastly", "cat": "CDN", "headers": [r"x-served-by:\s*cache", r"x-fastly", r"fastly-"]},
    {"name": "Amazon CloudFront", "cat": "CDN", "headers": [r"x-amz-cf-id:", r"via:.*cloudfront"]},
    {"name": "Akamai", "cat": "CDN", "headers": [r"x-akamai", r"server:.*akamai"]},
    {"name": "Vercel", "cat": "Hosting", "headers": [r"server:\s*vercel", r"x-vercel-id:"]},
    {"name": "Netlify", "cat": "Hosting", "headers": [r"server:\s*netlify", r"x-nf-request-id:"]},
    {"name": "GitHub", "cat": "Hosting", "headers": [r"server:.*github"]},

    # --- Analytics / marketing ---
    {"name": "Google Analytics", "cat": "Analytics",
     "html": [r"google-analytics\.com/analytics\.js", r"gtag\('config'", r"GoogleAnalyticsObject"]},
    {"name": "Google Tag Manager", "cat": "Analytics",
     "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"]},
    {"name": "Facebook Pixel", "cat": "Analytics",
     "html": [r"connect\.facebook\.net.*fbevents\.js", r"fbq\('init'"]},
    {"name": "Hotjar", "cat": "Analytics", "html": [r"static\.hotjar\.com", r"hjSiteSettings"]},
    {"name": "HubSpot", "cat": "Marketing", "html": [r"js\.hs-scripts\.com", r"hubspot"]},
]


def do_techstack(domain):
    title("Technology Profiler")
    try:
        resp = requests.get(f"https://{domain}", headers=HEADERS,
                            timeout=12, allow_redirects=True)
    except Exception as exc:
        err(f"Request failed: {exc}")
        return {"error": str(exc)}

    html = resp.text[:600000]                       # cap huge pages
    header_blob = "\n".join(f"{k.lower()}: {v}" for k, v in resp.headers.items())
    cookie_blob = " ".join(resp.cookies.keys())
    version_hay = header_blob + "\n" + html

    detected = {}   # category -> {name: version_or_None}
    for sig in TECH_SIGNATURES:
        hit = (
            any(re.search(p, html, re.I) for p in sig.get("html", []))
            or any(re.search(p, header_blob, re.I) for p in sig.get("headers", []))
            or any(re.search(p, cookie_blob, re.I) for p in sig.get("cookies", []))
        )
        if not hit:
            continue
        version = None
        if sig.get("version"):
            m = re.search(sig["version"], version_hay, re.I)
            if m and m.groups():
                version = m.group(1)
        detected.setdefault(sig["cat"], {})[sig["name"]] = version

    # Meta generator tag often names the exact CMS/builder + version.
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                    html, re.I)
    generator = gen.group(1).strip() if gen else None

    if not detected and not generator:
        warn("No known technologies fingerprinted (site may block bots or be custom).")
        return {"technologies": {}, "generator": None}

    if generator:
        ok("Meta generator", generator)
    for cat in sorted(detected):
        print(f"  {DIM}--- {cat} ---{RESET}")
        for name, version in sorted(detected[cat].items()):
            ok(name, version if version else "")

    total = sum(len(v) for v in detected.values())
    info("Total detected", f"{total} technolog" + ("y" if total == 1 else "ies"))
    return {
        "generator": generator,
        "technologies": {cat: detected[cat] for cat in detected},
    }


# ---------------------------------------------------------------------------
# Menu dispatch
# ---------------------------------------------------------------------------

ACTIONS = {
    "1": ("whois", do_whois),
    "2": ("dns", do_dns),
    "3": ("subdomains", do_subdomains),
    "4": ("ssl", do_ssl),
    "5": ("http_headers", do_headers),
    "6": ("geoip", do_geoip),
    "7": ("ports", do_ports),
    "8": ("wayback", do_wayback),
    "9": ("robots", do_robots),
    "10": ("techstack", do_techstack),
}


def run_all(domain, results):
    for key, (name, func) in ACTIONS.items():
        try:
            results[name] = func(domain)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            err(f"{name} crashed: {exc}")
            results[name] = {"error": str(exc)}


def save_json(domain, results):
    if not results:
        warn("Nothing to save yet - run at least one check first.")
        return
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-z0-9.-]", "_", domain.lower())
    fname = f"reconhawk_{safe}_{stamp}.json"
    payload = {
        "target": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    try:
        with open(fname, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        ok("Saved", fname)
    except OSError as exc:
        err(f"Could not write file: {exc}")


def prompt_domain(current=None):
    while True:
        raw = input(f"\n{BOLD}Enter target domain{RESET} "
                    f"(e.g. example.com): ").strip()
        domain = clean_domain(raw)
        if domain and "." in domain:
            return domain
        if not domain and current:
            return current
        err("Please enter a valid domain like example.com")


def main():
    print(BANNER)
    if not HAVE_DNS:
        warn("dnspython missing -> DNS record check disabled. "
             "Install: pip install dnspython")
    if not HAVE_WHOIS:
        warn("python-whois missing -> WHOIS check disabled. "
             "Install: pip install python-whois")

    prefill = clean_domain(sys.argv[1]) if len(sys.argv) > 1 else None
    domain = prefill if (prefill and "." in prefill) else prompt_domain()
    results = {}

    while True:
        print(f"\n{DIM}  Target:{RESET} {BOLD}{CYAN}{domain}{RESET}")
        print(MENU)
        choice = input(f"  Select an option {BOLD}>{RESET} ").strip().lower()

        if choice in ("0", "q", "exit", "quit"):
            print(f"\n{DIM}  Bye!{RESET}\n")
            break
        elif choice == "11" or choice == "all":
            run_all(domain, results)
        elif choice == "s":
            save_json(domain, results)
        elif choice == "t":
            domain = prompt_domain(domain)
            results = {}
        elif choice in ACTIONS:
            name, func = ACTIONS[choice]
            try:
                results[name] = func(domain)
            except Exception as exc:
                err(f"{name} crashed: {exc}")
        else:
            err("Invalid option. Choose a number from the menu.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{DIM}  Interrupted. Bye!{RESET}\n")
        sys.exit(0)
