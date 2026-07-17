<h1 align="center">🦅 ReconHawk</h1>

<p align="center">
  <b>All-in-One Domain OSINT & Reconnaissance Toolkit</b><br>
  Profile any domain from a simple numbered menu — WHOIS, DNS, subdomains, SSL,
  tech stack and more. <b>100% free, no API key required.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg" alt="Cross platform">
  <img src="https://img.shields.io/badge/API%20key-not%20required-brightgreen.svg" alt="No API key">
</p>

> ⚠️ **Ethical use only.** Run ReconHawk only on domains you own or are
> explicitly authorized to test.

---

## ✨ Features

Pick a number from the menu, or choose **[11] Run ALL** to run everything at once:

| # | Module | What it does |
|---|--------|--------------|
| 1 | **WHOIS Lookup** | Registrar, IANA ID, abuse contacts, registrant details, status, DNSSEC, dates |
| 2 | **DNS Records** | A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, CAA, DS, DNSKEY + PTR (reverse) |
| 3 | **Subdomain Enumeration** | Merges results from 4 sources (crt.sh, HackerTarget, CertSpotter, AlienVault OTX) — resilient if one is down |
| 4 | **SSL / TLS Certificate** | Issuer, validity, days-to-expiry, SANs, TLS version |
| 5 | **HTTP Security Headers** | Checks HSTS, CSP, X-Frame-Options and more |
| 6 | **IP Geolocation** | Country, city, ISP, ASN, reverse DNS |
| 7 | **Port Scan** | Scans 20 common ports (threaded) |
| 8 | **Wayback Machine** | Latest snapshot + total capture count from archive.org |
| 9 | **robots.txt / sitemap.xml** | Disallowed paths and listed sitemaps |
| 10 | **Technology Profiler** | Wappalyzer-style fingerprinting: CMS, JS frameworks, web server, CDN, backend language, analytics, UI libraries (with versions) |

Extra menu keys: **[S]** save results to JSON · **[T]** change target · **[0]** exit.

## 🚀 Install

```bash
git clone https://github.com/Krish-Patwa01/ReconHawk.git
cd ReconHawk
pip install -r requirements.txt
```

Requires Python 3.8+.

## 🧭 Usage

```bash
python reconhawk.py                # asks for the target, then shows the menu
python reconhawk.py example.com    # pre-fills the target
```

On Windows you can also just double-click **`reconhawk.bat`**.

## 💾 Output

Results print to the terminal in color. Press **S** at any time to save
everything gathered so far to a timestamped JSON file
(`reconhawk_<domain>_<timestamp>.json`) — handy for reports and automation.

## 📝 Notes

- Every check uses public sources only — nothing intrusive.
- Subdomain enumeration queries 4 sources in parallel, so a single slow or
  rate-limited provider won't stop you getting results.
- IP geolocation uses the free `ip-api.com` endpoint (rate-limited, no key).

## 🏷️ Suggested GitHub topics

`osint` · `reconnaissance` · `recon` · `cybersecurity` · `pentesting` ·
`whois` · `dns` · `subdomain-enumeration` · `information-gathering` ·
`security-tools` · `wappalyzer` · `python`

## 👤 Author

**Krishna Patwa**

- GitHub: [github.com/Krish-Patwa01](https://github.com/Krish-Patwa01/)
- LinkedIn: [linkedin.com/in/krishna-patwa](https://www.linkedin.com/in/krishna-patwa/)

---

<p align="center">⭐ If ReconHawk helped you, consider starring the repo!</p>
