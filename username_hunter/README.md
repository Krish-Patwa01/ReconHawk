# Username Hunter

A Sherlock-style OSINT tool that hunts for a username across ~35 websites and
reports where a matching public profile exists.

Useful for checking **your own** digital footprint or for **authorized** OSINT
research.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python hunter.py johndoe
python hunter.py alice bob charlie          # check several usernames
python hunter.py johndoe --found-only        # only show hits
python hunter.py johndoe --output results.txt
python hunter.py johndoe --timeout 10 --workers 30
```

### Options

| Flag           | Description                                      |
|----------------|--------------------------------------------------|
| `--timeout`    | Per-site request timeout in seconds (default 8). |
| `--workers`    | Number of concurrent requests (default 20).      |
| `--found-only` | Only print sites where the username was found.   |
| `--output`     | Append found results to a file.                  |

## How it works

Each site in `sites.json` has a URL template and a detection method:

- **`status`** — adaptive check. First tries the profile URL; if it returns
  `200 OK`, it also probes a random impossible username as a *control*. If the
  control 404s but the real one is 200, it's a reliable hit. If both return 200
  (a "soft 404" site), it compares the redirect destination and page body to
  decide. This is what kills most false positives.
- **`error`** — the page always returns 200, so presence is decided by whether a
  known "user not found" string is **absent** from the body.
- **`presence`** — the opposite: presence is decided by whether a distinctive
  "this profile exists" string (`successText`) is **present** (e.g. Telegram's
  profile-photo element, Pinterest's `- Profile | Pinterest` title).

Results are tagged by confidence: `[+]` = high confidence, `[?]` = likely
(decided by the soft-404 content heuristic). Checks run concurrently with a
thread pool for speed.

## Adding more sites

Edit `sites.json`:

```json
"NewSite": { "url": "https://newsite.com/{}", "check": "status" }
```

For sites that always return 200, use the error method:

```json
"NewSite": { "url": "https://newsite.com/{}", "check": "error", "errorText": "User not found" }
```

## Limitations & ethics

- Results are heuristic. Sites change their layouts, use bot protection
  (Cloudflare, rate limits), or return 200 for non-existent users — expect some
  false positives/negatives.
- A found profile does **not** prove the same real person owns every account.
- Only investigate your own accounts or targets you are authorized to research.
  Respect each site's Terms of Service and applicable law.
