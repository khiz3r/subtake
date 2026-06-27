# subtake.py

A fast, multi-threaded subdomain takeover detection tool with smart service fingerprinting, CNAME chain analysis, NS/MX/SPF takeover detection, and cloud IP attribution.

---

## Features

- **CNAME-based detection** — matches CNAME targets against 60+ service fingerprints
- **Multi-hop CNAME chain walking** — detects dead hops in chains that `dig CNAME` alone misses
- **NXDOMAIN detection** — flags unclaimed slots on known platforms (Elastic Beanstalk, Azure, SmugMug, etc.)
- **HTTP body fingerprinting** — fetches the live domain and matches error page signatures
- **False-positive guards** — `not_vulnerable` flags and `not_vulnerable_body` patterns prevent FPs on services like CloudFront, HubSpot, Zendesk, Firebase, etc.
- **NS takeover detection** — checks for dangling NS delegations where the nameserver domain is unregistered or returns SERVFAIL/NXDOMAIN
- **MX takeover detection** — SubdoMailing-style dead MX host detection
- **SPF include/redirect takeover** — finds dead `include:` and `redirect=` domains in SPF records that allow email spoofing
- **A record → cloud IP fingerprinting** — detects IP-recycling takeover scenarios (AWS, Azure, GCP)
- **Wildcard DNS detection** — skips domains where parent has a wildcard record to avoid false positives
- **Concurrent scanning** — configurable thread pool for bulk subdomain lists
- **JSON output** — machine-readable results for pipeline integration
- **Fallback mode** — works without `dig` using `host` and `socket` fallbacks

---

## Requirements

```
Python 3.8+
dig       (from dnsutils / bind-tools)
curl
```

Install DNS tools if missing:

```bash
# Debian/Ubuntu
sudo apt install dnsutils curl

# macOS
brew install bind curl
```

> If `dig` is unavailable, the tool falls back to `host` (CNAME) and `socket` (resolve). MX, NS, SPF, and A-record cloud detection require `dig`.

---

## Installation

```bash
git clone https://github.com/khiz3r/subtake.git
cd subtake
chmod +x subtake.py
```

No Python dependencies — stdlib only.

---

## Usage

```
python3 subtake.py -d <domain>
python3 subtake.py -f subdomains.txt
cat subs.txt | python3 subtake.py
python3 subtake.py -f subs.txt --only-vuln -o results.json
```

### Options

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Single domain to check |
| `-f`, `--file` | File with one domain per line |
| `-t`, `--threads` | Number of threads (default: 10) |
| `-o`, `--output` | Save results to JSON file |
| `--only-vuln` | Only print/save VULNERABLE and POSSIBLE results |
| `--http` | Force plain HTTP instead of HTTPS |
| `--delay` | Seconds to sleep between requests per thread |
| `--json` | Print JSON results to stdout |
| `--debug` | Show raw output of every DNS/HTTP command |
| `-v`, `--version` | Print version and exit |

---

## Examples

**Single domain:**
```bash
python3 subtake.py -d sub.target.com
```

**Bulk scan with output:**
```bash
python3 subtake.py -f subdomains.txt -t 20 --only-vuln -o vuln.json
```

**Pipe from subfinder/amass:**
```bash
subfinder -d target.com -silent | python3 subtake.py --only-vuln
```

**JSON to stdout for jq:**
```bash
python3 subtake.py -f subs.txt --json | jq '.[] | select(.verdict == "VULNERABLE")'
```

**Debug a specific domain:**
```bash
python3 subtake.py -d sub.target.com --debug
```

---

## Detection Logic

```
Domain
│
├─ Has CNAME?
│   ├─ No ──► Wildcard check → NS takeover → MX takeover → SPF takeover → A record cloud IP
│   │
│   └─ Yes ──► CNAME target resolves?
│               ├─ No  ──► VULNERABLE (NXDOMAIN, slot unclaimed)
│               └─ Yes ──► known not_vulnerable service? → NOT_VULNERABLE
│                          nxdomain_only service? → NOT_VULNERABLE
│                          HTTP body fingerprint match?
│                           ├─ Yes + edge_case ──► POSSIBLE
│                           ├─ Yes              ──► POSSIBLE
│                           └─ No               ──► NOT_VULNERABLE
│
└─ Multi-hop chain ──► Any dead hop? ──► VULNERABLE
```

---

## Verdict Reference

| Verdict | Meaning |
|---------|---------|
| 🔴 `VULNERABLE` | CNAME/chain points to an unclaimed slot — high confidence |
| 🔴 `VULNERABLE_NS` | Dangling NS delegation — nameserver domain unregistered |
| 🟡 `POSSIBLE` | CNAME resolves but error fingerprint matched — verify manually |
| 🟡 `POSSIBLE_MX` | Dead MX host — SubdoMailing / email takeover risk |
| 🟡 `POSSIBLE_SPF` | Dead SPF include/redirect domain — email spoofing risk |
| 🟡 `POSSIBLE_A` | A record in cloud IP space with takeover fingerprint (IP recycling) |
| 🟢 `NOT_VULNERABLE` | No indicators of takeover |
| ⚪ `NO_CNAME` | No CNAME record found |
| ⚫ `NO_DNS` | Domain has no DNS records at all |
| 🔵 `WILDCARD_SKIP` | Parent has wildcard DNS — results unreliable, skipped |
| ⚠️ `ERROR` | Unexpected error during check |

---

## Service Coverage

60+ services across categories:

**Cloud / Infrastructure**
AWS S3, Elastic Beanstalk, CloudFront\*, ELB\*, Microsoft Azure, Google Cloud Storage\*, Cloudflare Pages\*, Cloudflare R2\*

**Hosting / PaaS**
Heroku, Vercel, Netlify, Render, Railway, Surge.sh, Fly.io\*, Pantheon, WP Engine\*, Kinsta\*, Fastly\*, Ngrok, Discourse, JetBrains YouTrack

**Dev / Docs**
GitHub Pages, GitLab\*, Bitbucket, Readme.io, Readthedocs, GitBook, HatenaBlog, Anima, Gemfury

**Website Builders**
Webflow, Ghost, Squarespace\*, Wix, Strikingly, Tilda, Cargo Collective, Tumblr, WordPress.com, Worksites, Bubble.io, Framer, Durable, Webador, Stacker, Umbraco Cloud, Acquia\*, Frontify, Launchrock

**SaaS / Support**
HubSpot\*, Zendesk\*, Intercom, Freshdesk\*, Statuspage.io\*, HelpScout, HelpJuice, Helprace, UserVoice\*, Canny, Campaign Monitor, GetResponse, Pingdom, Uptimerobot, Agile CRM, Short.io, SurveySparrow, Uberflip, SmartJobBoard, Landingi, Mashery

**E-commerce**
Shopify, BigCartel

**Email / CDN**
SendGrid\*, Fastly\*, KeyCDN\*, Airee.ru

**Other**
Digital Ocean, Wishpond, SmugMug, Unbounce\*, Instapage\*, Mailchimp\*, Smartling, Feedpress\*, Firebase\*, Google Sites\*, Supabase, Dreamhost\*

> \* Marked `not_vulnerable` — detected and reported as NOT_VULNERABLE with FP guards to prevent false positives.

---

## JSON Output Format

Each result object:

```json
{
  "domain": "sub.target.com",
  "cname": "dead-app.herokudns.com",
  "cname_resolves": false,
  "cname_chain": null,
  "ns_records": null,
  "mx_records": null,
  "spf_includes": null,
  "a_ips": null,
  "cloud_provider": null,
  "service": "Heroku",
  "status_code": null,
  "verdict": "VULNERABLE",
  "confidence": "HIGH",
  "reason": "CNAME target 'dead-app.herokudns.com' returns NXDOMAIN — slot is unclaimed",
  "claim": "heroku create <slug> && heroku domains:add <subdomain>"
}
```

---

## Integrating with Recon Pipelines

```bash
# subfinder → subtake → notify
subfinder -d target.com -silent \
  | python3 subtake.py --only-vuln --json \
  | jq -r '.[] | "[" + .verdict + "] " + .domain + " → " + .service'

# amass + httpx pre-filter
amass enum -passive -d target.com \
  | python3 subtake.py -t 30 --only-vuln -o results.json
```

---

## Notes

- HTTPS is tried first; falls back to HTTP on TLS/connection errors (curl exit codes 7, 35, 60).
- curl follows redirects (`-L`) and extracts the status from the final response block, not intermediate 301s.
- Multi-hop CNAME chains are walked via `dig +short` which resolves the full chain in one query.
- Wildcard detection probes a random 20-character subdomain of the parent zone before running any checks.
- The `--delay` flag applies per-thread, useful for rate-sensitive targets.

---

## License

MIT