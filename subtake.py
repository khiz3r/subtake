#!/usr/bin/env python3
"""
subtake.py - Subdomain Takeover Decision Tool

Requirements: dig (dnsutils), curl
  Fallback: if dig is unavailable, CNAME lookup uses 'host' and resolve uses socket.

Usage:
  python3 subtake.py -d sub.target.com
  python3 subtake.py -f subdomains.txt
  cat subs.txt | python3 subtake.py
  python3 subtake.py -f subs.txt --only-vuln -o results.json
"""

import os
import sys
import re
import json
import time
import random
import string
import socket
import argparse
import subprocess
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

_PRINT_LOCK = threading.Lock()

VERSION = "3.2.0"
DEBUG = False  # set by --debug flag

# ── Local config / cache ────────────────────────────────────────────────────────
# Fingerprint & IP-range lists are no longer downloaded on every run. They are
# fetched once and cached under ~/.config/subtake/, and only refreshed when the
# user explicitly passes --update-list. Normal runs read the cache (fast, works
# offline). If no cache exists yet, the tool falls back to the built-in lists
# and tells the user to run --update-list.
CONFIG_DIR           = Path.home() / ".config" / "subtake"
SERVICES_CACHE_FILE  = CONFIG_DIR / "services.json"
IPS_CACHE_FILE       = CONFIG_DIR / "ips.json"

# ── Online fingerprint source ──────────────────────────────────────────────────
# can-i-take-over-xyz publishes a machine-readable fingerprint list.
# We fetch it at startup and merge with built-ins (online wins on name collision).
# Falls back to built-ins silently on any error.
_CITOX_URL = (
    "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz"
    "/master/fingerprints.json"
)

def _fetch_online_fingerprints(timeout=5):
    """Fetch fingerprints from can-i-take-over-xyz.
    Returns list of dicts normalised to subtake's schema, or [] on failure."""
    try:
        import urllib.request
        with urllib.request.urlopen(_CITOX_URL, timeout=timeout) as resp:
            raw = json.loads(resp.read().decode())
    except Exception:
        return []

    out = []
    for entry in raw:
        # Schema from repo: service, cname (list), fingerprint (list of strings),
        # vulnerable (bool), discussion, documentation, nxdomain (bool)
        service = entry.get("service") or entry.get("name", "")
        if not service:
            continue
        cnames = entry.get("cname", [])
        fingerprints = entry.get("fingerprint", [])
        is_nxdomain = entry.get("nxdomain", False)
        vulnerable = entry.get("vulnerable", True)

        # Build CNAME regex patterns: escape dots, anchor with $
        cname_pats = []
        for c in cnames:
            c = c.strip().lstrip("*").lstrip(".")
            if c:
                # Escape and build a suffix match pattern
                escaped = re.escape(c)
                cname_pats.append(rf"(?:^|\.){escaped}$")

        # body can be a string or list in the remote schema
        if isinstance(fingerprints, str):
            fingerprints = [fingerprints] if fingerprints else []

        discussion = entry.get("discussion", "")
        documentation = entry.get("documentation", "")

        svc = {
            "name": service,
            "cname": cname_pats,
            "body": fingerprints,
            "_online": True,
        }
        if discussion:
            svc["discussion"] = discussion
        if documentation:
            svc["documentation"] = documentation
        if not vulnerable:
            svc["not_vulnerable"] = True
        if is_nxdomain:
            svc["nxdomain_only"] = True
        out.append(svc)
    return out

_ONLINE_FP_CACHE = None   # fetched once per process
_ONLINE_FP_STATUS = None  # human-readable status string shown in the banner

def _ensure_config_dir():
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        dbg("config dir", note=f"could not create {CONFIG_DIR}: {e}")
        return False

def _load_services_cache():
    """Load previously-cached online fingerprints from services.json.
    Returns (list_of_service_dicts, fetched_at_str) or (None, None) if the
    cache doesn't exist yet or is corrupt/unreadable."""
    try:
        with open(SERVICES_CACHE_FILE) as f:
            data = json.load(f)
        return data.get("services", []), data.get("fetched_at")
    except Exception as e:
        dbg("services cache", note=f"load failed or absent: {e}")
        return None, None

def _save_services_cache(services):
    """Persist fetched online fingerprints to services.json."""
    if not _ensure_config_dir():
        return False
    try:
        payload = {
            "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "source": _CITOX_URL,
            "services": services,
        }
        with open(SERVICES_CACHE_FILE, "w") as f:
            json.dump(payload, f, indent=2)
        return True
    except Exception as e:
        dbg("services cache", note=f"save failed: {e}")
        return False

def _merge_online_services(online):
    """Merge a list of online fingerprint entries into the global SERVICES list.

    - Services whose name isn't already a builtin are appended as-is.
    - Services that DO collide with a builtin are NOT used to replace it
      (builtins carry richer metadata — not_vulnerable guards, edge_case
      flags, hand-verified claims — that we don't want to lose), but their
      'discussion'/'documentation' text IS backfilled onto the builtin entry
      if the builtin doesn't already have it. This is what feeds the
      'description' field in results for the vast majority of matches, which
      otherwise stayed empty even on confirmed vulnerable findings.

    Returns (num_added, num_backfilled).
    """
    global SERVICES
    by_name = {s["name"].lower(): s for s in SERVICES}
    added = 0
    backfilled = 0
    for svc in online:
        key = svc.get("name", "").lower()
        if not key:
            continue
        existing = by_name.get(key)
        if existing:
            if svc.get("discussion") and not existing.get("discussion"):
                existing["discussion"] = svc["discussion"]
                backfilled += 1
            if svc.get("documentation") and not existing.get("documentation"):
                existing["documentation"] = svc["documentation"]
                backfilled += 1
        else:
            SERVICES.append(svc)
            by_name[key] = svc
            added += 1
    return added, backfilled

# ── ANSI colors ────────────────────────────────────────────────────────────────
R   = "\033[91m"
G   = "\033[92m"
Y   = "\033[93m"
B   = "\033[94m"
M   = "\033[95m"
C   = "\033[96m"
W   = "\033[97m"
DIM = "\033[2m"
RST = "\033[0m"
BOLD= "\033[1m"

def dbg(label, cmd=None, stdout=None, stderr=None, note=None):
    if not DEBUG:
        return
    print(f"\n{M}{BOLD}  [DEBUG] {label}{RST}", file=sys.stderr)
    if cmd:
        print(f"  {DIM}  cmd    : {' '.join(cmd)}{RST}", file=sys.stderr)
    if stdout is not None:
        out = stdout.strip() if stdout.strip() else "(empty)"
        print(f"  {DIM}  stdout : {out}{RST}", file=sys.stderr)
    if stderr and stderr.strip():
        print(f"  {DIM}  stderr : {stderr.strip()}{RST}", file=sys.stderr)
    if note:
        print(f"  {DIM}  note   : {note}{RST}", file=sys.stderr)

# ── Service fingerprints ───────────────────────────────────────────────────────
# Fields:
#   name               : display name
#   cname              : list of regex patterns matched against CNAME target
#   nxdomain_only      : True = vulnerable purely by NXDOMAIN, no HTTP needed
#   body               : list of strings that, if found in response, indicate vulnerable
#   not_vulnerable_body: list of strings that, if found, override body as NOT vulnerable
#   claim              : how-to-claim hint
#   edge_case          : True = flag as POSSIBLE even on body match (needs manual verify)
#   not_vulnerable     : True = service is known-not-vulnerable; used as a guard to avoid FPs

SERVICES = [

    # ── AWS ──────────────────────────────────────────────────────────────────
    {
        "name": "AWS S3",
        "cname": [r"\.s3\.amazonaws\.com$", r"\.s3-website[\.-]", r"s3-website"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "claim": "aws s3api create-bucket --bucket <name>",
    },
    {
        "name": "AWS Elastic Beanstalk",
        "cname": [r"\.elasticbeanstalk\.com$"],
        "nxdomain_only": True,
        "body": [],
        "claim": "eb create <app-name> and eb domain:add <subdomain>",
    },
    {
        "name": "AWS CloudFront",
        "cname": [r"\.cloudfront\.net$"],
        # CloudFront is NOT vulnerable per can-i-take-over-xyz (domain ownership enforced)
        # Keep as guard to prevent false positives from generic 4xx body matches
        "not_vulnerable": True,
        "not_vulnerable_body": ["viewercertificateexception", "x-amz-replication-status",
                                "AmazonS3", "Cannot GET"],
        "body": [],
        "claim": "N/A — CloudFront enforces domain ownership verification",
    },
    {
        "name": "AWS Load Balancer (ELB)",
        "cname": [r"\.elb\.amazonaws\.com$"],
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — ELB is not vulnerable to subdomain takeover",
    },

    # ── Azure ─────────────────────────────────────────────────────────────────
    {
        "name": "Microsoft Azure",
        "cname": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.cloudapp\.net$",
            r"\.blob\.core\.windows\.net$",
            r"\.azure-api\.net$",
            r"\.azurehdinsight\.net$",
            r"\.azureedge\.net$",
            r"\.azurecontainer\.io$",
            r"\.database\.windows\.net$",
            r"\.azuredatalakestore\.net$",
            r"\.search\.windows\.net$",
            r"\.azurecr\.io$",
            r"\.redis\.cache\.windows\.net$",
            r"\.servicebus\.windows\.net$",
            r"\.visualstudio\.com$",
        ],
        "nxdomain_only": True,
        "body": ["404 Web Site not found", "This web app has been stopped"],
        "claim": "Create Azure resource with the same hostname slug in any subscription",
    },

    # ── GitHub / GitLab / Bitbucket ───────────────────────────────────────────
    {
        "name": "GitHub Pages",
        "cname": [r"\.github\.io$"],
        "body": ["There isn't a GitHub Pages site here"],
        "edge_case": True,
        "claim": "Create a GitHub repo named <slug> with Pages enabled and add CNAME file",
    },
    {
        "name": "Bitbucket",
        "cname": [r"\.bitbucket\.io$"],
        "body": ["Repository not found"],
        "claim": "Create a Bitbucket repo and enable Pages hosting",
    },
    {
        "name": "GitLab",
        "cname": [r"\.gitlab\.io$"],
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — GitLab validates domain ownership",
    },

    # ── Hosting / PaaS ────────────────────────────────────────────────────────
    {
        "name": "Heroku",
        "cname": [r"\.herokudns\.com$", r"\.herokuapp\.com$"],
        "body": ["No such app"],
        "edge_case": True,
        "claim": "heroku create <slug> && heroku domains:add <subdomain>",
    },
    {
        "name": "Vercel",
        "cname": [r"\.vercel\.app$", r"\.now\.sh$", r"cname\.vercel-dns\.com$"],
        "body": ["DEPLOYMENT_NOT_FOUND", "The deployment could not be found",
                 "This deployment has been disabled"],
        "edge_case": True,
        "claim": "vercel --prod and add domain to project",
    },
    {
        "name": "Netlify",
        "cname": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "body": ["Not Found - Request ID"],
        "edge_case": True,
        "claim": "Create Netlify site and add custom domain",
    },
    {
        "name": "Fly.io",
        "cname": [r"\.fly\.dev$", r"\.fly\.io$"],
        # Fly.io is NOT vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — Fly.io validates domain ownership",
    },
    {
        "name": "Render",
        "cname": [r"\.onrender\.com$"],
        "body": ["Not Found - Check that you have the right URL",
                 "Application not found"],
        "claim": "Create a Render service and add custom domain",
    },
    {
        "name": "Railway",
        "cname": [r"\.up\.railway\.app$", r"\.railway\.app$"],
        "body": ["Application not found"],
        "claim": "railway domain add <subdomain>",
    },
    {
        "name": "Surge.sh",
        "cname": [r"\.surge\.sh$", r"\.na-west1\.surge\.sh$"],
        "body": ["project not found"],
        "claim": "surge --domain <subdomain>",
    },
    {
        "name": "Pantheon",
        "cname": [r"\.pantheonsite\.io$", r"\.getpantheon\.com$"],
        "body": ["The gods are wise", "404 error unknown site"],
        "claim": "Add domain to Pantheon site dashboard",
    },
    {
        "name": "Fastly",
        "cname": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
        # Fastly is NOT vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["fastly error: unknown domain"],
        "body": [],
        "claim": "N/A — Fastly validates domain ownership",
    },
    {
        "name": "WP Engine",
        "cname": [r"\.wpengine\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — WP Engine validates domain ownership",
    },
    {
        "name": "Kinsta",
        "cname": [r"\.kinsta\.cloud$", r"\.kinstacdn\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["No Site For Domain"],
        "body": [],
        "claim": "N/A — Kinsta validates domain ownership",
    },
    {
        "name": "Ngrok",
        "cname": [r"\.ngrok\.io$", r"\.ngrok-free\.app$"],
        "body": ["Tunnel .*.ngrok.io not found", "ngrok.io not found"],
        "claim": "ngrok http --hostname=<subdomain> <port>",
    },
    {
        "name": "Launchrock",
        "cname": [r"\.launchrock\.com$"],
        "body": ["It looks like you may have taken a wrong turn"],
        "claim": "Create a Launchrock account and claim the slug",
    },
    {
        "name": "JetBrains YouTrack",
        "cname": [r"\.youtrack\.cloud$"],
        "body": ["is not a registered InCloud YouTrack"],
        "claim": "Register a YouTrack InCloud instance with the same slug",
    },
    {
        "name": "Discourse",
        "cname": [r"\.trydiscourse\.com$"],
        "nxdomain_only": True,
        "body": [],
        "claim": "Create a Discourse instance and point the domain to it",
    },

    # ── Website builders ──────────────────────────────────────────────────────
    {
        "name": "Webflow",
        "cname": [r"\.webflow\.io$", r"proxy\.webflow\.com$"],
        "body": ["The page you are looking for doesn't exist",
                 "The page you are looking for doesn\u2019t exist",
                 "site is not live"],
        "edge_case": True,
        "claim": "Create Webflow project and publish with custom domain",
    },
    {
        "name": "Ghost",
        "cname": [r"\.ghost\.io$"],
        "body": ["Site unavailable", "Failed to resolve DNS path for this host"],
        "claim": "Create Ghost(Pro) publication with that subdomain",
    },
    {
        "name": "Squarespace",
        "cname": [r"\.squarespace\.com$", r"ext-cust\.squarespace\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — Squarespace validates domain ownership",
    },
    {
        "name": "Wix",
        "cname": [r"\.wixdns\.net$", r"\.wix\.com$"],
        "body": ["Looks Like This Domain Isn't Connected To A Website Yet!",
                 "Error ConnectYourDomain occurred", "wixErrorPagesApp"],
        "edge_case": True,
        "claim": "Create Wix site (premium required) and connect domain",
    },
    {
        "name": "Strikingly",
        "cname": [r"\.strikinglydns\.com$", r"\.s\.strikinglydns\.com$"],
        "body": ["PAGE NOT FOUND."],
        "claim": "Create Strikingly site and add custom domain",
    },
    {
        "name": "Tilda",
        "cname": [r"\.tilda\.ws$"],
        "body": ["Please renew your subscription"],
        "edge_case": True,
        "claim": "Create Tilda account and add the domain",
    },
    {
        "name": "Cargo Collective",
        "cname": [r"\.cargocollective\.com$"],
        "body": ["404 Not Found", "If you're moving your domain away from Cargo"],
        "claim": "Create Cargo account and add domain",
    },
    {
        "name": "Tumblr",
        "cname": [r"\.tumblr\.com$"],
        "body": ["Whatever you were looking for doesn't currently exist"],
        "edge_case": True,
        "claim": "Create Tumblr blog and set custom domain",
    },
    {
        "name": "WordPress.com",
        "cname": [r"\.wordpress\.com$"],
        "body": ["Do you want to register"],
        "claim": "Create WordPress.com site (paid plan required) and map domain",
    },
    {
        "name": "Worksites",
        "cname": [r"\.worksites\.net$"],
        "body": ["Hello! Sorry, but the website you\u2019re looking for doesn\u2019t exist.",
                 "Hello! Sorry, but the website you're looking for doesn't exist."],
        "claim": "Register the slug at worksites.net",
    },

    # ── E-commerce ────────────────────────────────────────────────────────────
    {
        "name": "Shopify",
        "cname": [r"\.myshopify\.com$", r"shops\.myshopify\.com$"],
        "body": ["Sorry, this shop is currently unavailable"],
        "edge_case": True,
        "claim": "Create Shopify store and add custom domain",
    },
    {
        "name": "BigCartel",
        "cname": [r"\.bigcartel\.com$"],
        "body": ["An error has occurred", "This shop is not active"],
        "claim": "Create a BigCartel shop and add the domain",
    },

    # ── SaaS / Support ────────────────────────────────────────────────────────
    {
        "name": "HubSpot",
        "cname": [r"\.hubspot\.com$", r"\.hs-sites\.com$", r"\.hubspotpagebuilder\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["This page isn't available", "Domain not configured"],
        "body": [],
        "claim": "N/A — HubSpot validates domain ownership",
    },
    {
        "name": "Zendesk",
        "cname": [r"\.zendesk\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["Help Center Closed"],
        "body": [],
        "claim": "N/A — Zendesk validates domain ownership",
    },
    {
        "name": "Intercom",
        "cname": [r"\.intercom\.io$", r"custom\.intercom\.io$"],
        "body": ["Uh oh. That page doesn"],
        "edge_case": True,
        "claim": "Add custom domain inside Intercom Messenger settings",
    },
    {
        "name": "Freshdesk",
        "cname": [r"\.freshdesk\.com$", r"\.freshservice\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["Maybe this is still fresh!", "You can claim it now"],
        "body": [],
        "claim": "N/A — Freshdesk validates domain ownership",
    },
    {
        "name": "Statuspage.io",
        "cname": [r"\.statuspage\.io$"],
        # Not vulnerable — Atlassian added DNS verification token requirement
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — Statuspage.io requires DNS verification token, not vulnerable",
    },
    {
        "name": "HelpScout",
        "cname": [r"\.helpscoutdocs\.com$"],
        "body": ["No settings were found for this company:"],
        "claim": "Create a HelpScout Docs site and add custom domain",
    },
    {
        "name": "HelpJuice",
        "cname": [r"\.helpjuice\.com$"],
        "body": ["We could not find what you're looking for.",
                 "We could not find what you\u2019re looking for."],
        "claim": "Create a HelpJuice account and claim the subdomain slug",
    },
    {
        "name": "Helprace",
        "cname": [r"\.helprace\.com$"],
        "body": ["Helprace"],
        "claim": "Create a Helprace account and add the domain",
    },
    {
        "name": "UserVoice",
        "cname": [r"\.uservoice\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["This UserVoice subdomain is currently available"],
        "body": [],
        "claim": "N/A — UserVoice validates subdomain ownership",
    },
    {
        "name": "Readme.io",
        "cname": [r"\.readme\.io$", r"\.readmessl\.com$"],
        "body": ["The creators of this project are still working on making everything perfect!"],
        "claim": "Create a Readme.io project and add the custom domain",
    },
    {
        "name": "Readthedocs",
        "cname": [r"\.readthedocs\.io$", r"\.readthedocs\.org$"],
        "body": ["The link you have followed or the URL that you entered does not exist."],
        "claim": "Create a Read the Docs project and add the custom domain",
    },
    {
        "name": "Canny",
        "cname": [r"\.canny\.io$"],
        "body": ["Company Not Found", "There is no such company. Did you enter the right URL?"],
        "claim": "Create a Canny account and claim the company slug",
    },
    {
        "name": "Campaign Monitor",
        "cname": [r"\.createsend\.com$", r"\.cmail\d+\.com$"],
        "body": ["Trying to access your account?"],
        "claim": "Create a Campaign Monitor account and add the domain",
    },
    {
        "name": "GetResponse",
        "cname": [r"\.getresponse\.com$", r"\.gr-cname\.com$"],
        "body": ["With GetResponse Landing Pages, lead generation has never been easier"],
        "claim": "Create a GetResponse account and claim the landing page domain",
    },
    {
        "name": "Pingdom",
        "cname": [r"\.pingdom\.com$"],
        "body": ["Sorry, couldn't find the status page",
                 "Public Status Page"],
        "claim": "Create a Pingdom account and set up a status page with this domain",
    },
    {
        "name": "Uptimerobot",
        "cname": [r"\.stats\.uptimerobot\.com$"],
        "body": ["page not found"],
        "claim": "Create an UptimeRobot account and add a status page with this domain",
    },
    {
        "name": "Agile CRM",
        "cname": [r"\.agilecrm\.com$"],
        "body": ["Sorry, this page is no longer available."],
        "claim": "Create an Agile CRM account and claim the subdomain",
    },
    {
        "name": "Short.io",
        "cname": [r"\.short\.io$"],
        "body": ["Link does not exist", "Link Not Found"],
        "claim": "Create a Short.io account and add the custom domain",
    },
    {
        "name": "SurveySparrow",
        "cname": [r"\.surveysparrow\.com$"],
        "body": ["Account not found."],
        "claim": "Create a SurveySparrow account and claim the subdomain",
    },
    {
        "name": "Uberflip",
        "cname": [r"\.read\.uberflip\.com$", r"\.uberflip\.com$"],
        "body": ["The URL you've accessed does not provide a hub.",
                 "Non-hub domain"],
        "claim": "Create an Uberflip account and add the custom domain",
    },
    {
        "name": "Unbounce",
        "cname": [r"\.unbouncepages\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["The requested URL was not found on this server."],
        "body": [],
        "claim": "N/A — Unbounce validates domain ownership",
    },
    {
        "name": "Instapage",
        "cname": [r"\.pageserve\.co$", r"\.instapage\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — Instapage validates domain ownership",
    },
    {
        "name": "Mailchimp",
        "cname": [r"\.mcsv\.net$", r"\.list-manage\.com$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["We can't find that page"],
        "body": [],
        "claim": "N/A — Mailchimp validates domain ownership",
    },
    {
        "name": "Smartling",
        "cname": [r"\.smartling\.com$"],
        "body": ["Domain is not configured"],
        "edge_case": True,
        "claim": "Create a Smartling account and claim the domain",
    },
    {
        "name": "SmugMug",
        "cname": [r"\.smugmug\.com$"],
        "nxdomain_only": True,
        "body": [],
        "claim": "Create a SmugMug account and add the custom domain",
    },
    {
        "name": "SmartJobBoard",
        "cname": [r"\.smartjobboard\.com$"],
        "body": ["This job board website is either expired or its domain name is invalid."],
        "claim": "Create a SmartJobBoard account and add the domain",
    },
    {
        "name": "HatenaBlog",
        "cname": [r"\.hatenablog\.com$", r"\.hatenablog\.jp$"],
        "body": ["404 Blog is not found"],
        "claim": "Create a Hatena Blog and add the custom domain",
    },
    {
        "name": "Anima",
        "cname": [r"\.animaapp\.io$"],
        "body": ["The page you were looking for does not exist."],
        "claim": "Create an Anima project and add the custom domain",
    },
    {
        "name": "Gemfury",
        "cname": [r"\.furyns\.com$"],
        "body": ["404: This page could not be found."],
        "claim": "Create a Gemfury account and add the domain",
    },
    {
        "name": "Digital Ocean",
        "cname": [r"\.digitalocean\.com$"],
        "body": ["Domain uses DO name servers with no records in DO."],
        "claim": "Add DNS records in DigitalOcean for this domain",
    },
    {
        "name": "Airee.ru",
        "cname": [r"\.airee\.ru$"],
        "body": ["\u041e\u0448\u0438\u0431\u043a\u0430 402", "\u0421\u0435\u0440\u0432\u0438\u0441 \u0410\u0439\u0440\u0438.\u0440\u0444 \u043d\u0435 \u043e\u043f\u043b\u0430\u0447\u0435\u043d"],
        "claim": "Register the Airee.ru service account",
    },
    {
        "name": "Wishpond",
        "cname": [r"\.wishpond\.com$"],
        "body": ["https://www.wishpond.com/404", "page not found"],
        "claim": "Create a Wishpond account and add the domain",
    },
    {
        "name": "GitBook",
        "cname": [r"\.gitbook\.io$"],
        "body": ["gitbook.io - Domain not found", "If you need to talk to us"],
        "claim": "Create a GitBook space and add the custom domain",
    },
    {
        "name": "Feedpress",
        "cname": [r"\.feedpress\.me$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "not_vulnerable_body": ["The feed has not been found."],
        "body": [],
        "claim": "N/A — Feedpress validates domain ownership",
    },
    {
        "name": "Firebase",
        "cname": [r"\.firebaseapp\.com$", r"\.web\.app$"],
        # Not vulnerable per can-i-take-over-xyz
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — Firebase validates domain ownership",
    },
    {
        "name": "Google Cloud Storage",
        "cname": [r"\.storage\.googleapis\.com$"],
        # Not vulnerable per can-i-take-over-xyz (different account isolation)
        "not_vulnerable": True,
        "not_vulnerable_body": ["NoSuchBucket"],
        "body": [],
        "claim": "N/A — GCS bucket names are globally unique but not vulnerable to takeover",
    },
    {
        "name": "Cloudflare Pages",
        "cname": [r"\.pages\.dev$"],
        # Not vulnerable — Cloudflare validates ownership
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — Cloudflare Pages validates domain ownership",
    },

    # ── New / emerging services ────────────────────────────────────────────────

    # Bubble.io — no-code app builder, confirmed vulnerable (bug bounty reports 2024-25)
    # CNAME target: app.bubble.io — 403 on unclaimed domain = takeover possible
    {
        "name": "Bubble.io",
        "cname": [r"\.bubble\.io$", r"^app\.bubble\.io$"],
        "body": ["There was a problem loading this app. Please check back later.",
                 "The page you requested was not found"],
        "edge_case": True,
        "claim": "Register bubble.io account, create app, add custom domain in Settings → Domain/Email",
    },

    # Supabase — open-source Firebase alternative; CNAME → <ref>.supabase.co
    # If project is deleted the CNAME dangles; Supabase requires TXT verification for custom domains
    {
        "name": "Supabase",
        "cname": [r"\.supabase\.co$", r"\.supabase\.in$"],
        "body": ["Project not found", "supabase project is paused",
                 "This Supabase project is currently paused"],
        "not_vulnerable_body": ["supabase.com", "supabase.io"],
        "edge_case": True,
        "claim": "Create Supabase project with same ref slug and add custom domain via CLI: supabase domains create",
    },

    # Cloudflare R2 — object storage with public bucket URLs
    {
        "name": "Cloudflare R2",
        "cname": [r"\.r2\.cloudflarestorage\.com$", r"\.r2\.dev$"],
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — Cloudflare R2 requires account ownership verification for custom domains",
    },

    # Stacker — app builder on top of Airtable/Google Sheets
    {
        "name": "Stacker",
        "cname": [r"\.stackerhq\.com$", r"\.stacker\.app$"],
        "body": ["This app doesn't exist", "No app found for this domain",
                 "The app you are looking for could not be found"],
        "claim": "Create Stacker account at stackerhq.com and add custom domain in app settings",
    },

    # Durable — AI website builder
    {
        "name": "Durable",
        "cname": [r"\.durable\.co$", r"\.durable\.site$"],
        "body": ["This site doesn't exist", "Website not found",
                 "This website is no longer available"],
        "claim": "Create Durable account and publish a site pointing to this domain",
    },

    # Webador — website builder popular in EU
    {
        "name": "Webador",
        "cname": [r"\.webador\.com$", r"\.webador\.co\.uk$"],
        "body": ["This website does not exist", "Page not found"],
        "claim": "Create Webador account and connect domain in website settings",
    },

    # Framer — design-to-site builder, increasingly common in bug bounty targets
    {
        "name": "Framer",
        "cname": [r"\.framer\.app$", r"\.framer\.website$", r"\.framer\.site$"],
        "body": ["Site Not Published", "This site hasn't been published yet",
                 "No site found for this domain"],
        "edge_case": True,
        "claim": "Create Framer project, publish site, add custom domain in Site Settings → Custom Domain",
    },

    # Umbraco Cloud — .NET CMS hosting
    {
        "name": "Umbraco Cloud",
        "cname": [r"\.umbraco\.io$", r"\.s1\.umbraco\.io$"],
        "body": ["The specified hostname is not a registered"],
        "claim": "Create Umbraco Cloud project and add hostname in project settings",
    },

    # Acquia — Drupal cloud hosting (fingerprint confirmed not vulnerable but guard needed)
    {
        "name": "Acquia",
        "cname": [r"\.acquia-sites\.com$", r"\.acquia\.com$"],
        "not_vulnerable": True,
        "not_vulnerable_body": ["Web Site Not Found", "The requested URL was not found"],
        "body": [],
        "claim": "N/A — Acquia validates domain ownership",
    },

    # Landingi — landing page builder (edge case per can-i-take-over-xyz)
    {
        "name": "Landingi",
        "cname": [r"\.landingi\.com$", r"\.landingi\.co$"],
        "body": ["It looks like you\u2019re lost...", "It looks like you're lost..."],
        "edge_case": True,
        "claim": "Create Landingi account and add custom domain to a landing page",
    },

    # Frontify — brand management platform (edge case)
    {
        "name": "Frontify",
        "cname": [r"\.frontify\.com$"],
        "body": ["404 - Page Not Found", "Oops\u2026 looks like you got lost",
                 "Oops... looks like you got lost"],
        "edge_case": True,
        "claim": "Create Frontify workspace and add custom domain",
    },

    # SendGrid — email platform; platform itself not vulnerable but acts as intermediate
    # CNAME chains through sendgrid.net are used to reach third-party services
    {
        "name": "SendGrid",
        "cname": [r"\.sendgrid\.net$", r"u\d+\.ct\.sendgrid\.net$",
                  r"u\d+\.wl\d+\.sendgrid\.net$"],
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — SendGrid validates domain ownership; check what the CNAME chain resolves to",
    },

    # Mashery (TIBCO) — API management
    {
        "name": "Mashery",
        "cname": [r"\.mashery\.com$", r"\.api\.rackspace\.com$"],
        "body": ["Unrecognized domain", "x-mashery-error-code"],
        "edge_case": True,
        "claim": "Create Mashery API portal and claim the custom domain",
    },

    # Google Sites — not vulnerable but generates FPs
    {
        "name": "Google Sites",
        "cname": [r"\.sites\.google\.com$", r"ghs\.google\.com$", r"ghs\.googlehosted\.com$"],
        "not_vulnerable": True,
        "not_vulnerable_body": ["The requested URL was not found on this server",
                                "That\u2019s all we know"],
        "body": [],
        "claim": "N/A — Google Sites validates domain ownership",
    },

    # Key CDN — not vulnerable
    {
        "name": "KeyCDN",
        "cname": [r"\.kxcdn\.com$", r"\.keycdn\.com$"],
        "not_vulnerable": True,
        "body": [],
        "claim": "N/A — KeyCDN validates zone ownership",
    },

    # Dreamhost — not vulnerable per can-i-take-over-xyz
    {
        "name": "Dreamhost",
        "cname": [r"\.dreamhosters\.com$"],
        "not_vulnerable": True,
        "not_vulnerable_body": ["Site Not Found", "Well, this is awkward"],
        "body": [],
        "claim": "N/A — Dreamhost validates domain ownership",
    },
]

# Headers that indicate infrastructure is alive (not vulnerable)
ALIVE_HEADERS = [
    "x-amz-replication-status",
    "x-amz-version-id",
    "x-amz-server-side-encryption",
]

# ── Cloud IP ranges (compact CIDR table for A-record takeover detection) ───────
# At startup we attempt to fetch live IP ranges from each provider's official API.
# If a fetch fails we silently fall back to the hardcoded CIDRs below.
import ipaddress as _ipaddress

def _fetch_live_cloud_ranges(timeout=6):
    """Fetch IP ranges from provider APIs. Returns dict {provider: [ip_network, ...]}.
    Any failed provider falls back to hardcoded ranges (merged later).
    Providers: Cloudflare, AWS, GCP, Fastly.

    NOTE: Azure is intentionally NOT fetched live here. Azure's own
    ServiceTags_Public JSON is ~4.5MB and slow to download/parse, and it isn't
    actually needed: Azure subdomain takeover is detected via the CNAME +
    HTTP-body fingerprint path (see SERVICES / "Microsoft Azure"), which never
    looks at IP ranges at all. The only thing cloud IP ranges feed is the
    lowest-confidence POSSIBLE_A fallback (an A record with no visible CNAME
    landing in known cloud IP space) — the built-in representative Azure CIDR
    blocks below are more than sufficient for that heuristic. If you need
    exhaustive Azure ranges for some other reason, fetch
    https://www.microsoft.com/en-us/download/details.aspx?id=56519 manually
    and merge it into ips.json yourself."""
    import urllib.request as _req
    result = {}

    # ── Cloudflare ──────────────────────────────────────────────────────────
    try:
        with _req.urlopen("https://www.cloudflare.com/ips-v4", timeout=timeout) as r:
            cidrs = [l.strip() for l in r.read().decode().splitlines() if l.strip()]
        result["Cloudflare"] = [_ipaddress.ip_network(c, strict=False) for c in cidrs if "/" in c]
        dbg("live IPs", note=f"Cloudflare: {len(result['Cloudflare'])} CIDRs")
    except Exception as e:
        dbg("live IPs", note=f"Cloudflare fetch failed: {e}")

    # ── AWS ─────────────────────────────────────────────────────────────────
    try:
        with _req.urlopen("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=timeout) as r:
            data = json.loads(r.read())
        nets = []
        for prefix in data.get("prefixes", []):
            try:
                nets.append(_ipaddress.ip_network(prefix["ip_prefix"], strict=False))
            except Exception:
                pass
        result["AWS"] = nets
        dbg("live IPs", note=f"AWS: {len(nets)} CIDRs")
    except Exception as e:
        dbg("live IPs", note=f"AWS fetch failed: {e}")

    # ── GCP ─────────────────────────────────────────────────────────────────
    try:
        with _req.urlopen("https://www.gstatic.com/ipranges/cloud.json", timeout=timeout) as r:
            data = json.loads(r.read())
        nets = []
        for entry in data.get("prefixes", []):
            cidr = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
            if cidr:
                try:
                    nets.append(_ipaddress.ip_network(cidr, strict=False))
                except Exception:
                    pass
        result["GCP"] = nets
        dbg("live IPs", note=f"GCP: {len(nets)} CIDRs")
    except Exception as e:
        dbg("live IPs", note=f"GCP fetch failed: {e}")

    # ── Fastly ──────────────────────────────────────────────────────────────
    try:
        with _req.urlopen("https://api.fastly.com/public-ip-list", timeout=timeout) as r:
            data = json.loads(r.read())
        nets = []
        for cidr in data.get("addresses", []) + data.get("ipv6_addresses", []):
            try:
                nets.append(_ipaddress.ip_network(cidr, strict=False))
            except Exception:
                pass
        result["Fastly"] = nets
        dbg("live IPs", note=f"Fastly: {len(nets)} CIDRs")
    except Exception as e:
        dbg("live IPs", note=f"Fastly fetch failed: {e}")

    # Azure deliberately omitted — see docstring above. Built-in representative
    # CIDR blocks (CLOUD_IP_RANGES["Azure"]) are used unconditionally instead.

    return result

def _cidrs(*blocks):
    return [_ipaddress.ip_network(b, strict=False) for b in blocks]

CLOUD_IP_RANGES = {
    # Cloudflare anycast ranges (https://www.cloudflare.com/ips-v4)
    # Orange-cloud domains resolve to these — CNAME is hidden, need HTTP fingerprint.
    "Cloudflare": _cidrs(
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14",
        "108.162.192.0/18", "131.0.72.0/22",
        "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20",
        "188.114.96.0/20", "190.93.240.0/20",
        "197.234.240.0/22", "198.41.128.0/17",
    ),
    # Fastly CDN ranges (https://api.fastly.com/public-ip-list)
    "Fastly": _cidrs(
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16",
    ),
    # Akamai (representative blocks — full list is huge)
    "Akamai": _cidrs(
        "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13",
        "72.246.0.0/15", "96.6.0.0/15", "104.64.0.0/10",
        "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14",
    ),
    "AWS": _cidrs(
        "3.0.0.0/8", "13.32.0.0/15", "13.224.0.0/14", "13.249.0.0/19",
        "18.140.0.0/14", "18.168.0.0/14", "18.184.0.0/14", "18.196.0.0/15",
        "18.224.0.0/14", "34.192.0.0/10", "34.224.0.0/11", "35.71.0.0/17",
        "44.192.0.0/11", "44.224.0.0/11", "52.0.0.0/11", "52.32.0.0/11",
        "52.64.0.0/12", "52.80.0.0/12", "52.92.0.0/12", "52.94.0.0/15",
        "54.64.0.0/11", "54.144.0.0/12", "54.160.0.0/11", "54.192.0.0/12",
        "54.208.0.0/13", "54.216.0.0/14", "54.220.0.0/14", "54.224.0.0/11",
        "99.28.0.0/14", "99.83.128.0/17", "107.20.0.0/14", "176.34.0.0/16",
    ),
    "Azure": _cidrs(
        "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.0.0.0/8",
        "23.96.0.0/13", "40.64.0.0/10", "51.0.0.0/9", "52.96.0.0/12",
        "52.112.0.0/14", "52.120.0.0/14", "52.224.0.0/11", "65.52.0.0/14",
        "70.37.0.0/18", "104.40.0.0/13", "104.208.0.0/13", "137.116.0.0/15",
        "157.56.0.0/14", "168.61.0.0/16", "168.62.0.0/15", "191.232.0.0/13",
    ),
    "GCP": _cidrs(
        "8.8.4.0/24", "8.8.8.0/24", "8.34.208.0/20", "8.35.192.0/20",
        "23.236.48.0/20", "23.251.128.0/19", "34.0.0.0/9", "34.128.0.0/10",
        "35.184.0.0/13", "35.192.0.0/11", "35.224.0.0/12", "35.240.0.0/13",
        "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18",
        "74.125.0.0/16", "104.154.0.0/15", "104.196.0.0/14", "107.167.160.0/19",
        "108.170.192.0/18", "108.177.0.0/17", "130.211.0.0/16", "142.250.0.0/15",
        "146.148.0.0/17", "162.216.148.0/22", "172.110.32.0/21", "173.194.0.0/16",
        "209.85.128.0/17", "216.239.32.0/19",
    ),
}

_LIVE_CLOUD_RANGES = None   # populated at startup by _init_cloud_ranges()
_CLOUD_RANGES_SOURCE = "built-in"

def _load_ips_cache():
    """Load cached cloud IP ranges from ips.json.
    Returns (dict{provider: [ip_network,...]}, fetched_at_str) or (None, None)."""
    try:
        with open(IPS_CACHE_FILE) as f:
            data = json.load(f)
        ranges = {}
        for provider, cidrs in data.get("ranges", {}).items():
            nets = []
            for c in cidrs:
                try:
                    nets.append(_ipaddress.ip_network(c, strict=False))
                except Exception:
                    pass
            if nets:
                ranges[provider] = nets
        return ranges, data.get("fetched_at")
    except Exception as e:
        dbg("ips cache", note=f"load failed or absent: {e}")
        return None, None

def _save_ips_cache(ranges):
    """Persist cloud IP ranges (dict of provider -> [ip_network,...]) to ips.json."""
    if not _ensure_config_dir():
        return False
    try:
        payload = {
            "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "ranges": {p: [str(n) for n in nets] for p, nets in ranges.items()},
        }
        with open(IPS_CACHE_FILE, "w") as f:
            json.dump(payload, f, indent=2)
        return True
    except Exception as e:
        dbg("ips cache", note=f"save failed: {e}")
        return False

def _init_cloud_ranges(no_online=False, update_list=False):
    """Populate cloud IP ranges from local cache (default), a forced live
    fetch (--update-list), or built-ins only (--no-online). Normal runs no
    longer hit the network — they just read ~/.config/subtake/ips.json."""
    global _LIVE_CLOUD_RANGES, _CLOUD_RANGES_SOURCE

    if update_list:
        live = _fetch_live_cloud_ranges()
        if live:
            merged = dict(CLOUD_IP_RANGES)
            merged.update({p: n for p, n in live.items() if n})
            _LIVE_CLOUD_RANGES = merged
            saved = _save_ips_cache(merged)
            _CLOUD_RANGES_SOURCE = f"updated ({', '.join(sorted(live.keys()))})"
            return saved
        else:
            cached, fetched_at = _load_ips_cache()
            if cached:
                merged = dict(CLOUD_IP_RANGES)
                merged.update(cached)
                _LIVE_CLOUD_RANGES = merged
                _CLOUD_RANGES_SOURCE = f"update failed — kept existing cache ({fetched_at})"
            else:
                _LIVE_CLOUD_RANGES = CLOUD_IP_RANGES
                _CLOUD_RANGES_SOURCE = "update failed, no cache — built-in only"
        return False  # nothing new was written to ips.json this run

    if no_online:
        _LIVE_CLOUD_RANGES = CLOUD_IP_RANGES
        _CLOUD_RANGES_SOURCE = "built-in (--no-online)"
        return False

    cached, fetched_at = _load_ips_cache()
    if cached:
        merged = dict(CLOUD_IP_RANGES)
        merged.update(cached)
        _LIVE_CLOUD_RANGES = merged
        _CLOUD_RANGES_SOURCE = f"cached ({fetched_at})"
    else:
        _LIVE_CLOUD_RANGES = CLOUD_IP_RANGES
        _CLOUD_RANGES_SOURCE = "built-in (no cache — run --update-list to fetch)"
    return False

def _ip_to_cloud(ip_str):
    """Return cloud provider name if ip_str falls in a known cloud range, else None."""
    try:
        addr = _ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    ranges = _LIVE_CLOUD_RANGES if _LIVE_CLOUD_RANGES is not None else CLOUD_IP_RANGES
    for provider, nets in ranges.items():
        for net in nets:
            if addr in net:
                return provider
    return None

# ── DNS helpers ────────────────────────────────────────────────────────────────
def _dig_available():
    try:
        subprocess.run(["dig", "-v"], capture_output=True, timeout=3)
        return True
    except (FileNotFoundError, PermissionError, OSError):
        return False

DIG_AVAILABLE = _dig_available()

def dig_cname(domain):
    """Return CNAME target (str) or None. Uses dig if available, else 'host'."""
    if DIG_AVAILABLE:
        cmd = ["dig", "+short", "CNAME", domain]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            # Take only the first non-empty line (CNAME returns one target)
            lines = [l.strip() for l in r.stdout.splitlines()
                     if l.strip() and not l.strip().startswith(";")]
            result = lines[0].rstrip(".") if lines else None
            dbg(f"dig CNAME {domain}", cmd=cmd, stdout=r.stdout, stderr=r.stderr,
                note=f"→ {result or 'no CNAME'}")
            return result
        except Exception as e:
            dbg(f"dig CNAME {domain} FAILED", cmd=cmd, note=str(e))
            return None
    else:
        # Fallback: 'host' command
        cmd = ["host", "-t", "CNAME", domain]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            m = re.search(r"is an alias for (.+)\.", r.stdout)
            result = m.group(1).rstrip(".") if m else None
            dbg(f"host CNAME {domain}", cmd=cmd, stdout=r.stdout, note=f"→ {result or 'no CNAME'}")
            return result
        except Exception as e:
            dbg(f"host CNAME {domain} FAILED", cmd=cmd, note=str(e))
            return None

def dig_resolve(fqdn):
    """Return True if fqdn resolves to an A/AAAA address, False otherwise.
    Uses dig if available, else socket.getaddrinfo fallback.
    Critically: checks that output contains an actual IP, not just a CNAME label,
    to avoid false-positives on dangling CNAME chains."""
    if DIG_AVAILABLE:
        cmd = ["dig", "+short", fqdn]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            # dig +short emits CNAME labels (dotted names) before the final A record.
            # We need at least one line that looks like an IP address.
            lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            resolves = any(
                re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", l) or
                re.match(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$", l)   # IPv6
                for l in lines
            )
            dbg(f"dig resolve {fqdn}", cmd=cmd, stdout=r.stdout, stderr=r.stderr,
                note="RESOLVES" if resolves else "NXDOMAIN/DANGLING")
            return resolves
        except Exception as e:
            dbg(f"dig resolve {fqdn} FAILED", cmd=cmd, note=str(e))
            return False
    else:
        # Fallback: socket
        try:
            socket.getaddrinfo(fqdn, None)
            dbg(f"socket resolve {fqdn}", note="RESOLVES")
            return True
        except socket.gaierror:
            dbg(f"socket resolve {fqdn}", note="NXDOMAIN")
            return False

def dig_a(domain):
    """Return list of IPv4/IPv6 addresses for domain, or []."""
    cmd = ["dig", "+short", "A", domain] if DIG_AVAILABLE else None
    if not DIG_AVAILABLE:
        try:
            infos = socket.getaddrinfo(domain, None)
            ips = list({i[4][0] for i in infos})
            dbg(f"socket A {domain}", note=f"→ {ips}")
            return ips
        except Exception:
            return []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ips = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        # filter out CNAME lines (contain dots but no valid IP format) — keep only IPs
        ips = [ip for ip in ips if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
               or re.match(r"^[0-9a-fA-F:]+$", ip)]
        dbg(f"dig A {domain}", cmd=cmd, stdout=r.stdout, note=f"→ {ips}")
        return ips
    except Exception as e:
        dbg(f"dig A {domain} FAILED", cmd=cmd, note=str(e))
        return []

def dig_ns(domain):
    """Return list of NS nameserver FQDNs for domain, or []."""
    if not DIG_AVAILABLE:
        return []
    cmd = ["dig", "+short", "NS", domain]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ns_list = [
            l.strip().rstrip(".")
            for l in r.stdout.strip().splitlines()
            if l.strip() and not l.strip().startswith(";")
        ]
        dbg(f"dig NS {domain}", cmd=cmd, stdout=r.stdout, note=f"→ {ns_list}")
        return ns_list
    except Exception as e:
        dbg(f"dig NS {domain} FAILED", cmd=cmd, note=str(e))
        return []

_MX_WARN_SHOWN = False

def dig_mx(domain):
    """Return list of MX host FQDNs for domain, or []."""
    global _MX_WARN_SHOWN
    if not DIG_AVAILABLE:
        if not _MX_WARN_SHOWN:
            print(f"  {Y}[!] dig not available — MX takeover detection disabled (install dnsutils){RST}",
                  file=sys.stderr)
            _MX_WARN_SHOWN = True
        return []
    cmd = ["dig", "+short", "MX", domain]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        mx_hosts = []
        for line in r.stdout.strip().splitlines():
            parts = line.strip().split()
            if len(parts) == 2:
                mx_hosts.append(parts[1].rstrip("."))
        dbg(f"dig MX {domain}", cmd=cmd, stdout=r.stdout, note=f"→ {mx_hosts}")
        return mx_hosts
    except Exception as e:
        dbg(f"dig MX {domain} FAILED", cmd=cmd, note=str(e))
        return []


def dig_txt(domain):
    """Return list of TXT record strings for domain, or []."""
    if not DIG_AVAILABLE:
        return []
    cmd = ["dig", "+short", "TXT", domain]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        records = []
        for line in r.stdout.strip().splitlines():
            line = line.strip().strip('"')
            if line:
                records.append(line)
        dbg(f"dig TXT {domain}", cmd=cmd, stdout=r.stdout, note=f"-> {len(records)} record(s)")
        return records
    except Exception as e:
        dbg(f"dig TXT {domain} FAILED", cmd=cmd, note=str(e))
        return []

def parse_spf_includes(txt_records):
    """Extract include: and redirect= domains from SPF TXT records.
    Both are takeover vectors if the referenced domain is expired/unregistered."""
    domains = []
    for rec in txt_records:
        if not rec.lower().startswith("v=spf1"):
            continue
        for token in rec.split():
            tl = token.lower()
            if tl.startswith("include:"):
                d = token[len("include:"):].strip().rstrip(".")
                if d and "." in d:
                    domains.append(d)
            elif tl.startswith("redirect="):
                d = token[len("redirect="):].strip().rstrip(".")
                if d and "." in d:
                    domains.append(d)
    seen = set()
    out = []
    for d in domains:
        if d.lower() not in seen:
            seen.add(d.lower())
            out.append(d)
    return out

def dig_ns_query(nameserver, zone):
    """Query nameserver directly for zone. Returns rcode string (NOERROR/SERVFAIL/REFUSED/NXDOMAIN)."""
    if not DIG_AVAILABLE:
        return "UNKNOWN"
    cmd = ["dig", f"@{nameserver}", zone, "SOA", "+time=3", "+tries=1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        m = re.search(r"status:\s+(\w+)", r.stdout)
        rcode = m.group(1).upper() if m else "UNKNOWN"
        dbg(f"dig @{nameserver} {zone} SOA", cmd=cmd, stdout=r.stdout, note=f"→ {rcode}")
        return rcode
    except Exception as e:
        dbg(f"dig @{nameserver} {zone} SOA FAILED", cmd=cmd, note=str(e))
        return "UNKNOWN"

def _dig_short(fqdn):
    """Return all lines from 'dig +short <fqdn>' (follows full chain). Returns [] on failure."""
    if not DIG_AVAILABLE:
        return []
    cmd = ["dig", "+short", fqdn]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return [l.strip().rstrip(".") for l in r.stdout.splitlines()
                if l.strip() and not l.strip().startswith(";")]
    except Exception:
        return []

def walk_cname_chain(domain, max_hops=10):
    """Walk the full CNAME chain from domain using dig +short (follows all hops).
    Returns list of (src, tgt, resolves) tuples for each CNAME hop found.
    A hop is 'dead' if tgt does not have an A/AAAA record at the end of the chain."""
    # dig +short on the original domain returns the full chain lines:
    # e.g. ["mid.partner.com", "dead.heroku.com"] then potentially an IP.
    # We reconstruct hop pairs from consecutive CNAME-looking lines.
    lines = _dig_short(domain)
    if not lines:
        return []

    # Separate CNAME labels (dotted hostnames) from IP addresses
    ip_pat = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
    cname_labels = [l for l in lines if not ip_pat.match(l)]
    has_ip = any(ip_pat.match(l) for l in lines)

    if not cname_labels:
        # No CNAME hops — just A records or empty
        return []

    # Build hop pairs: domain→cname_labels[0], cname_labels[0]→cname_labels[1], ...
    all_nodes = [domain] + cname_labels
    chain = []
    for i in range(len(all_nodes) - 1):
        src = all_nodes[i]
        tgt = all_nodes[i + 1]
        # The last hop resolves only if the full chain ends in an IP
        is_last = (i == len(all_nodes) - 2)
        resolves = has_ip if is_last else True
        chain.append((src, tgt, resolves))

    dbg(f"CNAME chain for {domain}", note=str(chain))
    return chain

def detect_wildcard(domain):
    """Return True if the parent domain has a wildcard DNS record.
    Technique: resolve a random nonsense subdomain of the same parent.
    Uses the subdomain's immediate parent (one label up), not a naive last-2-labels
    split, to avoid probing TLD zones like co.uk instead of foo.co.uk."""
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
    parts = domain.rstrip(".").split(".")
    # Parent = everything except the leftmost label (sub.foo.co.uk → foo.co.uk)
    # This is more correct than [-2:] which would give co.uk for a 4-label domain.
    if len(parts) < 2:
        parent = domain
    else:
        parent = ".".join(parts[1:])
    probe = f"{rand}.{parent}"
    resolves = dig_resolve(probe)
    dbg(f"wildcard probe {probe}", note="WILDCARD ACTIVE" if resolves else "no wildcard")
    return resolves

# ── HTTP helper ────────────────────────────────────────────────────────────────
def curl_fetch(domain, force_http=False, no_follow=False):
    """Return (status_code, headers_str, body_str) via curl.

    Tries HTTPS first. If force_http=True or HTTPS fails with a connection
    error (exit code 35 / 60 / 7), retries over plain HTTP.

    Status code is extracted from the *last* HTTP response block so that
    curl -L redirect chains don't leave us with a 301 instead of the final code.

    no_follow=True: skip --location so we see the raw response of the target
    domain (important for CDN-proxied fingerprinting where a redirect would
    take us to a completely different page).
    """
    def _run(url):
        cmd = ["curl", "-si", "--max-time", "10",
               "-A", "Mozilla/5.0 (subtake.py)", url]
        if not no_follow:
            cmd.insert(3, "--location")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            raw = r.stdout

            # ── Split on *last* blank line between headers and body ──────────
            # curl -L dumps all intermediate response headers before the final
            # body. We want the FINAL status, not the first redirect code.
            # Strategy: split on every \r\n\r\n (or \n\n), take the last
            # header block that starts with HTTP/.
            sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
            blocks = raw.split(sep)

            headers_raw = ""
            body = ""
            for i, block in enumerate(blocks):
                if re.match(r"HTTP/[\d.]+", block.strip()):
                    headers_raw = block
                    body = sep.join(blocks[i+1:])
                # Keep iterating — last HTTP/ block wins

            # Extract status from the chosen header block
            status = 0
            m = re.search(r"HTTP/[\d.]+ (\d+)", headers_raw)
            if m:
                status = int(m.group(1))

            dbg(f"curl {url}", cmd=cmd,
                note=f"status={status} | headers={len(headers_raw)}b | body={len(body)}b")
            if DEBUG:
                print(f"  {DIM}  headers:\n{headers_raw[:800]}{RST}", file=sys.stderr)
                if body.strip():
                    print(f"  {DIM}  body (first 500):\n{body[:500]}{RST}", file=sys.stderr)

            return status, headers_raw.lower(), body, r.returncode
        except Exception as e:
            dbg(f"curl {url} FAILED", cmd=cmd, note=str(e))
            return 0, "", "", -1

    scheme = "http" if force_http else "https"
    status, headers, body, rc = _run(f"{scheme}://{domain}")

    # If HTTPS failed at the TLS/connection level, retry over HTTP
    # curl exit codes: 35=SSL handshake, 60=cert verify, 7=connection refused
    if not force_http and rc in (7, 35, 60) and status == 0:
        dbg(f"HTTPS failed (rc={rc}), retrying HTTP", note=domain)
        status, headers, body, _ = _run(f"http://{domain}")

    return status, headers, body

# ── Service matcher ────────────────────────────────────────────────────────────
def match_service(cname):
    """Match CNAME to a known service definition."""
    if not cname:
        return None
    for svc in SERVICES:
        for pattern in svc["cname"]:
            if re.search(pattern, cname, re.IGNORECASE):
                return svc
    return None

_MD_LINK_RE = re.compile(r'^\[(?P<label>[^\]]+)\]\((?P<url>https?://[^\)]+)\)$')

def _clean_ref(text):
    """can-i-take-over-xyz ships discussion/documentation as raw markdown, e.g.
    '[Issue #152](https://github.com/.../152)'. That renders as ugly literal
    brackets in a terminal. Convert to 'Label — url'; leave plain text/bare
    URLs untouched."""
    if not text:
        return text
    m = _MD_LINK_RE.match(text.strip())
    if m:
        return f"{m.group('label')} — {m.group('url')}"
    return text.strip()

def _apply_svc_description(result, svc):
    """Populate result['description'] with reference info for the matched service.

    Prefers discussion/documentation links backfilled from can-i-take-over-xyz
    (via --update-list). If none are cached for this service, falls back to a
    generic-but-useful pointer instead of leaving the field empty — a real
    finding should never come back with description: null just because we
    haven't fetched metadata for that particular service yet.
    """
    if not svc:
        return
    parts = []
    disc = _clean_ref(svc.get("discussion", ""))
    docs = _clean_ref(svc.get("documentation", ""))
    if disc:
        parts.append(f"Discussion: {disc}")
    if docs:
        parts.append(f"Docs: {docs}")
    if not parts:
        parts.append(
            f"No cached discussion/documentation for '{svc['name']}'. "
            f"Run with --update-list to fetch reference links, or check "
            f"https://github.com/EdOverflow/can-i-take-over-xyz for this fingerprint."
        )
    result["description"] = "  |  ".join(parts)

def check_body_fingerprint(svc, body, headers):
    """Return True if body/headers match known vulnerable fingerprints."""
    # First: bail out if NOT-vulnerable signals are present
    not_vuln = svc.get("not_vulnerable_body", [])
    for sig in not_vuln:
        if sig.lower() in body.lower() or sig.lower() in headers.lower():
            dbg("fingerprint", note=f"NOT-VULN signal hit: '{sig}'")
            return False
    # Bail out if alive headers are present
    for h in ALIVE_HEADERS:
        if h in headers:
            dbg("fingerprint", note=f"alive header hit: '{h}'")
            return False
    # Check vulnerable fingerprints
    for fp in svc.get("body", []):
        if fp.lower() in body.lower():
            dbg("fingerprint", note=f"VULN fingerprint hit: '{fp}'")
            return True
    dbg("fingerprint", note="no fingerprint matched")
    return False

# ── Core check ─────────────────────────────────────────────────────────────────
_INTERESTING_VERDICTS = ("VULNERABLE", "VULNERABLE_NS", "POSSIBLE",
                          "POSSIBLE_MX", "POSSIBLE_SPF", "POSSIBLE_A")

def check_subdomain(domain, force_http=False):
    """Thin wrapper around _check_subdomain_impl that guarantees 'description'
    is never left null on a result the user actually needs to act on (VULNERABLE/
    POSSIBLE/*). Findings that don't map to a known SERVICES entry - e.g. dangling
    NS delegation, dead MX, dead SPF include, unknown dead-hop service - never went
    through _apply_svc_description at all, so they previously reported description:
    null even though they ARE a real finding worth a note."""
    result = _check_subdomain_impl(domain, force_http=force_http)
    if result and result.get("verdict") in _INTERESTING_VERDICTS and not result.get("description"):
        result["description"] = (
            "This finding type (DNS delegation/records, not a third-party SaaS "
            "fingerprint) has no can-i-take-over-xyz reference - see the 'reason' "
            "and 'claim' fields above for exploitation details."
        )
    return result

def _check_subdomain_impl(domain, force_http=False):
    domain = domain.strip().lower()
    if not domain:
        return None

    result = {
        "domain": domain,
        "cname": None,
        "cname_resolves": None,
        "cname_chain": None,
        "ns_records": None,
        "mx_records": None,
        "spf_includes": None,
        "a_ips": None,
        "cloud_provider": None,
        "service": None,
        "status_code": None,
        "verdict": None,      # VULNERABLE / VULNERABLE_NS / POSSIBLE / POSSIBLE_MX / POSSIBLE_SPF / POSSIBLE_A
                              # NOT_VULNERABLE / NO_DNS / WILDCARD_SKIP / ERROR
        "confidence": None,   # HIGH / MEDIUM / LOW
        "reason": None,
        "claim": None,
        "description": None,   # discussion/documentation link from can-i-take-over-xyz
    }

    # Step 1: CNAME
    cname = dig_cname(domain)
    result["cname"] = cname

    if not cname:
        # ── Step 0: Wildcard detection ────────────────────────────────────────
        if detect_wildcard(domain):
            result["verdict"] = "WILDCARD_SKIP"
            result["reason"] = "Parent domain has wildcard DNS — results unreliable, skipping"
            return result

        # ── Step 1a: Walk full CNAME chain (multi-hop) ───────────────────────
        chain = walk_cname_chain(domain)
        if chain:
            result["cname_chain"] = chain
            # Check if any hop in the chain is dead
            dead_hops = [(src, tgt) for src, tgt, res in chain if not res]
            if dead_hops:
                dead_src, dead_tgt = dead_hops[0]
                result["verdict"] = "VULNERABLE"
                result["confidence"] = "HIGH"
                result["reason"] = (
                    f"CNAME chain has dead hop: '{dead_src}' → '{dead_tgt}' returns NXDOMAIN"
                )
                # Try to identify service from dead target first, then walk all hops
                svc = match_service(dead_tgt)
                if not svc:
                    # Dead target unknown — try each hop in the chain for service hints
                    for hop_src, hop_tgt, _ in chain:
                        svc = match_service(hop_src) or match_service(hop_tgt)
                        if svc:
                            break
                if svc:
                    result["service"] = svc["name"]
                    result["claim"] = svc["claim"]
                    _apply_svc_description(result, svc)
                else:
                    result["service"] = "Unknown"
                    result["claim"] = "Identify service at dead hop and register the slug"
                return result

        # ── Step 1b: NS record check ─────────────────────────────────────────
        ns_records = dig_ns(domain)
        if ns_records:
            result["ns_records"] = ns_records
            dead_ns = []
            for ns in ns_records:
                ns_resolves = dig_resolve(ns)
                if not ns_resolves:
                    dead_ns.append(ns)
                    continue
                # Query the NS directly for the zone
                rcode = dig_ns_query(ns, domain)
                if rcode in ("SERVFAIL", "REFUSED", "NXDOMAIN"):
                    dead_ns.append(ns)
            if dead_ns:
                result["verdict"] = "VULNERABLE_NS"
                result["confidence"] = "HIGH"
                result["service"] = "NS delegation"
                result["reason"] = (
                    f"Dangling NS delegation — nameserver(s) {dead_ns} "
                    f"do not exist or return error for zone '{domain}'"
                )
                result["claim"] = "Register the dead nameserver domain and host the zone"
                return result

        # ── Step 1c: MX record check ─────────────────────────────────────────
        mx_records = dig_mx(domain)
        if mx_records:
            result["mx_records"] = mx_records
            dead_mx = [mx for mx in mx_records if not dig_resolve(mx)]
            if dead_mx:
                result["verdict"] = "POSSIBLE_MX"
                result["confidence"] = "MEDIUM"
                result["service"] = "MX / email"
                result["reason"] = (
                    f"Dangling MX record(s) {dead_mx} — "
                    f"mail host(s) do not resolve (SubdoMailing / email takeover risk)"
                )
                result["claim"] = "Register the dead MX domain and accept mail for this address"
                return result


        # ── Step 1d: SPF include/redirect check ──────────────────────────────
        # Only run when dig is available; socket fallback can't do TXT lookups.
        # We check TXT records on the root domain (no CNAME) for SPF include:
        # and redirect= mechanisms that point to dead/unregistered domains.
        # Impact: registering a dead include domain lets an attacker send mail
        # that passes SPF on behalf of the target (SubdoMailing / email spoofing).
        if DIG_AVAILABLE:
            txt_records = dig_txt(domain)
            spf_domains = parse_spf_includes(txt_records)
            if spf_domains:
                dead_spf = []
                spf_details = []
                for inc_domain in spf_domains:
                    is_dead = not dig_resolve(inc_domain)
                    spf_details.append({"domain": inc_domain, "dead": is_dead})
                    if is_dead:
                        dead_spf.append(inc_domain)
                result["spf_includes"] = spf_details
                if dead_spf:
                    result["verdict"] = "POSSIBLE_SPF"
                    result["confidence"] = "MEDIUM"
                    result["service"] = "SPF / email"
                    result["reason"] = (
                        f"SPF record references dead domain(s) {dead_spf} — "
                        f"registering them enables sending mail that passes SPF as {domain} "
                        f"(email spoofing / SubdoMailing risk)"
                    )
                    result["claim"] = (
                        f"Register the dead SPF include domain(s): {dead_spf}. "
                        f"Then publish a permissive SPF record (+all) to pass SPF checks as {domain}."
                    )
                    return result

        # ── Step 1e: A record → cloud/CDN IP fingerprint ────────────────────
        a_ips = dig_a(domain)
        if a_ips:
            result["a_ips"] = a_ips
            cloud_ips = [(ip, _ip_to_cloud(ip)) for ip in a_ips if _ip_to_cloud(ip)]
            if cloud_ips:
                first_ip, first_provider = cloud_ips[0]
                result["cloud_provider"] = first_provider

                # Cloudflare orange-cloud note: when a domain is Cloudflare-proxied,
                # dig CNAME returns empty (hidden behind anycast A records).
                # The CNAME still exists at origin but is invisible to public DNS.
                # We MUST do an HTTP fingerprint check here — DNS-only recon is blind.
                is_cdn_proxy = first_provider in ("Cloudflare", "Fastly", "Akamai")

                # Fetch HTTP without following redirects so we see the actual
                # unclaimed-service error page, not a redirect destination.
                status, headers, body = curl_fetch(domain, force_http=force_http,
                                                   no_follow=is_cdn_proxy)
                result["status_code"] = status

                # Check all services for a fingerprint match
                matched_svc = None
                for svc in SERVICES:
                    if svc.get("not_vulnerable"):
                        continue
                    if check_body_fingerprint(svc, body, headers):
                        matched_svc = svc
                        break

                if matched_svc:
                    if is_cdn_proxy:
                        result["verdict"] = "POSSIBLE"
                        result["confidence"] = "MEDIUM"
                        result["service"] = matched_svc["name"]
                        result["reason"] = (
                            f"A records resolve to {first_provider} proxy ({first_ip}) — "
                            f"origin CNAME hidden (orange-cloud). HTTP response matches "
                            f"'{matched_svc['name']}' unclaimed-service fingerprint. "
                            f"Verify manually: the backend slot may be claimable."
                        )
                    else:
                        result["verdict"] = "POSSIBLE_A"
                        result["confidence"] = "LOW"
                        result["service"] = matched_svc["name"]
                        result["reason"] = (
                            f"A record {first_ip} is in {first_provider} IP space and HTTP "
                            f"response matches '{matched_svc['name']}' takeover fingerprint "
                            f"(IP recycling — low confidence, manual verify required)"
                        )
                    result["claim"] = matched_svc["claim"]
                    _apply_svc_description(result, matched_svc)
                    return result

                if is_cdn_proxy:
                    # CDN proxy, no fingerprint match — flag as proxied, not safe-clean
                    result["verdict"] = "NOT_VULNERABLE"
                    result["reason"] = (
                        f"A records resolve to {first_provider} proxy ({first_ip}) — "
                        f"origin CNAME hidden. No unclaimed-service fingerprint matched "
                        f"in HTTP response. Appears live/claimed."
                    )
                else:
                    result["verdict"] = "NOT_VULNERABLE"
                    result["reason"] = (
                        f"A record {first_ip} is in {first_provider} IP space but no takeover "
                        f"fingerprint matched in HTTP response"
                    )
                return result

            # Has A records but no cloud IP → completely live non-cloud host
            result["verdict"] = "NOT_VULNERABLE"
            result["reason"] = "Domain resolves via A record to non-cloud IP — not vulnerable"
            return result

        # ── No DNS at all ─────────────────────────────────────────────────────
        result["verdict"] = "NO_DNS"
        result["reason"] = "Domain has no CNAME, NS, MX, or A/AAAA records — completely dead"
        return result

    # Step 2: Does CNAME target resolve?
    resolves = dig_resolve(cname)
    result["cname_resolves"] = resolves

    svc = match_service(cname)
    result["service"] = svc["name"] if svc else "Unknown"

    # Known-not-vulnerable service: short-circuit
    if svc and svc.get("not_vulnerable"):
        result["verdict"] = "NOT_VULNERABLE"
        result["reason"] = f"{svc['name']} validates domain ownership — not vulnerable"
        return result

    if not resolves:
        result["verdict"] = "VULNERABLE"
        result["confidence"] = "HIGH"
        result["reason"] = f"CNAME target '{cname}' returns NXDOMAIN — slot is unclaimed"
        result["claim"] = svc["claim"] if svc else "Identify service and register the slug"
        _apply_svc_description(result, svc)
        return result

    # NXDOMAIN-only services that resolved (i.e. the slot IS claimed) → not vulnerable.
    #
    # BUG FIX: this used to short-circuit unconditionally whenever nxdomain_only
    # was set, which made any 'body' fingerprints on that service unreachable
    # dead code. Azure is the concrete case: its shared frontend IP resolves
    # for ANY *.azurewebsites.net-style hostname whether claimed or not — DNS
    # always resolves, so nxdomain_only-style logic alone produces a false
    # NOT_VULNERABLE. The real signal for Azure is the HTTP body ("404 Web Site
    # not found" / "This web app has been stopped"), which is exactly the body
    # list already defined on that SERVICES entry but was never being checked.
    # Fix: only take the NXDOMAIN-only shortcut when there's no body fingerprint
    # to fall back on; otherwise continue to Step 3 (HTTP fetch) below.
    if svc and svc.get("nxdomain_only") and not svc.get("body"):
        result["verdict"] = "NOT_VULNERABLE"
        result["reason"] = f"CNAME resolves — {svc['name']} slot appears to be claimed"
        return result

    # Step 3: HTTP response
    status, headers, body = curl_fetch(domain, force_http=force_http)
    result["status_code"] = status

    if not svc:
        result["verdict"] = "NOT_VULNERABLE"
        result["reason"] = f"CNAME resolves, unknown service '{cname}', no fingerprint to match"
        return result

    fp_match = check_body_fingerprint(svc, body, headers)

    if fp_match:
        if svc.get("edge_case"):
            result["verdict"] = "POSSIBLE"
            result["confidence"] = "MEDIUM"
            result["reason"] = (f"CNAME resolves but {svc['name']} error fingerprint matched — "
                                f"edge case, verify manually")
        else:
            result["verdict"] = "POSSIBLE"
            result["confidence"] = "MEDIUM"
            result["reason"] = f"CNAME resolves but {svc['name']} error fingerprint matched in response"
        result["claim"] = svc["claim"]
        _apply_svc_description(result, svc)
    else:
        result["verdict"] = "NOT_VULNERABLE"
        result["reason"] = f"CNAME resolves to live {svc['name']} infrastructure — no takeover fingerprint found"

    return result

# ── Output formatting ──────────────────────────────────────────────────────────
VERDICT_COLOR = {
    "VULNERABLE":     R + BOLD,
    "VULNERABLE_NS":  R + BOLD,
    "POSSIBLE":       Y + BOLD,
    "POSSIBLE_MX":    Y + BOLD,
    "POSSIBLE_SPF":   Y + BOLD,
    "POSSIBLE_A":     Y,
    "NOT_VULNERABLE": G,
    "NO_CNAME":       DIM,
    "NO_DNS":         DIM,
    "WILDCARD_SKIP":  B,
    "ERROR":          M,
}

VERDICT_ICON = {
    "VULNERABLE":     "🔴 VULNERABLE",
    "VULNERABLE_NS":  "🔴 VULNERABLE (NS TAKEOVER)",
    "POSSIBLE":       "🟡 POSSIBLE",
    "POSSIBLE_MX":    "🟡 POSSIBLE (MX TAKEOVER)",
    "POSSIBLE_SPF":   "🟡 POSSIBLE (SPF TAKEOVER)",
    "POSSIBLE_A":     "🟡 POSSIBLE (A RECORD)",
    "NOT_VULNERABLE": "🟢 NOT VULNERABLE",
    "NO_CNAME":       "⚪ NO CNAME",
    "NO_DNS":         "⚫ NO DNS (dead)",
    "WILDCARD_SKIP":  "🔵 WILDCARD DNS (skip)",
    "ERROR":          "⚠️  ERROR",
}

def print_result(r):
    if r is None:
        return
    vc   = VERDICT_COLOR.get(r["verdict"], W)
    icon = VERDICT_ICON.get(r["verdict"], r["verdict"])

    print(f"\n{BOLD}{C}{'─'*60}{RST}")
    print(f"  {BOLD}Domain   :{RST} {W}{r['domain']}{RST}")
    print(f"  {BOLD}Verdict  :{RST} {vc}{icon}{RST}", end="")
    if r.get("confidence"):
        print(f"  [{r['confidence']} confidence]", end="")
    print()

    if r.get("cname"):
        resolv_str = f"{G}resolves{RST}" if r["cname_resolves"] else f"{R}NXDOMAIN{RST}"
        print(f"  {BOLD}CNAME    :{RST} {r['cname']} → {resolv_str}")

    if r.get("cname_chain"):
        print(f"  {BOLD}Chain    :{RST}", end="")
        for src, tgt, res in r["cname_chain"]:
            arrow = f"{G}→{RST}" if res else f"{R}→ DEAD{RST}"
            print(f" {DIM}{src}{RST} {arrow} {tgt}", end="")
        print()

    if r.get("ns_records"):
        print(f"  {BOLD}NS       :{RST} {', '.join(r['ns_records'])}")

    if r.get("mx_records"):
        print(f"  {BOLD}MX       :{RST} {', '.join(r['mx_records'])}")
    if r.get("spf_includes"):
        dead = [d for d in r["spf_includes"] if isinstance(d, dict) and d.get("dead")]
        all_inc = [d["domain"] if isinstance(d, dict) else d for d in r["spf_includes"]]
        dead_names = [d["domain"] if isinstance(d, dict) else d for d in dead]
        line = ", ".join(all_inc)
        if dead_names:
            line += f"  {R}(DEAD: {', '.join(dead_names)}){RST}"
        print(f"  {BOLD}SPF incl :{RST} {line}")


    if r.get("a_ips"):
        cloud = r.get("cloud_provider", "")
        cloud_str = f"  {Y}[{cloud}]{RST}" if cloud else ""
        print(f"  {BOLD}A record :{RST} {', '.join(r['a_ips'])}{cloud_str}")

    if r.get("service") and r["service"] != "Unknown":
        print(f"  {BOLD}Service  :{RST} {r['service']}")

    if r.get("status_code") is not None and r["status_code"] != 0:
        print(f"  {BOLD}HTTP     :{RST} {r['status_code']}")

    print(f"  {BOLD}Reason   :{RST} {DIM}{r['reason']}{RST}")

    if r.get("claim") or r.get("description"):
        print(f"  {DIM}{'-'*58}{RST}")
        print(f"  {BOLD}Remediation{RST}")
        if r.get("claim"):
            print(f"    {Y}{BOLD}{'Claim':<10}{RST}: {r['claim']}")
        if r.get("description"):
            for part in r["description"].split("  |  "):
                part = part.strip()
                label, sep, rest = part.partition(":")
                if sep:
                    print(f"    {C}{BOLD}{label.strip():<10}{RST}: {rest.strip()}")
                else:
                    print(f"    {DIM}{part}{RST}")

def print_summary(results):
    vuln     = [r for r in results if r and r["verdict"] in ("VULNERABLE", "VULNERABLE_NS")]
    possible = [r for r in results if r and r["verdict"] in ("POSSIBLE", "POSSIBLE_MX", "POSSIBLE_SPF", "POSSIBLE_A")]
    safe     = [r for r in results if r and r["verdict"] == "NOT_VULNERABLE"]
    no_cname = [r for r in results if r and r["verdict"] in ("NO_CNAME", "NO_DNS")]
    wildcard = [r for r in results if r and r["verdict"] == "WILDCARD_SKIP"]

    print(f"\n{BOLD}{'═'*60}")
    print(f"  SUMMARY")
    print(f"{'═'*60}{RST}")
    print(f"  {R}{BOLD}VULNERABLE    : {len(vuln)}{RST}")
    print(f"  {Y}{BOLD}POSSIBLE      : {len(possible)}{RST}")
    print(f"  {G}NOT VULNERABLE: {len(safe)}{RST}")
    print(f"  {DIM}NO DNS        : {len(no_cname)}{RST}")
    if wildcard:
        print(f"  {B}WILDCARD SKIP : {len(wildcard)}{RST}")
    print(f"  {BOLD}TOTAL         : {len(results)}{RST}\n")

    if vuln:
        print(f"{R}{BOLD}  ── HIGH PRIORITY ──{RST}")
        for r in vuln:
            print(f"  {R}▶ {r['domain']}{RST}  [{r.get('service','?')}]  {DIM}{r['verdict']}{RST}")
    if possible:
        print(f"{Y}{BOLD}  ── INVESTIGATE ──{RST}")
        for r in possible:
            print(f"  {Y}▶ {r['domain']}{RST}  [{r.get('service','?')}]  {DIM}{r['verdict']}{RST}")

# ── Main ───────────────────────────────────────────────────────────────────────
def banner():
    dig_note = f"{G}dig available{RST}" if DIG_AVAILABLE else f"{Y}dig not found — using socket fallback{RST}"
    status = _ONLINE_FP_STATUS or ""
    if status.startswith("cached") or status.startswith("updated"):
        online_note = f"{G}fingerprints: {status}{RST}"
    elif status.startswith("skipped") or status.startswith("no cache"):
        online_note = f"{DIM}fingerprints: {status}{RST}"
    elif status:
        online_note = f"{Y}fingerprints: {status}{RST}"
    else:
        online_note = ""
    print(f"""{C}{BOLD}
  ███████╗██╗   ██╗██████╗ ████████╗ █████╗ ██╗  ██╗███████╗
  ██╔════╝██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝
  ███████╗██║   ██║██████╔╝   ██║   ███████║█████╔╝ █████╗
  ╚════██║██║   ██║██╔══██╗   ██║   ██╔══██║██╔═██╗ ██╔══╝
  ███████║╚██████╔╝██████╔╝   ██║   ██║  ██║██║  ██╗███████╗
  ╚══════╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
{RST}{DIM}  Subdomain Takeover v{VERSION}  —  {dig_note}
  {online_note}
  Services: {len(SERVICES)} fingerprints ({sum(1 for s in SERVICES if not s.get('not_vulnerable'))} vulnerable/edge-case)
  IP ranges: {_CLOUD_RANGES_SOURCE}{RST}
""")

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain takeover decision tool"
    )
    parser.add_argument("-d", "--domain",   help="Single domain to check")
    parser.add_argument("-f", "--file",     help="File with one domain per line")
    parser.add_argument("-t", "--threads",  type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("-o", "--output",   help="Save JSON results to file")
    parser.add_argument("--only-vuln",      action="store_true",
                        help="Only print and save VULNERABLE/POSSIBLE results")
    parser.add_argument("--http",           action="store_true",
                        help="Force plain HTTP instead of HTTPS (skips TLS fallback)")
    parser.add_argument("--delay",          type=float, default=0.0,
                        help="Seconds to sleep between requests per thread (default: 0)")
    parser.add_argument("--json",            action="store_true",
                        help="Print JSON results to stdout (respects --only-vuln)")
    parser.add_argument("--debug",          action="store_true",
                        help="Show raw output of every command")
    parser.add_argument("-v", "--version",  action="store_true", help="Print version and exit")
    parser.add_argument("--no-online",      action="store_true",
                        help="Don't read the local fingerprint/IP cache either — "
                             "use the built-in list only")
    parser.add_argument("--update-list",    action="store_true",
                        help="Download the latest fingerprints (can-i-take-over-xyz) "
                             "and cloud IP ranges and refresh the local cache at "
                             "~/.config/subtake/ (services.json, ips.json)")
    args = parser.parse_args()

    if args.version:
        print(f"subtake.py v{VERSION}")
        sys.exit(0)

    global DEBUG
    DEBUG = args.debug

    # ── Cloud IP ranges: read from local cache by default, only network on --update-list
    ips_cache_saved = _init_cloud_ranges(no_online=args.no_online, update_list=args.update_list)

    # ── Fingerprints: read from local cache by default, only network on --update-list
    global SERVICES, _ONLINE_FP_STATUS
    services_cache_saved = False
    if args.update_list:
        online = _fetch_online_fingerprints()
        if online:
            added, backfilled = _merge_online_services(online)
            services_cache_saved = _save_services_cache(online)
            _ONLINE_FP_STATUS = (f"updated: {len(online)} fetched, +{added} new, "
                                  f"{backfilled} descriptions backfilled")
        else:
            cached, fetched_at = _load_services_cache()
            if cached:
                added, backfilled = _merge_online_services(cached)
                _ONLINE_FP_STATUS = f"update failed (network) — kept existing cache ({fetched_at})"
            else:
                _ONLINE_FP_STATUS = "update failed (network), no cache — built-in only"
    elif args.no_online:
        _ONLINE_FP_STATUS = "skipped (--no-online)"
    else:
        cached, fetched_at = _load_services_cache()
        if cached is not None:
            added, backfilled = _merge_online_services(cached)
            _ONLINE_FP_STATUS = f"cached ({fetched_at}), +{added} new"
        else:
            _ONLINE_FP_STATUS = "no cache — run --update-list to fetch (using built-in only)"

    banner()

    if args.update_list:
        if services_cache_saved:
            print(f"  {G}✓ Cache refreshed →{RST} {SERVICES_CACHE_FILE}")
        else:
            print(f"  {Y}✗ Fingerprint fetch failed — {SERVICES_CACHE_FILE} not updated{RST}")
        if ips_cache_saved:
            print(f"  {G}✓ Cache refreshed →{RST} {IPS_CACHE_FILE}")
        else:
            print(f"  {Y}✗ IP range fetch failed — {IPS_CACHE_FILE} not updated{RST}")
        print()

    # Collect targets
    targets = []
    if args.domain:
        targets.append(args.domain)
    elif args.file:
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip()]
    elif not sys.stdin.isatty():
        targets = [l.strip() for l in sys.stdin if l.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    print(f"{DIM}  Checking {len(targets)} target(s) with {args.threads} threads...{RST}")

    def check_with_delay(domain):
        if args.delay > 0:
            time.sleep(args.delay)
        return check_subdomain(domain, force_http=args.http)

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_with_delay, t): t for t in targets}
        for fut in as_completed(futures):
            r = fut.result()
            if r is None:
                continue
            results.append(r)
            # --only-vuln: skip printing (and later saving) boring results
            if args.only_vuln and r["verdict"] not in (
                "VULNERABLE", "VULNERABLE_NS", "POSSIBLE", "POSSIBLE_MX", "POSSIBLE_SPF", "POSSIBLE_A"
            ):
                continue
            with _PRINT_LOCK:
                print_result(r)

    if len(targets) > 1:
        print_summary(results)

    _interesting = ("VULNERABLE", "VULNERABLE_NS", "POSSIBLE", "POSSIBLE_MX", "POSSIBLE_SPF", "POSSIBLE_A")

    if args.output:
        save = ([r for r in results if r["verdict"] in _interesting]
                if args.only_vuln else results)
        with open(args.output, "w") as f:
            json.dump(save, f, indent=2)
        print(f"\n  {G}Results saved → {args.output}  ({len(save)} entries){RST}\n")

    if args.json:
        save = ([r for r in results if r["verdict"] in _interesting]
                if args.only_vuln else results)
        print(json.dumps(save, indent=2))

if __name__ == "__main__":
    main()
