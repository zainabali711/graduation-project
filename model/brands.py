"""Known-good brand / domain allowlist for ML false-positive reduction."""

from __future__ import annotations

from urllib.parse import urlparse

# Brand tokens used for dataset cleanup / weak matching inside hostnames.
BRAND_TOKENS = [
    "google",
    "youtube",
    "tiktok",
    "facebook",
    "instagram",
    "twitter",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "paypal",
    "bankmuscat",
    "linkedin",
    "whatsapp",
    "github",
    "wikipedia",
    "yahoo",
    "reddit",
    "spotify",
    "adobe",
    "oracle",
    "samsung",
    "nvidia",
    "intel",
    "ibm",
    "cisco",
    "dropbox",
    "zoom",
    "slack",
    "shopify",
    "ebay",
    "walmart",
    "target",
    "nike",
    "adidas",
    "bbc",
    "cnn",
    "nytimes",
    "cloudflare",
    "openai",
    "bankofamerica",
    "wellsfargo",
    "chase",
    "hsbc",
    "citibank",
]

# Exact registrable hostnames treated as trusted (allowlist).
KNOWN_GOOD_DOMAINS = {
    "google.com",
    "www.google.com",
    "youtube.com",
    "www.youtube.com",
    "tiktok.com",
    "www.tiktok.com",
    "facebook.com",
    "www.facebook.com",
    "instagram.com",
    "www.instagram.com",
    "twitter.com",
    "www.twitter.com",
    "x.com",
    "www.x.com",
    "microsoft.com",
    "www.microsoft.com",
    "apple.com",
    "www.apple.com",
    "amazon.com",
    "www.amazon.com",
    "netflix.com",
    "www.netflix.com",
    "paypal.com",
    "www.paypal.com",
    "bankmuscat.com",
    "www.bankmuscat.com",
    "linkedin.com",
    "www.linkedin.com",
    "whatsapp.com",
    "www.whatsapp.com",
    "github.com",
    "www.github.com",
    "wikipedia.org",
    "www.wikipedia.org",
    "en.wikipedia.org",
    "yahoo.com",
    "www.yahoo.com",
    "reddit.com",
    "www.reddit.com",
    "spotify.com",
    "www.spotify.com",
    "adobe.com",
    "www.adobe.com",
    "oracle.com",
    "www.oracle.com",
    "cloudflare.com",
    "www.cloudflare.com",
    "openai.com",
    "www.openai.com",
    "bbc.com",
    "www.bbc.com",
    "cnn.com",
    "www.cnn.com",
    "nytimes.com",
    "www.nytimes.com",
    "ebay.com",
    "www.ebay.com",
    "walmart.com",
    "www.walmart.com",
    "shopify.com",
    "www.shopify.com",
    "dropbox.com",
    "www.dropbox.com",
    "zoom.us",
    "www.zoom.us",
    "slack.com",
    "www.slack.com",
    "samsung.com",
    "www.samsung.com",
    "nvidia.com",
    "www.nvidia.com",
    "intel.com",
    "www.intel.com",
    "ibm.com",
    "www.ibm.com",
    "chase.com",
    "www.chase.com",
    "bankofamerica.com",
    "www.bankofamerica.com",
    "wellsfargo.com",
    "www.wellsfargo.com",
    "hsbc.com",
    "www.hsbc.com",
    "citibank.com",
    "www.citibank.com",
    "office.com",
    "www.office.com",
    "live.com",
    "www.live.com",
    "outlook.com",
    "www.outlook.com",
    "bing.com",
    "www.bing.com",
    "gmail.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "maps.google.com",
}


def hostname_from_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    host = (urlparse(raw).hostname or "").lower()
    return host


def bare_host(host: str) -> str:
    host = (host or "").lower().strip(".")
    if host.startswith("www."):
        return host[4:]
    return host


def is_known_good_domain(url_or_host: str) -> bool:
    """True if hostname (or URL) is on the trusted allowlist."""
    host = hostname_from_url(url_or_host) if "://" in url_or_host or "/" in url_or_host else url_or_host
    host = (host or "").lower().strip(".")
    if not host:
        return False
    if host in KNOWN_GOOD_DOMAINS:
        return True
    if bare_host(host) in {bare_host(d) for d in KNOWN_GOOD_DOMAINS}:
        # Allow exact apex match against allowlist apexes
        apex = bare_host(host)
        allowed_apexes = {bare_host(d) for d in KNOWN_GOOD_DOMAINS}
        return apex in allowed_apexes
    return False


def benign_brand_urls() -> list[str]:
    """Homepage-style benign URLs used to strengthen training."""
    urls: list[str] = []
    seen = set()
    for host in sorted(KNOWN_GOOD_DOMAINS):
        for scheme in ("https://", "http://"):
            u = scheme + host
            if u not in seen:
                seen.add(u)
                urls.append(u)
            u2 = scheme + host + "/"
            if u2 not in seen:
                seen.add(u2)
                urls.append(u2)
    # Extra common paths on major brands
    extras = [
        "https://www.google.com/search",
        "https://maps.google.com/",
        "https://mail.google.com/",
        "https://drive.google.com/",
        "https://www.youtube.com/watch",
        "https://www.facebook.com/login",
        "https://www.instagram.com/accounts/login",
        "https://www.amazon.com/gp/css/homepage.html",
        "https://www.paypal.com/signin",
        "https://www.microsoft.com/en-us",
        "https://www.apple.com/iphone",
        "https://www.netflix.com/login",
        "https://bankmuscat.com/",
        "https://www.bankmuscat.com/",
        "https://www.bankmuscat.com/en",
        "https://tiktok.com/",
        "https://www.tiktok.com/",
        "https://www.tiktok.com/explore",
        "https://github.com/login",
        "https://www.wikipedia.org/wiki/Main_Page",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://www.reddit.com/r/popular",
        "https://openai.com/chatgpt",
        "https://www.cloudflare.com/",
        "https://www.bbc.com/news",
        "https://www.cnn.com/",
        "https://www.nytimes.com/",
    ]
    for u in extras:
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls
