import math
import re
import socket
import ssl
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

from model.brands import is_known_good_domain

SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".pw",
    ".cc",
    ".su",
]

KNOWN_TLDS = (".com", ".org", ".net", ".edu", ".gov")

URL_SHORTENERS = [
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
]

# Compact lexicon for domain_word_count (common English / brand-ish tokens).
COMMON_WORDS = {
    "about",
    "account",
    "admin",
    "app",
    "bank",
    "blog",
    "book",
    "buy",
    "center",
    "city",
    "cloud",
    "club",
    "commerce",
    "community",
    "company",
    "contact",
    "data",
    "digital",
    "download",
    "drive",
    "earth",
    "edu",
    "email",
    "file",
    "free",
    "game",
    "global",
    "google",
    "group",
    "help",
    "home",
    "host",
    "info",
    "login",
    "mail",
    "market",
    "media",
    "mobile",
    "money",
    "music",
    "my",
    "net",
    "news",
    "online",
    "pay",
    "portal",
    "secure",
    "security",
    "server",
    "service",
    "shop",
    "site",
    "soft",
    "store",
    "support",
    "tech",
    "the",
    "update",
    "user",
    "video",
    "web",
    "world",
    "www",
}

CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def calculate_entropy(text):
    if not text:
        return 0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _domain_core(domain: str) -> str:
    """Hostname without www / port, lowercased."""
    host = (domain or "").split("@")[-1]
    host = host.split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _consonant_ratio(domain: str) -> float:
    letters = [c for c in domain.lower() if c.isalpha()]
    if not letters:
        return 0.0
    consonants = sum(1 for c in letters if c in CONSONANTS)
    return round(consonants / len(letters), 4)


def _repeated_chars(domain: str) -> int:
    """Count repeated-character runs (e.g. 'aa', '111', '---')."""
    if not domain:
        return 0
    return len(re.findall(r"(.)\1+", domain.lower()))


def _domain_word_count(domain: str) -> int:
    """
    Count real-word-like tokens in the domain:
    hyphen/underscore splits plus common words found in the label.
    """
    host = _domain_core(domain)
    parts = [p for p in host.split(".") if p and p not in {"com", "org", "net", "edu", "gov"}]
    label = "-".join(parts)
    if not label:
        return 0

    tokens = [t for t in re.split(r"[-_]+", label) if t.isalpha() and len(t) >= 2]
    count = 0
    seen = set()

    for token in tokens:
        if token in COMMON_WORDS and token not in seen:
            seen.add(token)
            count += 1
        elif len(token) >= 3 and token.isalpha() and token not in seen:
            seen.add(token)
            count += 1

    compact = re.sub(r"[^a-z]", "", label)
    for word in COMMON_WORDS:
        if len(word) >= 3 and word in compact and word not in seen:
            seen.add(word)
            count += 1

    return count


def _dns_resolves(hostname: str) -> int:
    if not hostname:
        return 0
    try:
        socket.gethostbyname(hostname)
        return 1
    except OSError:
        return 0


def _ssl_valid(hostname: str) -> int:
    if not hostname:
        return 0
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return 1 if ssock.getpeercert() else 0
    except Exception:
        if not hostname.startswith("www."):
            return _ssl_valid(f"www.{hostname}")
        return 0


def _domain_age_days(hostname: str) -> int:
    """WHOIS creation age in days; 0 if unknown."""
    if not hostname:
        return 0
    try:
        import whois

        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, (list, tuple)):
            created = created[0] if created else None
        if not isinstance(created, datetime):
            return 0
        now = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, (now - created).days)
    except Exception:
        return 0


def _offline_rich_features(url: str, hostname: str, known: bool) -> dict:
    """
    Training-safe proxies (no network). Known brands get strong reputation priors.
    """
    https = 1 if url.startswith("https") else 0
    return {
        "domain_age_days": 3650 if known else 0,
        "dns_resolves": 1 if known else 0,
        "ssl_valid": 1 if known and https else (1 if known else 0),
    }


def _live_rich_features(hostname: str, known: bool) -> dict:
    """Live DNS / SSL / WHOIS enrichment for a single prediction."""
    dns = _dns_resolves(hostname) or _dns_resolves(
        hostname[4:] if hostname.startswith("www.") else f"www.{hostname}"
    )
    ssl_ok = _ssl_valid(hostname)
    age = _domain_age_days(_domain_core(hostname) or hostname)
    # Soft fallback for allowlisted brands when WHOIS/DNS flake
    if known and age <= 0:
        age = 3650
    if known and dns == 0:
        dns = 1
    if known and ssl_ok == 0 and hostname:
        ssl_ok = 1
    return {
        "domain_age_days": int(age),
        "dns_resolves": int(dns),
        "ssl_valid": int(ssl_ok),
    }


def extract_features(url, live_enrich: bool = False):
    """
    Extract lexical + reputation features.

    has_https was removed (dominated RF importance / protocol bias).
    live_enrich=True enables DNS/SSL/WHOIS (prediction time only).
    """
    try:
        if not url or not isinstance(url, str):
            return None

        url = url.strip()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
        host = _domain_core(domain)
        hostname = (parsed.hostname or "").lower()
        known = 1 if is_known_good_domain(url) else 0

        try:
            has_port = 1 if parsed.port is not None else 0
        except Exception:
            has_port = 0

        if live_enrich:
            rich = _live_rich_features(hostname or host, bool(known))
        else:
            rich = _offline_rich_features(url, hostname or host, bool(known))

        return {
            "url_length": len(url),
            "domain_length": len(domain),
            "num_digits": sum(c.isdigit() for c in url),
            "num_special_chars": len(re.findall(r"[-_@?=&%#+~]", url)),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_slashes": url.count("/"),
            "subdomain_count": max(len(domain.split(".")) - 2, 0),
            "has_ip_address": 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0,
            "has_at_symbol": 1 if "@" in url else 0,
            "has_double_slash": 1 if "//" in url[7:] else 0,
            "tld_suspicious": 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
            "entropy": round(calculate_entropy(domain), 4),
            "digit_ratio": round(sum(c.isdigit() for c in url) / max(len(url), 1), 4),
            "path_length": len(path),
            "query_length": len(query),
            "num_params": len(query.split("&")) if query else 0,
            "is_shortened": 1 if hostname in URL_SHORTENERS else 0,
            "has_port": has_port,
            "has_known_tld": 1 if any(host.endswith(t) for t in KNOWN_TLDS) else 0,
            "consonant_ratio": _consonant_ratio(host),
            "digit_in_domain": 1 if any(c.isdigit() for c in host) else 0,
            "repeated_chars": _repeated_chars(host),
            "domain_word_count": _domain_word_count(host),
            "is_known_brand": known,
            "domain_age_days": rich["domain_age_days"],
            "dns_resolves": rich["dns_resolves"],
            "ssl_valid": rich["ssl_valid"],
        }

    except Exception:
        return None
