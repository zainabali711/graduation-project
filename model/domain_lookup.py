"""Domain inspection: DNS/IP, IP geolocation, domain WHOIS, and SSL status."""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalize_domain(raw: str) -> str:
    """Extract a bare domain from user input."""
    value = (raw or "").strip().lower()
    if not value:
        raise ValueError("Domain cannot be empty")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    host = parsed.netloc or parsed.path
    host = host.split("/")[0].split("?")[0].split("#")[0]
    if "@" in host:
        host = host.split("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]

    host = host.strip(".")
    if not host or not _DOMAIN_RE.match(host):
        raise ValueError("Please enter a valid domain (for example: example.com)")
    return host


def _format_date(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.strftime("%Y-%m-%d")
    return str(value)


def _domain_age(created) -> str | None:
    if created is None:
        return None
    if isinstance(created, (list, tuple)):
        created = created[0] if created else None
    if not isinstance(created, datetime):
        return None

    now = datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    days = max(0, (now - created).days)
    years, rem = divmod(days, 365)
    months = rem // 30
    if years > 0:
        return f"{years} year{'s' if years != 1 else ''} {months} month{'s' if months != 1 else ''}"
    if months > 0:
        return f"{months} month{'s' if months != 1 else ''}"
    return f"{days} day{'s' if days != 1 else ''}"


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _ip_details(ip: str | None) -> dict:
    """Lookup country and organization via ip-api.com (free, no key)."""
    if not ip:
        return {"country": None, "organization": None}

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,message,country,countryCode,org,isp,as",
            },
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            return {"country": None, "organization": None}

        country = data.get("country") or data.get("countryCode")
        organization = data.get("org") or data.get("isp") or data.get("as")
        return {"country": country, "organization": organization}
    except Exception:
        return {"country": None, "organization": None}


def _whois_details(domain: str) -> dict:
    try:
        w = whois.whois(domain)
    except Exception as exc:
        return {
            "registrar": None,
            "created_date": None,
            "expires_date": None,
            "updated_date": None,
            "name_servers": None,
            "domain_age": None,
            "error": str(exc),
        }

    name_servers = w.name_servers
    if isinstance(name_servers, (list, tuple)):
        seen = set()
        cleaned = []
        for ns in name_servers:
            if not ns:
                continue
            key = str(ns).lower()
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(str(ns).lower())
        name_servers = ", ".join(cleaned[:6]) if cleaned else None
    elif name_servers:
        name_servers = str(name_servers)

    created = w.creation_date
    return {
        "registrar": w.registrar,
        "created_date": _format_date(created),
        "expires_date": _format_date(w.expiration_date),
        "updated_date": _format_date(w.updated_date),
        "name_servers": name_servers,
        "domain_age": _domain_age(created),
        "error": None,
    }


def check_ssl(domain: str) -> str:
    """Return Valid if TLS succeeds; otherwise Could not verify (blocked/timeout)."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return "Valid" if cert else "Could not verify"
    except Exception:
        return "Could not verify"


def _ssl_status(domain: str) -> str:
    """Check SSL on the bare domain, then www.<domain> as a fallback."""
    status = check_ssl(domain)
    if status == "Valid":
        return "Valid"
    if not domain.startswith("www."):
        return check_ssl(f"www.{domain}")
    return status


def inspect_domain(raw_domain: str) -> dict:
    """
    Full domain inspection result for the Domain Inspector page.
    """
    domain = normalize_domain(raw_domain)
    ip = _resolve_ip(domain)
    ip_info = _ip_details(ip)
    whois_info = _whois_details(domain)
    ssl_status = _ssl_status(domain)

    return {
        "domain": domain,
        "ip_address": ip or "Not resolved",
        "country": ip_info.get("country") or "Unknown",
        "organization": ip_info.get("organization") or "Unknown",
        "domain_age": whois_info.get("domain_age") or "Unknown",
        "ssl_status": ssl_status,
        "registrar": whois_info.get("registrar") or "Unknown",
        "created_date": whois_info.get("created_date") or "Unknown",
        "expires_date": whois_info.get("expires_date") or "Unknown",
        "updated_date": whois_info.get("updated_date") or "Unknown",
        "name_servers": whois_info.get("name_servers") or "Unknown",
    }
