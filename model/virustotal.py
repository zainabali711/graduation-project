"""VirusTotal URL reputation lookup (free API)."""

import base64
import os
import time
import warnings
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None

# Always load project .env (works even if cwd is wrong)
_BASE = Path(__file__).resolve().parent.parent
load_dotenv(_BASE / ".env", override=True)

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"

# Clean message shown in the UI (no technical / OS details).
USER_UNAVAILABLE_MSG = "VirusTotal check unavailable — using ML result only"


def _api_key() -> str:
    """Read key fresh each call so late dotenv loads still work."""
    return (os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()


def _vt_headers() -> dict:
    return {
        "x-apikey": _api_key(),
        "User-Agent": "CyberScan/1.0",
        "Accept": "application/json",
    }


def _ssl_verify_setting():
    """
    Prefer system/certifi CAs. Some Windows antivirus products intercept HTTPS
    and break verification — callers may fall back to verify=False.
    """
    env = (os.environ.get("VIRUSTOTAL_SSL_VERIFY") or "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if certifi is not None:
        return certifi.where()
    return True


def _make_session() -> requests.Session:
    """Session with retries; ignore broken system proxies."""
    session = requests.Session()
    session.trust_env = False  # avoid Windows proxy env causing Permission denied
    session.headers.update(_vt_headers())
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme so VirusTotal can scan it."""
    url = (url or "").strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _url_id(url: str) -> str:
    """VirusTotal URL identifier (URL-safe base64 without padding)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


def _request(session: requests.Session, method: str, url: str, **kwargs):
    """Try secure SSL first; on CERTIFICATE_VERIFY_FAILED retry without verify."""
    verify = kwargs.pop("verify", _ssl_verify_setting())
    try:
        return session.request(method, url, verify=verify, timeout=20, **kwargs)
    except requests.exceptions.SSLError:
        # Common on Windows when antivirus does HTTPS scanning.
        warnings.simplefilter("ignore", InsecureRequestWarning)
        return session.request(method, url, verify=False, timeout=20, **kwargs)


def check_url(url: str) -> dict:
    """
    Check a URL with VirusTotal (free API — no paid plan required).

    Returns engine counts when available, or a clean unavailable message for the UI.
    """
    if not _api_key():
        return _error_result("VIRUSTOTAL_API_KEY is not set in .env")

    url = _normalize_url(url)
    url_id = _url_id(url)
    headers = _vt_headers()

    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            with _make_session() as session:
                report = _request(
                    session,
                    "GET",
                    f"{VT_URL_ENDPOINT}/{url_id}",
                    headers=headers,
                )

                if report.status_code == 401:
                    return _error_result("Invalid VirusTotal API key")
                if report.status_code == 429:
                    if attempt < 2:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                    return _error_result("VirusTotal rate limit reached (free: 4 requests/min)")

                if report.status_code == 404:
                    submit = _request(
                        session,
                        "POST",
                        VT_URL_ENDPOINT,
                        headers=headers,
                        data={"url": url},
                    )
                    if submit.status_code == 429:
                        if attempt < 2:
                            time.sleep(1.5 * (attempt + 1))
                            continue
                        return _error_result(
                            "VirusTotal rate limit reached (free: 4 requests/min)"
                        )
                    if submit.status_code >= 400:
                        return _error_result(f"VirusTotal submit failed ({submit.status_code})")

                    analysis_id = submit.json()["data"]["id"]
                    analysis = _request(
                        session,
                        "GET",
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                    )
                    if analysis.status_code >= 400:
                        return _error_result("VirusTotal has no report for this URL yet")

                    stats = analysis.json()["data"]["attributes"].get("stats", {})
                    permalink = f"https://www.virustotal.com/gui/url/{url_id}"
                elif report.status_code >= 400:
                    return _error_result(f"VirusTotal report failed ({report.status_code})")
                else:
                    attrs = report.json()["data"]["attributes"]
                    stats = attrs.get("last_analysis_stats", {})
                    permalink = f"https://www.virustotal.com/gui/url/{url_id}"

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                positives = malicious + suspicious
                total = malicious + suspicious + harmless + undetected

                return {
                    "available": True,
                    "error": None,
                    "error_detail": None,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total,
                    "positives": positives,
                    "is_malicious": positives > 0,
                    "permalink": permalink,
                    "domain": urlparse(url).netloc,
                }

        except (requests.Timeout, requests.RequestException, OSError, PermissionError) as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(0.8 * (attempt + 1))
                continue
        except (KeyError, ValueError, TypeError) as exc:
            return _error_result(f"Unexpected VirusTotal response: {exc}")

    return _error_result(str(last_exc) if last_exc else "Network error")


def _error_result(detail: str) -> dict:
    """Return unavailable result; UI sees only USER_UNAVAILABLE_MSG."""
    return {
        "available": False,
        "error": USER_UNAVAILABLE_MSG,
        "error_detail": detail,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "positives": 0,
        "is_malicious": False,
        "permalink": None,
    }
