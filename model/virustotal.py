"""VirusTotal URL reputation lookup (free API)."""

import base64
import logging
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

logger = logging.getLogger("cyberscan.virustotal")
if not logger.handlers:
    # Ensure messages appear in Render logs even if app root logging is minimal.
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

# Always load project .env for local dev (no-op if file missing on Render).
# Do NOT override existing process env (Render dashboard vars must win).
_BASE = Path(__file__).resolve().parent.parent
load_dotenv(_BASE / ".env", override=False)

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"

# Clean message shown in the UI (no technical / OS details).
USER_UNAVAILABLE_MSG = "VirusTotal check unavailable — using ML result only"

# Exact env var name Render must use (character-for-character):
API_KEY_ENV_NAME = "VIRUSTOTAL_API_KEY"


def _api_key() -> str:
    """Read key fresh each call so late dotenv loads still work."""
    return (os.environ.get(API_KEY_ENV_NAME) or "").strip()


def _log_key_debug(context: str) -> str:
    """Log whether the API key is present (never log the key itself)."""
    key = _api_key()
    present = bool(key)
    length = len(key)
    # Also report if a similarly named var exists (common Render typo).
    similar = [
        name
        for name in os.environ
        if "VIRUSTOTAL" in name.upper() or "VIRUS_TOTAL" in name.upper()
    ]
    logger.info(
        "[VirusTotal] %s | env=%s | key_present=%s | key_length=%s | "
        "expected_length=64 | virustotal_related_env_names=%s",
        context,
        API_KEY_ENV_NAME,
        present,
        length,
        similar,
    )
    return key


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
    Real failure reasons are logged and stored in error_detail (UI hides error_detail).
    """
    key = _log_key_debug("before API call")
    ssl_verify = _ssl_verify_setting()
    logger.info(
        "[VirusTotal] ssl_verify=%s | endpoint=%s",
        ssl_verify if isinstance(ssl_verify, bool) else "certifi_bundle",
        VT_URL_ENDPOINT,
    )

    if not key:
        return _error_result(f"{API_KEY_ENV_NAME} is not set in environment")

    url = _normalize_url(url)
    url_id = _url_id(url)
    headers = _vt_headers()

    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            logger.info("[VirusTotal] attempt=%s GET report url_id_prefix=%s…", attempt + 1, url_id[:12])
            with _make_session() as session:
                report = _request(
                    session,
                    "GET",
                    f"{VT_URL_ENDPOINT}/{url_id}",
                    headers=headers,
                )
                logger.info("[VirusTotal] report status_code=%s", report.status_code)

                if report.status_code == 401:
                    return _error_result("Invalid VirusTotal API key (HTTP 401)")
                if report.status_code == 403:
                    return _error_result("VirusTotal forbidden (HTTP 403)")
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
                    logger.info("[VirusTotal] submit status_code=%s", submit.status_code)
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
                    logger.info("[VirusTotal] analysis status_code=%s", analysis.status_code)
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

                logger.info(
                    "[VirusTotal] OK positives=%s total_engines=%s",
                    positives,
                    total,
                )
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
            # Previously swallowed into generic Unavailable with no log.
            last_exc = exc
            logger.warning(
                "[VirusTotal] request exception attempt=%s type=%s detail=%s",
                attempt + 1,
                type(exc).__name__,
                exc,
            )
            if attempt < 2:
                time.sleep(0.8 * (attempt + 1))
                continue
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning(
                "[VirusTotal] response parse error type=%s detail=%s",
                type(exc).__name__,
                exc,
            )
            return _error_result(f"Unexpected VirusTotal response: {exc}")

    return _error_result(str(last_exc) if last_exc else "Network error")


def _error_result(detail: str) -> dict:
    """Return unavailable result; UI sees only USER_UNAVAILABLE_MSG."""
    logger.warning("[VirusTotal] UNAVAILABLE reason=%s", detail)
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
