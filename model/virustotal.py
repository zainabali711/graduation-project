"""VirusTotal URL reputation lookup (free API)."""

from __future__ import annotations

import base64
import logging
import os
import sys
import threading
import time
import warnings
from collections import OrderedDict
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
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = True


def _diag(msg: str) -> None:
    """Force a line into Render runtime logs (stdout + stderr, unbuffered)."""
    line = f"VT_DIAG {msg}"
    print(line, flush=True)
    print(line, file=sys.stderr, flush=True)
    logger.info(line)

# Local .env for development only. Never override Render/process env vars.
_BASE = Path(__file__).resolve().parent.parent
load_dotenv(_BASE / ".env", override=False)

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
USER_UNAVAILABLE_MSG = "VirusTotal check unavailable — using ML result only"
USER_RATE_LIMIT_MSG = (
    "VirusTotal is busy (free plan: 4 requests/min shared by all users). "
    "Please wait about 20 seconds and scan again — ML result is shown for now."
)
API_KEY_ENV_NAME = "VIRUSTOTAL_API_KEY"

# Free public API: 4 requests / minute per key (shared by every user of this app).
_MAX_REQUESTS_PER_MINUTE = 4
_MIN_INTERVAL_SEC = 60.0 / _MAX_REQUESTS_PER_MINUTE  # 15s
_CACHE_TTL_SEC = 600.0  # 10 minutes
_CACHE_MAX_ENTRIES = 256

_rate_lock = threading.Lock()
_request_times: list[float] = []
_cache_lock = threading.Lock()
_result_cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()


def _api_key() -> str:
    return (os.environ.get(API_KEY_ENV_NAME) or "").strip()


def _log_key_debug(context: str) -> str:
    key = _api_key()
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
        bool(key),
        len(key),
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
    env = (os.environ.get("VIRUSTOTAL_SSL_VERIFY") or "").strip().lower()
    if env in {"0", "false", "no", "off"}:
        return False
    if certifi is not None:
        return certifi.where()
    return True


def _make_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update(_vt_headers())
    # Do NOT auto-retry 429 here — that burns the shared free quota.
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.5,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


def _cache_get(url_id: str) -> dict | None:
    now = time.monotonic()
    with _cache_lock:
        item = _result_cache.get(url_id)
        if not item:
            return None
        stored_at, payload = item
        if now - stored_at > _CACHE_TTL_SEC:
            _result_cache.pop(url_id, None)
            return None
        _result_cache.move_to_end(url_id)
        logger.info("[VirusTotal] cache hit url_id_prefix=%s…", url_id[:12])
        return dict(payload)


def _cache_set(url_id: str, payload: dict) -> None:
    if not payload.get("available"):
        return
    with _cache_lock:
        _result_cache[url_id] = (time.monotonic(), dict(payload))
        _result_cache.move_to_end(url_id)
        while len(_result_cache) > _CACHE_MAX_ENTRIES:
            _result_cache.popitem(last=False)


def _wait_for_rate_slot() -> None:
    """Block until making one more VT API call stays under 4/min.

    Sleeps happen OUTSIDE the lock so concurrent requests are not frozen.
    """
    while True:
        wait = 0.0
        with _rate_lock:
            now = time.monotonic()
            while _request_times and now - _request_times[0] >= 60.0:
                _request_times.pop(0)

            if len(_request_times) < _MAX_REQUESTS_PER_MINUTE:
                if _request_times:
                    since_last = now - _request_times[-1]
                    if since_last < _MIN_INTERVAL_SEC:
                        wait = _MIN_INTERVAL_SEC - since_last
                    else:
                        _request_times.append(now)
                        return
                else:
                    _request_times.append(now)
                    return
            else:
                wait = 60.0 - (now - _request_times[0]) + 0.05

        wait = max(wait, 0.05)
        logger.info("[VirusTotal] rate-slot wait=%.1fs", wait)
        time.sleep(wait)


def _request(session: requests.Session, method: str, url: str, **kwargs):
    """Rate-limited request; SSL fallback for broken local trust stores."""
    _wait_for_rate_slot()
    verify = kwargs.pop("verify", _ssl_verify_setting())
    try:
        resp = session.request(method, url, verify=verify, timeout=25, **kwargs)
    except requests.exceptions.SSLError as ssl_exc:
        _diag(f"SSLError on {method} — retry verify=False | {ssl_exc}")
        warnings.simplefilter("ignore", InsecureRequestWarning)
        resp = session.request(method, url, verify=False, timeout=25, **kwargs)

    body_snip = ""
    try:
        body_snip = (resp.text or "")[:180].replace("\n", " ")
    except Exception:
        body_snip = "<unreadable>"
    _diag(
        f"HTTP {method} status_code={resp.status_code} "
        f"path={url.split('/api/v3/')[-1][:80]} body_snip={body_snip!r}"
    )
    return resp


def _retry_after_seconds(response: requests.Response, default: float = 20.0) -> float:
    raw = response.headers.get("Retry-After")
    if not raw:
        return default
    try:
        return max(float(raw), 1.0)
    except ValueError:
        return default


def check_url(url: str) -> dict:
    """
    Check a URL with VirusTotal (free API — one key shared by all app users).
    """
    _diag("check_url ENTER")
    key = _log_key_debug("before API call")
    ssl_verify = _ssl_verify_setting()
    _diag(
        f"key_present={bool(key)} key_length={len(key)} "
        f"ssl_verify={'certifi' if not isinstance(ssl_verify, bool) else ssl_verify}"
    )

    if not key:
        return _error_result(f"{API_KEY_ENV_NAME} is not set in environment")

    url = _normalize_url(url)
    url_id = _url_id(url)

    cached = _cache_get(url_id)
    if cached is not None:
        _diag("CACHE_HIT available=True")
        return cached

    headers = _vt_headers()
    last_exc: Exception | None = None
    last_status: int | None = None

    for attempt in range(3):
        try:
            _diag(f"attempt={attempt + 1} GET report")
            with _make_session() as session:
                report = _request(
                    session,
                    "GET",
                    f"{VT_URL_ENDPOINT}/{url_id}",
                    headers=headers,
                )
                last_status = report.status_code

                if report.status_code == 401:
                    return _error_result("Invalid VirusTotal API key (HTTP 401)")
                if report.status_code == 403:
                    return _error_result("VirusTotal forbidden (HTTP 403)")
                if report.status_code == 429:
                    wait = _retry_after_seconds(report)
                    _diag(f"HTTP 429 — waiting {wait:.1f}s then retry")
                    if attempt < 2:
                        time.sleep(wait)
                        continue
                    return _error_result(
                        "VirusTotal rate limit reached (free: 4 requests/min)",
                        user_message=USER_RATE_LIMIT_MSG,
                    )

                if report.status_code == 404:
                    submit = _request(
                        session,
                        "POST",
                        VT_URL_ENDPOINT,
                        headers=headers,
                        data={"url": url},
                    )
                    last_status = submit.status_code
                    if submit.status_code == 429:
                        wait = _retry_after_seconds(submit)
                        if attempt < 2:
                            time.sleep(wait)
                            continue
                        return _error_result(
                            "VirusTotal rate limit reached (free: 4 requests/min)",
                            user_message=USER_RATE_LIMIT_MSG,
                        )
                    if submit.status_code >= 400:
                        return _error_result(
                            f"VirusTotal submit failed ({submit.status_code})"
                        )

                    analysis_id = submit.json()["data"]["id"]
                    analysis = _request(
                        session,
                        "GET",
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                    )
                    last_status = analysis.status_code
                    if analysis.status_code == 429:
                        wait = _retry_after_seconds(analysis)
                        if attempt < 2:
                            time.sleep(wait)
                            continue
                        return _error_result(
                            "VirusTotal rate limit reached (free: 4 requests/min)",
                            user_message=USER_RATE_LIMIT_MSG,
                        )
                    if analysis.status_code >= 400:
                        return _error_result(
                            "VirusTotal has no report for this URL yet"
                        )

                    stats = analysis.json()["data"]["attributes"].get("stats", {})
                    permalink = f"https://www.virustotal.com/gui/url/{url_id}"
                elif report.status_code >= 400:
                    return _error_result(
                        f"VirusTotal report failed ({report.status_code})"
                    )
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

                result = {
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
                _diag(
                    f"SUCCESS status_code={last_status} "
                    f"positives={positives} total={total}"
                )
                _cache_set(url_id, result)
                return result

        except (requests.Timeout, requests.RequestException, OSError, PermissionError) as exc:
            last_exc = exc
            _diag(
                f"EXCEPTION attempt={attempt + 1} "
                f"type={type(exc).__name__} detail={exc}"
            )
            if attempt < 2:
                time.sleep(0.8 * (attempt + 1))
                continue
        except (KeyError, ValueError, TypeError) as exc:
            _diag(f"PARSE_ERROR type={type(exc).__name__} detail={exc}")
            return _error_result(f"Unexpected VirusTotal response: {exc}")

    detail = str(last_exc) if last_exc else "Network error"
    if last_status is not None:
        detail = f"{detail} | last_status_code={last_status}"
    return _error_result(detail)


def _error_result(detail: str, user_message: str | None = None) -> dict:
    _diag(f"UNAVAILABLE error_detail={detail}")
    return {
        "available": False,
        "error": user_message or USER_UNAVAILABLE_MSG,
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
