"""Email verification helpers for CyberScan auth."""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
import sys
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse

from flask import current_app, has_request_context, render_template, url_for
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = logging.getLogger("cyberscan.mail")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def _mail_log(msg: str) -> None:
    line = f"MAIL_DIAG {msg}"
    print(line, flush=True)
    print(line, file=sys.stderr, flush=True)
    logger.info(line)


def auth_log(msg: str) -> None:
    line = f"AUTH_DIAG {msg}"
    print(line, flush=True)
    print(line, file=sys.stderr, flush=True)
    logger.info(line)


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="email-verify")


def generate_verification_token(email: str) -> str:
    return _serializer().dumps(email)


def confirm_verification_token(token: str, max_age_seconds: int = 60 * 60 * 24) -> str | None:
    """Return email if token is valid, otherwise None."""
    try:
        return _serializer().loads(token, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None


def _is_unreachable_public_base(base: str) -> bool:
    """True for localhost/LAN bases that phones/other devices cannot open."""
    host = (urlparse(base).hostname or "").lower()
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if host.startswith("192.168.") or host.startswith("10."):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def build_verification_path(user) -> tuple[str, str]:
    """Return (token, same-origin path) for in-browser verify — never a cross-host URL."""
    token = generate_verification_token(user.email)
    path = url_for("verify_email", token=token)
    return token, path


def build_verification_url(user, token: str | None = None) -> str:
    """
    Absolute verify URL for emails.

    Prefer APP_BASE_URL when it is a public URL. Never fall back to a LAN/private
    IP (that makes the in-browser button hang on phones). Inside a request, use
    the current public host via url_for(_external=True) + ProxyFix.

    Pass token= to reuse the same token as the in-browser verify button.
    Must be called from an active request (or with APP_BASE_URL set) — do not
    call this from a background thread.
    """
    token = token or generate_verification_token(user.email)
    path = url_for("verify_email", token=token)
    base = (
        os.environ.get("APP_BASE_URL")
        or current_app.config.get("APP_BASE_URL")
        or ""
    ).strip().rstrip("/")

    if base and _is_unreachable_public_base(base):
        _mail_log(f"ignore_bad_app_base_url base={base!r}")
        base = ""

    if base:
        return f"{base}{path}"

    if has_request_context():
        # Uses the Host / X-Forwarded-* headers (ProxyFix on Render).
        return url_for("verify_email", token=token, _external=True)

    raise RuntimeError(
        "Cannot build verification URL without a request context or APP_BASE_URL"
    )


def send_verification_email(mail, user, verify_url: str | None = None) -> str:
    """
    Send a verification email with a signed token link.

    Uses smtplib directly with an explicit timeout so Render workers do not hang
    forever when Gmail SMTP is slow/blocked. Flask-Mail has no reliable timeout.

    Prefer passing verify_url built inside the HTTP request (see
    queue_verification_email). Building it here requires a request context or
    APP_BASE_URL.
    """
    if not verify_url:
        verify_url = build_verification_url(user)

    sender = (
        current_app.config.get("MAIL_DEFAULT_SENDER")
        or current_app.config.get("MAIL_USERNAME")
        or ""
    )
    username = (current_app.config.get("MAIL_USERNAME") or "").strip()
    password = (current_app.config.get("MAIL_PASSWORD") or "").strip().replace(" ", "")
    server = current_app.config.get("MAIL_SERVER", "smtp.gmail.com")
    port = int(current_app.config.get("MAIL_PORT", 587))
    use_tls = bool(current_app.config.get("MAIL_USE_TLS", True))
    timeout = int(current_app.config.get("MAIL_TIMEOUT", 10))

    text_body = (
        f"Hello {user.username},\n\n"
        "Thank you for registering with CyberScan.\n"
        "Please verify your email by opening this link:\n\n"
        f"{verify_url}\n\n"
        "This link expires in 24 hours.\n\n"
        "If you did not create this account, you can ignore this email.\n"
    )
    html_body = render_template(
        "email/verify.html",
        username=user.username,
        verify_url=verify_url,
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Verify your CyberScan account"
    msg["From"] = sender
    msg["To"] = user.email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    _mail_log(
        f"send_start to={user.email!r} server={server}:{port} "
        f"timeout={timeout}s tls={use_tls}"
    )

    try:
        with smtplib.SMTP(server, port, timeout=timeout) as smtp:
            smtp.ehlo()
            if use_tls:
                context = ssl.create_default_context()
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(username, password)
            smtp.sendmail(sender, [user.email], msg.as_string())
        _mail_log(f"send_ok to={user.email!r}")
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        _mail_log(f"send_fail type={type(exc).__name__} detail={exc}")
        raise

    return verify_url


def queue_verification_email(app, user_id: int, verify_url: str) -> None:
    """
    Send verification email on a daemon thread so the HTTP worker is never blocked
    by SMTP (even for the MAIL_TIMEOUT window).

    verify_url must be built in the active request before calling this — url_for
    cannot run safely on a background thread without SERVER_NAME.
    """
    if not verify_url:
        raise ValueError("verify_url is required for background email send")

    def _worker() -> None:
        with app.app_context():
            from models import User, db as _db

            user = _db.session.get(User, user_id)
            if user is None:
                _mail_log(f"async_skip missing_user_id={user_id}")
                return
            try:
                send_verification_email(None, user, verify_url=verify_url)
            except Exception as exc:
                _mail_log(
                    f"async_fail user_id={user_id} type={type(exc).__name__} detail={exc}"
                )

    thread = threading.Thread(
        target=_worker,
        name=f"verify-mail-{user_id}",
        daemon=True,
    )
    thread.start()
    _mail_log(f"async_queued user_id={user_id}")


def mail_configured() -> bool:
    """True when Gmail credentials are available in Flask config or environment."""
    username = ""
    password = ""
    try:
        username = (current_app.config.get("MAIL_USERNAME") or "").strip()
        password = (current_app.config.get("MAIL_PASSWORD") or "").strip().replace(" ", "")
    except RuntimeError:
        pass

    if not username:
        username = os.environ.get("MAIL_USERNAME", "").strip()
    if not password:
        password = os.environ.get("MAIL_PASSWORD", "").strip().replace(" ", "")

    return bool(username and password)
