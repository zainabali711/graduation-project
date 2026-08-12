"""Email verification helpers for CyberScan auth."""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app, render_template, url_for
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = logging.getLogger("cyberscan.mail")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = True


def _mail_log(msg: str) -> None:
    line = f"MAIL_DIAG {msg}"
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


def build_verification_url(user) -> str:
    """
    Build an absolute verify URL.

    Prefer APP_BASE_URL from config/.env so links work when opened from email
    (phones cannot open http://127.0.0.1 — that points at the phone itself).
    """
    token = generate_verification_token(user.email)
    path = url_for("verify_email", token=token)
    base = (
        current_app.config.get("APP_BASE_URL")
        or os.environ.get("APP_BASE_URL")
        or ""
    ).strip().rstrip("/")
    if base:
        return f"{base}{path}"
    return url_for("verify_email", token=token, _external=True)


def send_verification_email(mail, user) -> str:
    """
    Send a verification email with a signed token link.

    Uses smtplib directly with an explicit timeout so Render workers do not hang
    forever when Gmail SMTP is slow/blocked. Flask-Mail has no reliable timeout.
    Returns the verify URL (whether or not you also surface it in the UI).
    """
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
