"""Email verification helpers for CyberScan auth (OTP via Resend / SMTP)."""

from __future__ import annotations

import logging
import os
import secrets
import smtplib
import socket
import ssl
import sys
import threading
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from flask import current_app, render_template
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger("cyberscan.mail")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

OTP_TTL_SECONDS = 10 * 60
OTP_RESEND_COOLDOWN_SECONDS = 60

# Resend's built-in test sender — no domain verification required.
# (Only delivers to the email on your Resend account until you verify a domain.)
RESEND_SANDBOX_FROM = "CyberScan <onboarding@resend.dev>"


def _mail_log(msg: str) -> None:
    line = f"MAIL_DIAG {msg}"
    print(line, file=sys.stderr, flush=True)
    logger.info(line)


def auth_log(msg: str) -> None:
    line = f"AUTH_DIAG {msg}"
    print(line, file=sys.stderr, flush=True)
    logger.info(line)


def generate_otp_code() -> str:
    """Cryptographically random 6-digit code as a zero-padded string."""
    return f"{secrets.randbelow(1_000_000):06d}"


def mask_email(email: str) -> str:
    """Mask like di******@gmail.com for OTP UI copy."""
    email = (email or "").strip()
    if "@" not in email:
        return "******"
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = (local[:1] + "******") if local else "******"
    else:
        masked_local = local[:2] + "******"
    return f"{masked_local}@{domain}"


def assign_user_otp(user, code: str) -> None:
    """Store hashed OTP + expiry timestamps on the user row."""
    user.otp_hash = generate_password_hash(code)
    user.otp_expires_at = datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)
    user.otp_last_sent_at = datetime.utcnow()


def clear_user_otp(user) -> None:
    user.otp_hash = None
    user.otp_expires_at = None


def verify_user_otp(user, code: str) -> bool:
    code = (code or "").strip()
    if not code or not user.otp_hash or not user.otp_expires_at:
        return False
    if datetime.utcnow() > user.otp_expires_at:
        return False
    return check_password_hash(user.otp_hash, code)


def resend_cooldown_remaining(user) -> int:
    """Seconds until another OTP may be sent (0 = allowed now)."""
    if not user.otp_last_sent_at:
        return 0
    elapsed = (datetime.utcnow() - user.otp_last_sent_at).total_seconds()
    remaining = OTP_RESEND_COOLDOWN_SECONDS - elapsed
    return max(0, int(remaining))


def _resend_api_key() -> str:
    try:
        key = (current_app.config.get("RESEND_API_KEY") or "").strip()
    except RuntimeError:
        key = ""
    return key or os.environ.get("RESEND_API_KEY", "").strip()


def _smtp_sender() -> str:
    """From address for local SMTP only (not used by Resend)."""
    try:
        sender = (
            current_app.config.get("MAIL_DEFAULT_SENDER")
            or current_app.config.get("MAIL_USERNAME")
            or ""
        ).strip()
    except RuntimeError:
        sender = ""
    return (
        sender
        or os.environ.get("MAIL_DEFAULT_SENDER", "").strip()
        or os.environ.get("MAIL_USERNAME", "").strip()
        or "noreply@cyberscan.local"
    )


def _resend_from() -> str:
    """
    From address for Resend HTTPS sends.

    Never fall back to MAIL_USERNAME / Gmail — Resend rejects unverified domains
    (403). Use onboarding@resend.dev unless RESEND_FROM is explicitly a
    non-gmail address (e.g. after verifying your own domain).
    """
    try:
        configured = (current_app.config.get("RESEND_FROM") or "").strip()
    except RuntimeError:
        configured = ""
    configured = configured or os.environ.get("RESEND_FROM", "").strip()

    if configured:
        lower = configured.lower()
        # Extract bare email if "Name <email>" form
        if "<" in configured and ">" in configured:
            bare = configured[configured.rfind("<") + 1 : configured.rfind(">")].strip().lower()
        else:
            bare = lower
        if bare.endswith("@gmail.com") or bare.endswith("@googlemail.com"):
            _mail_log(
                f"from_override reason=gmail_unverified configured={configured!r} "
                f"using={RESEND_SANDBOX_FROM!r}"
            )
            return RESEND_SANDBOX_FROM
        return configured

    return RESEND_SANDBOX_FROM


def _send_via_resend(
    *,
    to_email: str,
    subject: str,
    text_body: str,
    html_body: str,
    timeout: int,
) -> None:
    api_key = _resend_api_key()
    sender = _resend_from()
    _mail_log(f"send_start transport=resend to={to_email!r} from={sender!r}")
    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "from": sender,
            "to": [to_email],
            "subject": subject,
            "text": text_body,
            "html": html_body,
        },
        timeout=timeout,
    )
    if resp.status_code >= 400:
        detail = resp.text[:500]
        _mail_log(f"send_fail transport=resend status={resp.status_code} detail={detail}")
        raise RuntimeError(f"Resend API error {resp.status_code}: {detail}")
    _mail_log(f"send_ok transport=resend to={to_email!r} id={resp.json().get('id')}")


def _send_via_smtp(
    *,
    to_email: str,
    sender: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> None:
    username = (current_app.config.get("MAIL_USERNAME") or "").strip()
    password = (current_app.config.get("MAIL_PASSWORD") or "").strip().replace(" ", "")
    server = current_app.config.get("MAIL_SERVER", "smtp.gmail.com")
    port = int(current_app.config.get("MAIL_PORT", 587))
    use_tls = bool(current_app.config.get("MAIL_USE_TLS", True))
    timeout = int(current_app.config.get("MAIL_TIMEOUT", 10))

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    _mail_log(
        f"send_start transport=smtp to={to_email!r} server={server}:{port} "
        f"timeout={timeout}s tls={use_tls}"
    )

    try:
        infos = socket.getaddrinfo(server, port, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"No IPv4 address for {server}:{port}")

        with smtplib.SMTP(server, port, timeout=timeout) as smtp:
            smtp.ehlo()
            if use_tls:
                context = ssl.create_default_context()
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(username, password)
            smtp.sendmail(sender, [to_email], msg.as_string())
        _mail_log(f"send_ok transport=smtp to={to_email!r}")
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        hint = ""
        err = str(exc).lower()
        if "101" in str(exc) or "unreachable" in err or "timed out" in err:
            hint = (
                " | hint=Render free tier blocks outbound SMTP ports 25/465/587. "
                "Set RESEND_API_KEY to send over HTTPS, or upgrade the Render plan."
            )
        _mail_log(f"send_fail transport=smtp type={type(exc).__name__} detail={exc}{hint}")
        raise


def send_otp_email(user, code: str) -> None:
    """Send a 6-digit OTP email (Resend HTTPS preferred)."""
    subject = "Your CyberScan verification code"
    text_body = (
        f"Hello {user.username},\n\n"
        "Your CyberScan verification code is:\n\n"
        f"  {code}\n\n"
        "This code expires in 10 minutes.\n"
        "If you did not create this account, you can ignore this email.\n"
    )
    html_body = render_template(
        "email/otp.html",
        username=user.username,
        code=code,
    )

    timeout = int(current_app.config.get("MAIL_TIMEOUT", 15))
    if _resend_api_key():
        _send_via_resend(
            to_email=user.email,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            timeout=max(timeout, 15),
        )
        return

    _send_via_smtp(
        to_email=user.email,
        sender=_smtp_sender(),
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )


def queue_otp_email(app, user_id: int, code: str) -> None:
    """Send OTP on a daemon thread. Pass plaintext code built before starting."""

    def _worker() -> None:
        with app.app_context():
            from models import User, db as _db

            user = _db.session.get(User, user_id)
            if user is None:
                _mail_log(f"async_skip missing_user_id={user_id}")
                return
            try:
                send_otp_email(user, code)
            except Exception as exc:
                _mail_log(
                    f"async_fail user_id={user_id} type={type(exc).__name__} detail={exc}"
                )

    thread = threading.Thread(
        target=_worker,
        name=f"otp-mail-{user_id}",
        daemon=True,
    )
    thread.start()
    _mail_log(f"async_queued user_id={user_id} kind=otp")


def mail_configured() -> bool:
    """True when Resend API key or Gmail SMTP credentials are available."""
    if _resend_api_key():
        return True

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
