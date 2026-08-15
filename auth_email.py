"""Email verification helpers for CyberScan auth (OTP via Brevo / Resend / SMTP)."""

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
from email.utils import parseaddr

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

# Resend sandbox (only delivers to the Resend account email).
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
    """Return True only for a non-expired 6-digit code matching otp_hash."""
    code = (code or "").strip()
    if not code.isdigit() or len(code) != 6:
        return False
    if not user.otp_hash or not user.otp_expires_at:
        return False
    if bool(getattr(user, "is_verified", False)):
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


def _cfg(key: str, default: str = "") -> str:
    try:
        value = current_app.config.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    except RuntimeError:
        pass
    return os.environ.get(key, default).strip()


def _brevo_api_key() -> str:
    return _cfg("BREVO_API_KEY")


def _resend_api_key() -> str:
    return _cfg("RESEND_API_KEY")


def _parse_from_address(raw: str) -> tuple[str, str]:
    """Return (display_name, email) from 'Name <email>' or bare email."""
    name, email = parseaddr((raw or "").strip())
    if not email and raw and "@" in raw:
        email = raw.strip()
    return (name or "CyberScan").strip(), email.strip()


def _smtp_sender() -> str:
    """From address for local SMTP only."""
    return (
        _cfg("MAIL_DEFAULT_SENDER")
        or _cfg("MAIL_USERNAME")
        or "noreply@cyberscan.local"
    )


def _brevo_sender() -> dict:
    """
    Brevo sender object. Use a sender email verified in the Brevo dashboard
    (Senders → Add a sender). Gmail is fine after Brevo email verification.
    """
    raw = (
        _cfg("BREVO_FROM")
        or _cfg("MAIL_DEFAULT_SENDER")
        or _cfg("MAIL_USERNAME")
    )
    name, email = _parse_from_address(raw)
    if not email or "@" not in email:
        raise RuntimeError(
            "BREVO_FROM (or MAIL_DEFAULT_SENDER / MAIL_USERNAME) must be a "
            "verified sender email in your Brevo account."
        )
    if _cfg("BREVO_FROM_NAME"):
        name = _cfg("BREVO_FROM_NAME")
    return {"name": name or "CyberScan", "email": email}


def _resend_from() -> str:
    """From address for Resend HTTPS (sandbox unless custom verified domain)."""
    configured = _cfg("RESEND_FROM")
    if configured:
        _, bare = _parse_from_address(configured)
        bare_l = bare.lower()
        if bare_l.endswith("@gmail.com") or bare_l.endswith("@googlemail.com"):
            _mail_log(
                f"from_override reason=gmail_unverified configured={configured!r} "
                f"using={RESEND_SANDBOX_FROM!r}"
            )
            return RESEND_SANDBOX_FROM
        return configured
    return RESEND_SANDBOX_FROM


def _send_via_brevo(
    *,
    to_email: str,
    to_name: str,
    subject: str,
    text_body: str,
    html_body: str,
    timeout: int,
) -> None:
    api_key = _brevo_api_key()
    sender = _brevo_sender()
    _mail_log(
        f"send_start transport=brevo to={to_email!r} "
        f"from={sender.get('email')!r} name={sender.get('name')!r}"
    )
    resp = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "api-key": api_key,
            "accept": "application/json",
            "content-type": "application/json",
        },
        json={
            "sender": sender,
            "to": [{"email": to_email, "name": (to_name or to_email)[:70]}],
            "subject": subject,
            "htmlContent": html_body,
            "textContent": text_body,
        },
        timeout=timeout,
    )
    if resp.status_code >= 400:
        detail = resp.text[:500]
        _mail_log(f"send_fail transport=brevo status={resp.status_code} detail={detail}")
        raise RuntimeError(f"Brevo API error {resp.status_code}: {detail}")
    message_id = ""
    try:
        message_id = resp.json().get("messageId") or ""
    except Exception:
        pass
    _mail_log(f"send_ok transport=brevo to={to_email!r} id={message_id}")


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
    username = _cfg("MAIL_USERNAME")
    password = _cfg("MAIL_PASSWORD").replace(" ", "")
    try:
        server = current_app.config.get("MAIL_SERVER", "smtp.gmail.com")
        port = int(current_app.config.get("MAIL_PORT", 587))
        use_tls = bool(current_app.config.get("MAIL_USE_TLS", True))
        timeout = int(current_app.config.get("MAIL_TIMEOUT", 10))
    except RuntimeError:
        server, port, use_tls, timeout = "smtp.gmail.com", 587, True, 10

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
                " | hint=Render free tier blocks outbound SMTP. "
                "Set BREVO_API_KEY to send over HTTPS."
            )
        _mail_log(f"send_fail transport=smtp type={type(exc).__name__} detail={exc}{hint}")
        raise


def send_otp_email(user, code: str) -> None:
    """Send a 6-digit OTP email (Brevo HTTPS preferred)."""
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

    timeout = int(_cfg("MAIL_TIMEOUT") or "15")
    timeout = max(timeout, 15)

    if _brevo_api_key():
        _send_via_brevo(
            to_email=user.email,
            to_name=user.username,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            timeout=timeout,
        )
        return

    if _resend_api_key():
        _send_via_resend(
            to_email=user.email,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            timeout=timeout,
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
    """True when Brevo, Resend, or local SMTP credentials are available."""
    if _brevo_api_key() or _resend_api_key():
        return True

    username = _cfg("MAIL_USERNAME")
    password = _cfg("MAIL_PASSWORD").replace(" ", "")
    return bool(username and password)
