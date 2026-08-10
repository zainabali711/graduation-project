"""Email verification helpers for CyberScan auth."""

import os

from flask import current_app, render_template, url_for
from flask_mail import Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


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
    """Send a verification email with a signed token link. Returns the verify URL."""
    verify_url = build_verification_url(user)
    sender = current_app.config.get("MAIL_DEFAULT_SENDER") or current_app.config.get(
        "MAIL_USERNAME"
    )

    msg = Message(
        subject="Verify your CyberScan account",
        recipients=[user.email],
        sender=sender,
        body=(
            f"Hello {user.username},\n\n"
            "Thank you for registering with CyberScan.\n"
            "Please verify your email by opening this link on the same computer "
            "where CyberScan is running (or use the Verify button on the login page):\n\n"
            f"{verify_url}\n\n"
            "This link expires in 24 hours.\n\n"
            "If you did not create this account, you can ignore this email.\n"
        ),
        html=render_template(
            "email/verify.html",
            username=user.username,
            verify_url=verify_url,
        ),
    )
    mail.send(msg)
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
