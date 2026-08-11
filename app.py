"""Flask main application for CyberScan."""

import json
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# Load .env BEFORE importing model modules (they read VIRUSTOTAL_API_KEY at import).
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_mail import Mail
from werkzeug.security import check_password_hash, generate_password_hash

from auth_email import (
    build_verification_url,
    confirm_verification_token,
    mail_configured,
    send_verification_email,
)
from model.domain_lookup import inspect_domain
from model.predict import predict_url
from models import Admin, DomainScan, UrlScan, User, db
from admin_routes import admin_bp

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "url-shield-dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cyberscan.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Gmail SMTP — credentials come from .env only
_mail_username = os.environ.get("MAIL_USERNAME", "").strip()
_mail_password = os.environ.get("MAIL_PASSWORD", "").strip().replace(" ", "")
_mail_sender = os.environ.get("MAIL_DEFAULT_SENDER", "").strip() or _mail_username

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = _mail_username
app.config["MAIL_PASSWORD"] = _mail_password
app.config["MAIL_DEFAULT_SENDER"] = _mail_sender or "noreply@cyberscan.local"
def _detect_lan_ip() -> str:
    """Best-effort local Wi‑Fi/LAN IPv4 for phone/tablet testing."""
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


# Base URL for verification emails.
# On Render set APP_BASE_URL=https://your-service.onrender.com
# Locally, if unset, fall back to this PC's LAN IP for device testing.
_app_base = os.environ.get("APP_BASE_URL", "").strip().rstrip("/")
if not _app_base:
    _app_base = f"http://{_detect_lan_ip()}:5000"
app.config["APP_BASE_URL"] = _app_base

db.init_app(app)
mail = Mail(app)
app.register_blueprint(admin_bp)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"

METRICS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "model", "saved", "metrics.json"
)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


with app.app_context():
    db.create_all()


def _load_metrics():
    """Load model metrics for display."""
    try:
        with open(METRICS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0}


def _current_user_id():
    if current_user.is_authenticated:
        return current_user.id
    return None


def _save_url_scan(result: dict) -> None:
    """Persist a URL Scanner result to the url_scans table."""
    label = result.get("label", "Benign")
    stored_result = "Malicious" if label == "Malicious" else "Safe"
    record = UrlScan(
        user_id=_current_user_id(),
        url=result.get("url", ""),
        result=stored_result,
        risk_level=result.get("risk_level", "Safe"),
        confidence=float(result.get("confidence") or 0),
        scan_date=datetime.utcnow(),
    )
    db.session.add(record)
    db.session.commit()


def _save_domain_scan(result: dict) -> None:
    """Persist a Domain Inspector result to the domain_scans table."""
    record = DomainScan(
        user_id=_current_user_id(),
        domain=result.get("domain", ""),
        ip_address=result.get("ip_address"),
        country=result.get("country"),
        organization=result.get("organization"),
        ssl_status=result.get("ssl_status"),
        scan_date=datetime.utcnow(),
    )
    db.session.add(record)
    db.session.commit()


@app.route("/")
def index():
    metrics = _load_metrics()
    return render_template(
        "index.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="home",
    )


@app.route("/scan")
def scan():
    metrics = _load_metrics()
    return render_template(
        "scan.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="scan",
    )


@app.route("/domain", methods=["GET", "POST"])
def domain():
    """Domain Inspector — WHOIS, IP geolocation/org, and SSL status."""
    metrics = _load_metrics()
    domain_query = ""
    error = None
    result = None

    if request.method == "POST":
        domain_query = request.form.get("domain", "").strip()
        if not domain_query:
            error = "Please enter a domain name (for example: example.com)"
        else:
            try:
                result = inspect_domain(domain_query)
                domain_query = result.get("domain", domain_query)
                _save_domain_scan(result)
            except ValueError as exc:
                error = str(exc)
            except Exception as exc:
                error = f"Could not inspect this domain right now: {exc}"

    return render_template(
        "domain.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="domain",
        domain_query=domain_query,
        error=error,
        info_note=None,
        result=result,
    )


@app.route("/history")
def history():
    metrics = _load_metrics()
    recent_scans = []
    recent_domains = []

    if current_user.is_authenticated:
        recent_scans = (
            UrlScan.query.filter_by(user_id=current_user.id)
            .order_by(UrlScan.scan_date.desc())
            .limit(50)
            .all()
        )
        recent_domains = (
            DomainScan.query.filter_by(user_id=current_user.id)
            .order_by(DomainScan.scan_date.desc())
            .limit(50)
            .all()
        )

    return render_template(
        "history.html",
        accuracy=metrics.get("accuracy", 0),
        recent_scans=recent_scans,
        recent_domains=recent_domains,
        active_page="history",
        history_requires_login=not current_user.is_authenticated,
    )


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()
    if not url:
        metrics = _load_metrics()
        return render_template(
            "scan.html",
            error="Please enter a valid URL",
            accuracy=metrics.get("accuracy", 0),
            active_page="scan",
        )

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"VT_DIAG predict_route ENTER url_len={len(url)}", flush=True)

    try:
        result = predict_url(url)
    except ValueError as exc:
        metrics = _load_metrics()
        return render_template(
            "scan.html",
            error=str(exc),
            accuracy=metrics.get("accuracy", 0),
            active_page="scan",
        )

    _save_url_scan(result)

    final_label = result.get("final_label") or result["label"]
    final_is_malicious = bool(
        result.get("final_is_malicious", final_label == "Malicious")
    )

    return render_template(
        "result.html",
        result=result,
        url=result["url"],
        label=result["label"],
        final_label=final_label,
        final_is_malicious=final_is_malicious,
        is_malicious=final_is_malicious,
        confidence=result["confidence"],
        malicious_probability=result["malicious_probability"],
        benign_probability=result["benign_probability"],
        risk_level=result["risk_level"],
        risk_color=result["risk_color"],
        features=result["features"],
        explanation=result["explanation"],
        model_votes=result["model_votes"],
        subtype=result.get("subtype", ""),
        virustotal=result.get("virustotal", {}),
        ml_label=result.get("ml_label", result["label"]),
        verdict_source=result.get("verdict_source", "ml_majority"),
        correction_note=result.get("correction_note", ""),
        vt_unavailable=result.get("vt_unavailable", False),
        accuracy=_load_metrics().get("accuracy", 94.2),
        active_page="scan",
    )


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """JSON API endpoint."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = predict_url(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    _save_url_scan(result)
    return jsonify(result)


@app.route("/stats")
def stats():
    with open(METRICS_PATH, encoding="utf-8") as f:
        metrics = json.load(f)

    total = metrics.get("dataset_size", metrics.get("total_urls", 0))
    # 80/20 split used in training
    train_samples = metrics.get("train_samples", int(total * 0.8) if total else 0)
    test_samples = metrics.get("test_samples", int(total * 0.2) if total else 0)

    return render_template(
        "stats.html",
        metrics=metrics,
        accuracy=metrics.get("accuracy", 0),
        precision=metrics.get("precision", 0),
        recall=metrics.get("recall", 0),
        f1=metrics.get("f1", 0),
        confusion_matrix=metrics.get("confusion_matrix", [[0, 0], [0, 0]]),
        total_urls=total,
        train_samples=train_samples,
        test_samples=test_samples,
        active_page="stats",
    )


@app.route("/about")
def about():
    metrics = _load_metrics()
    return render_template(
        "about.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="about",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    metrics = _load_metrics()

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None
    success = request.args.get("success")
    verify_url = request.args.get("verify_url")
    show_resend = False
    form_username = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        form_username = username

        user = User.query.filter_by(username=username).first()
        if user is None or not check_password_hash(user.password, password):
            error = "Invalid username or password."
        elif not user.is_verified:
            error = (
                "Please verify your email before logging in. "
                "Use Resend below, then click Verify in this browser "
                "(opening the email link on your phone will not work with localhost)."
            )
            show_resend = True
            verify_url = build_verification_url(user)
        else:
            login_user(user)
            return redirect(url_for("index"))

    return render_template(
        "login.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="login",
        error=error,
        success=success,
        auth_mode="login",
        show_resend=show_resend,
        form_username=form_username,
        verify_url=verify_url,
    )


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    """Resend the email verification link for an unverified account."""
    metrics = _load_metrics()

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = User.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password, password):
        return render_template(
            "login.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="login",
            error="Invalid username or password.",
            success=None,
            auth_mode="login",
            show_resend=False,
            form_username=username,
        )

    if user.is_verified:
        return redirect(
            url_for(
                "login",
                success="This account is already verified. You can log in.",
            )
        )

    if not mail_configured():
        return render_template(
            "login.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="login",
            error="Email is not configured. Check MAIL settings in .env.",
            success=None,
            auth_mode="login",
            show_resend=True,
            form_username=username,
        )

    try:
        verify_url = send_verification_email(mail, user)
    except Exception:
        return render_template(
            "login.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="login",
            error=(
                "Could not send the verification email. "
                "Check your Gmail App Password and spam folder settings."
            ),
            success=None,
            auth_mode="login",
            show_resend=True,
            form_username=username,
            verify_url=None,
        )

    return redirect(
        url_for(
            "login",
            success=(
                f"Verification email sent to {user.email}. "
                "Prefer the Verify button below (same computer as the app)."
            ),
            verify_url=verify_url,
        )
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    metrics = _load_metrics()

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            error = "Please fill in username, email, and password."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif User.query.filter_by(username=username).first():
            error = "That username is already taken."
        elif User.query.filter_by(email=email).first():
            error = "That email is already registered."
        else:
            if not mail_configured():
                error = (
                    "Email is not configured yet. Add MAIL_USERNAME and "
                    "MAIL_PASSWORD to your .env file, then try again."
                )
            else:
                user = User(
                    username=username,
                    email=email,
                    password=generate_password_hash(password),
                    is_verified=False,
                )
                db.session.add(user)
                db.session.commit()
                try:
                    verify_url = send_verification_email(mail, user)
                except Exception:
                    db.session.delete(user)
                    db.session.commit()
                    error = (
                        "Account was not created because the verification email "
                        "could not be sent. Check your Gmail App Password settings."
                    )
                else:
                    return redirect(
                        url_for(
                            "login",
                            success=(
                                "Account created. Click Verify in this browser below "
                                "(phone email links to localhost will not work)."
                            ),
                            verify_url=verify_url,
                        )
                    )

    return render_template(
        "login.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="login",
        error=error,
        success=None,
        auth_mode="register",
    )


@app.route("/verify/<token>")
def verify_email(token):
    metrics = _load_metrics()
    email = confirm_verification_token(token)
    if not email:
        return render_template(
            "login.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="login",
            error="This verification link is invalid or has expired.",
            success=None,
            auth_mode="login",
        )

    user = User.query.filter_by(email=email).first()
    if user is None:
        return render_template(
            "login.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="login",
            error="No account was found for this verification link.",
            success=None,
            auth_mode="login",
        )

    if not user.is_verified:
        user.is_verified = True
        db.session.commit()

    return redirect(
        url_for(
            "login",
            success="Your email has been verified. You can log in now.",
        )
    )


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/ping")
def ping():
    """Simple reachability check for phone/tablet LAN testing."""
    return jsonify(
        {
            "ok": True,
            "app_base_url": app.config.get("APP_BASE_URL"),
            "message": "CyberScan is reachable from this device.",
        }
    )


if __name__ == "__main__":
    # Local/dev only. Production (Render) uses: gunicorn app:app
    port = int(os.environ.get("PORT", 5000))
    lan_url = app.config.get("APP_BASE_URL", f"http://127.0.0.1:{port}")
    print("\n=== CyberScan ===")
    print(f"Local:   http://127.0.0.1:{port}")
    print(f"LAN/App: {lan_url}")
    print("=================\n")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
    )
