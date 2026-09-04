"""Flask main application for CyberScan."""

import json
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# Load .env BEFORE importing model modules (they read VIRUSTOTAL_API_KEY at import).
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_mail import Mail
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from auth_email import (
    OTP_RESEND_COOLDOWN_SECONDS,
    assign_user_otp,
    auth_log,
    clear_user_otp,
    generate_otp_code,
    mail_configured,
    mask_email,
    queue_otp_email,
    resend_cooldown_remaining,
    verify_user_otp,
)
from models import Admin, DnsScan, DomainScan, UrlScan, User, db
from admin_routes import admin_bp
from model.dns_examples import get_dns_examples
from model.predict_dns import predict_dns_query
from model.domain_lookup import inspect_domain
from model.predict import predict_url

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "url-shield-dev-secret-key")

# Prefer DATABASE_URL (Supabase / any Postgres). Fall back to local SQLite for development.
_database_url = (os.environ.get("DATABASE_URL") or "").strip()
if _database_url.startswith("postgres://"):
    # SQLAlchemy requires the postgresql:// scheme (some hosts still emit postgres://).
    _database_url = _database_url.replace("postgres://", "postgresql://", 1)

if _database_url:
    # Supabase (and most hosted Postgres) require SSL from external hosts like Render.
    if "sslmode=" not in _database_url.lower():
        _database_url += ("&" if "?" in _database_url else "?") + "sslmode=require"
    app.config["SQLALCHEMY_DATABASE_URI"] = _database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cyberscan.db"
    # Fail fast if local SQLite is locked instead of waiting forever.
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {"timeout": 10},
    }

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
# Fail fast on Render if Gmail SMTP is slow/blocked (Flask-Mail has no timeout).
app.config["MAIL_TIMEOUT"] = int(os.environ.get("MAIL_TIMEOUT", "10"))
# Brevo (preferred on Render) — verify your Gmail as a sender in Brevo dashboard.
app.config["BREVO_API_KEY"] = os.environ.get("BREVO_API_KEY", "").strip()
app.config["BREVO_FROM"] = os.environ.get("BREVO_FROM", "").strip()
app.config["BREVO_FROM_NAME"] = os.environ.get("BREVO_FROM_NAME", "").strip() or "CyberScan"
# Optional Resend fallback (sandbox only delivers to your Resend account email).
app.config["RESEND_API_KEY"] = os.environ.get("RESEND_API_KEY", "").strip()
app.config["RESEND_FROM"] = os.environ.get("RESEND_FROM", "").strip() or "CyberScan <onboarding@resend.dev>"


def _detect_lan_ip() -> str:
    """Best-effort local Wi‑Fi/LAN IPv4 for phone/tablet testing (local only)."""
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


# Optional public site URL (legacy / diagnostics). OTP emails no longer embed links.
app.config["APP_BASE_URL"] = os.environ.get("APP_BASE_URL", "").strip().rstrip("/")

# Render terminates TLS at a proxy — keep ProxyFix for correct request URLs.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

db.init_app(app)
mail = Mail(app)
app.register_blueprint(admin_bp)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"

METRICS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "model", "saved", "metrics.json"
)
DNS_METRICS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "model", "saved", "dns_metrics.json"
)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.before_request
def _reject_unverified_sessions():
    """Never treat an unverified account as logged-in."""
    if not current_user.is_authenticated:
        return None
    # Admin blueprint uses a separate session; skip those paths.
    if request.endpoint and str(request.endpoint).startswith("admin."):
        return None
    if bool(getattr(current_user, "is_verified", False)):
        return None
    auth_log(f"unverified_session_cleared user_id={getattr(current_user, 'id', None)}")
    logout_user()
    session.pop("welcome_message", None)
    # Keep pending OTP session if present so they can finish verify.
    return None


def _ensure_user_otp_columns() -> None:
    """Add OTP / settings columns on existing Postgres/SQLite DBs (create_all won't alter)."""
    from sqlalchemy import inspect, text

    try:
        inspector = inspect(db.engine)
        if "users" not in inspector.get_table_names():
            return
        existing = {col["name"] for col in inspector.get_columns("users")}
    except Exception as exc:
        auth_log(f"otp_schema_inspect_fail detail={exc}")
        return

    dialect = db.engine.dialect.name
    if dialect == "postgresql":
        bool_false = "BOOLEAN DEFAULT FALSE NOT NULL"
        theme_col = "VARCHAR(16) DEFAULT 'dark' NOT NULL"
    else:
        bool_false = "BOOLEAN DEFAULT 0 NOT NULL"
        theme_col = "VARCHAR(16) DEFAULT 'dark' NOT NULL"

    needed = {
        "otp_hash": "VARCHAR(255)",
        "otp_expires_at": "TIMESTAMP",
        "otp_last_sent_at": "TIMESTAMP",
        "theme": theme_col,
        "notify_scan_email": bool_false,
    }
    for name, sql_type in needed.items():
        if name in existing:
            continue
        try:
            if dialect == "postgresql":
                db.session.execute(
                    text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {name} {sql_type}")
                )
            else:
                db.session.execute(text(f"ALTER TABLE users ADD COLUMN {name} {sql_type}"))
            db.session.commit()
            auth_log(f"user_schema_added column={name}")
        except Exception as exc:
            db.session.rollback()
            auth_log(f"user_schema_add_fail column={name} detail={exc}")


with app.app_context():
    db.create_all()
    _ensure_user_otp_columns()


@app.context_processor
def _inject_user_theme():
    theme = "dark"
    if current_user.is_authenticated:
        theme = getattr(current_user, "theme", None) or "dark"
        if theme not in ("dark", "light"):
            theme = "dark"
    return {"user_theme": theme}


def _load_metrics():
    """Load model metrics for display."""
    try:
        with open(METRICS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0}


def _pct(value) -> float:
    """Normalize a metric that may be stored as 0–1 or already as percent."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return 0.0
    return n * 100.0 if n <= 1.0 else n


def _load_dns_metrics():
    """Load DNS module metrics with honest evaluation caveats."""
    empty = {
        "accuracy": 0,
        "precision": 0,
        "recall": 0,
        "f1": 0,
        "dataset_size": 0,
        "train_samples": 0,
        "test_samples": 0,
        "feature_count": 18,
        "dataset_caveat": "",
        "evaluation_limitations": {},
        "confusion_matrix": [[0, 0], [0, 0]],
        "feature_columns": [],
    }
    try:
        with open(DNS_METRICS_PATH, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return empty

    limits = raw.get("evaluation_limitations") or {}
    features = raw.get("feature_columns") or []
    return {
        "accuracy": round(_pct(raw.get("accuracy", 0)), 2),
        "precision": round(_pct(raw.get("precision", 0)), 2),
        "recall": round(_pct(raw.get("recall", 0)), 2),
        "f1": round(_pct(raw.get("f1", 0)), 2),
        "dataset_size": raw.get("dataset_size", 0),
        "train_samples": raw.get("train_samples", 0),
        "test_samples": raw.get("test_samples", 0),
        "feature_count": len(features) or 18,
        "dataset_caveat": raw.get("dataset_caveat", ""),
        "evaluation_limitations": limits,
        "confusion_matrix": raw.get("confusion_matrix", [[0, 0], [0, 0]]),
        "feature_columns": features,
        "length_only_baseline_accuracy": round(
            _pct(limits.get("length_only_baseline_accuracy", 0)), 2
        ),
        "mean_loto_malicious_recall": round(
            _pct(limits.get("mean_leave_one_tool_out_malicious_recall", 0)), 1
        ),
        "risk_level": limits.get("risk_level", "HIGH"),
        "limitations_summary": limits.get("summary", ""),
    }


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


def _save_dns_scan(result: dict) -> None:
    """Persist a DNS query-name scan to dns_scans."""
    gen = result.get("generalization") or {}
    record = DnsScan(
        user_id=_current_user_id(),
        query_name=result.get("query_name", ""),
        result=result.get("result")
        or ("Malicious" if result.get("label") == "Malicious" else "Safe"),
        risk_level=result.get("risk_level", "Unknown"),
        confidence=float(result.get("confidence") or 0),
        generalization_level=gen.get("level"),
        scan_date=datetime.utcnow(),
    )
    db.session.add(record)
    db.session.commit()


@app.route("/")
def index():
    metrics = _load_metrics()
    recent_items = []

    if current_user.is_authenticated:
        url_scans = (
            UrlScan.query.filter_by(user_id=current_user.id)
            .order_by(UrlScan.scan_date.desc())
            .limit(8)
            .all()
        )
        domain_scans = (
            DomainScan.query.filter_by(user_id=current_user.id)
            .order_by(DomainScan.scan_date.desc())
            .limit(8)
            .all()
        )
        for scan in url_scans:
            recent_items.append(
                {
                    "target": scan.url,
                    "type": "URL",
                    "result": scan.result,
                    "date": scan.scan_date,
                }
            )
        for item in domain_scans:
            recent_items.append(
                {
                    "target": item.domain,
                    "type": "Domain",
                    "result": item.ssl_status or "Could not verify",
                    "date": item.scan_date,
                }
            )
        recent_items.sort(
            key=lambda row: row["date"] or datetime.min,
            reverse=True,
        )
        recent_items = recent_items[:6]

    return render_template(
        "index.html",
        accuracy=metrics.get("accuracy", 0),
        precision=metrics.get("precision", 0),
        recall=metrics.get("recall", 0),
        f1=metrics.get("f1", 0),
        recent_items=recent_items,
        welcome_message=session.pop("welcome_message", None),
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


@app.route("/dns-scan")
def dns_scan():
    """DNS query-name classifier (offline ML on synthetic Daumel data)."""
    metrics = _load_metrics()
    return render_template(
        "dns_scan.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="dns_scan",
        examples=get_dns_examples(),
        error=None,
        prefill=request.args.get("q", "").strip(),
    )


@app.route("/dns-predict", methods=["POST"])
def dns_predict():
    metrics = _load_metrics()
    query = (request.form.get("query") or request.form.get("q") or "").strip()
    if not query:
        return render_template(
            "dns_scan.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="dns_scan",
            examples=get_dns_examples(),
            error="Please enter a DNS query name (for example: example.com).",
            prefill="",
        )
    try:
        result = predict_dns_query(query)
        _save_dns_scan(result)
    except ValueError as exc:
        return render_template(
            "dns_scan.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="dns_scan",
            examples=get_dns_examples(),
            error=str(exc),
            prefill=query,
        )
    except Exception as exc:
        return render_template(
            "dns_scan.html",
            accuracy=metrics.get("accuracy", 0),
            active_page="dns_scan",
            examples=get_dns_examples(),
            error=f"DNS classification failed: {exc}",
            prefill=query,
        )

    return render_template(
        "dns_result.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="dns_scan",
        **result,
    )


@app.route("/dns-limitations")
def dns_limitations():
    """Learn-more page: synthetic data, length baseline, LOOT highlights."""
    metrics = _load_metrics()
    loot = []
    length_baseline = None
    risk = "HIGH"
    try:
        with open(
            BASE_DIR / "model" / "saved" / "dns_leakage_report.json",
            encoding="utf-8",
        ) as f:
            report = json.load(f)
        loot = report.get("leave_one_tool_out") or []
        risk = report.get("risk_level", risk)
        for row in report.get("single_feature_rf_test_accuracy") or []:
            if row.get("feature") == "dns_domain_name_length":
                length_baseline = row.get("accuracy")
                break
    except (OSError, json.JSONDecodeError):
        pass

    return render_template(
        "dns_limitations.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="dns_scan",
        loot=loot,
        length_baseline=length_baseline,
        risk_level=risk,
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
    recent_dns = []
    combined_history = []

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
        recent_dns = (
            DnsScan.query.filter_by(user_id=current_user.id)
            .order_by(DnsScan.scan_date.desc())
            .limit(50)
            .all()
        )

        for scan in recent_scans:
            combined_history.append(
                {
                    "type": "URL",
                    "type_key": "url",
                    "target": scan.url,
                    "result": scan.result,
                    "detail": scan.risk_level or "—",
                    "date": scan.scan_date,
                }
            )
        for item in recent_domains:
            ssl = item.ssl_status or "Could not verify"
            combined_history.append(
                {
                    "type": "Domain",
                    "type_key": "domain",
                    "target": item.domain,
                    "result": ssl,
                    "detail": item.ip_address or item.country or "—",
                    "date": item.scan_date,
                }
            )
        for item in recent_dns:
            combined_history.append(
                {
                    "type": "DNS",
                    "type_key": "dns",
                    "target": item.query_name,
                    "result": item.result,
                    "detail": item.risk_level or "—",
                    "date": item.scan_date,
                }
            )

        combined_history.sort(
            key=lambda row: row["date"] or datetime.min,
            reverse=True,
        )
        combined_history = combined_history[:100]

    return render_template(
        "history.html",
        accuracy=metrics.get("accuracy", 0),
        recent_scans=recent_scans,
        recent_domains=recent_domains,
        recent_dns=recent_dns,
        combined_history=combined_history,
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
    dns_metrics = _load_dns_metrics()

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
        dns_metrics=dns_metrics,
        dns_cm=dns_metrics.get("confusion_matrix", [[0, 0], [0, 0]]),
        active_page="stats",
    )


@app.route("/about")
def about():
    from model.dns_features import DNS_FEATURE_COLUMNS

    metrics = _load_metrics()
    return render_template(
        "about.html",
        accuracy=metrics.get("accuracy", 0),
        dns_feature_columns=DNS_FEATURE_COLUMNS,
        active_page="about",
    )


def _auth_page(
    *,
    auth_mode="login",
    error=None,
    success=None,
    form_username="",
    masked_email=None,
    resend_cooldown=0,
):
    metrics = _load_metrics()
    return render_template(
        "login.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="login",
        error=error,
        success=success,
        auth_mode=auth_mode,
        form_username=form_username,
        masked_email=masked_email,
        resend_cooldown=int(resend_cooldown or 0),
        otp_resend_window=OTP_RESEND_COOLDOWN_SECONDS,
    )


def _issue_and_queue_otp(user, *, force: bool = False) -> int:
    """
    Create a new OTP, persist hash, queue email.
    Returns remaining cooldown seconds if blocked (and force is False), else 0.
    """
    remaining = resend_cooldown_remaining(user)
    if remaining > 0 and not force:
        return remaining

    code = generate_otp_code()
    assign_user_otp(user, code)
    db.session.commit()
    queue_otp_email(app, user.id, code)
    auth_log(f"otp_queued user_id={user.id}")
    return OTP_RESEND_COOLDOWN_SECONDS


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None
    success = request.args.get("success")
    form_username = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        form_username = username
        auth_log(f"login_start username={username!r}")

        try:
            user = User.query.filter_by(username=username).first()
            if user is None or not check_password_hash(user.password, password):
                auth_log(f"login_fail reason=bad_credentials username={username!r}")
                error = "Invalid username or password."
            elif not user.is_verified:
                auth_log(f"login_unverified user_id={user.id}")
                session["pending_user_id"] = user.id
                if not mail_configured():
                    return _auth_page(
                        auth_mode="otp",
                        error="Email is not configured. Add BREVO_API_KEY on Render.",
                        masked_email=mask_email(user.email),
                        resend_cooldown=resend_cooldown_remaining(user),
                    )
                remaining = resend_cooldown_remaining(user)
                if remaining > 0:
                    return _auth_page(
                        auth_mode="otp",
                        success="Enter the verification code sent to your email.",
                        masked_email=mask_email(user.email),
                        resend_cooldown=remaining,
                    )
                _issue_and_queue_otp(user, force=True)
                return _auth_page(
                    auth_mode="otp",
                    success="Enter the verification code sent to your email.",
                    masked_email=mask_email(user.email),
                    resend_cooldown=OTP_RESEND_COOLDOWN_SECONDS,
                )
            else:
                # Verified accounts only — never login_user for unverified users.
                if not login_user(user):
                    auth_log(f"login_rejected_inactive user_id={user.id}")
                    error = "Please verify your email before signing in."
                else:
                    session.pop("pending_user_id", None)
                    session["welcome_message"] = f"Welcome back, {user.username}!"
                    auth_log(f"login_ok user_id={user.id}")
                    return redirect(url_for("index"))
        except Exception as exc:
            auth_log(f"login_error type={type(exc).__name__} detail={exc}")
            error = "Login failed due to a server error. Please try again."

    return _auth_page(
        auth_mode="login",
        error=error,
        success=success,
        form_username=form_username,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "GET":
        return _auth_page(auth_mode="register")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    auth_log(f"register_start username={username!r} email={email!r}")

    error = None
    if not username or not email or not password or not confirm:
        error = "Please fill in all fields."
    elif len(password) < 6:
        error = "Password must be at least 6 characters."
    elif password != confirm:
        error = "Passwords do not match."
    elif User.query.filter_by(username=username).first():
        error = "That username is already taken."
    elif User.query.filter_by(email=email).first():
        error = "That email is already registered."
    elif not mail_configured():
        error = (
            "Email is not configured yet. On Render add BREVO_API_KEY "
            "(and verify your sender email in Brevo). "
            "Locally you can use MAIL_USERNAME and MAIL_PASSWORD."
        )
    else:
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            is_verified=False,
        )
        db.session.add(user)
        db.session.flush()
        # Hard guarantee: registration must never mark the account verified.
        user.is_verified = False
        db.session.commit()
        db.session.refresh(user)
        if user.is_verified:
            auth_log(f"register_verified_anomaly user_id={user.id} forcing_false")
            user.is_verified = False
            db.session.commit()
        session["pending_user_id"] = user.id
        _issue_and_queue_otp(user, force=True)
        # Re-assert after OTP issue/commit — OTP helpers must not flip verified.
        if user.is_verified:
            auth_log(f"otp_issue_verified_anomaly user_id={user.id} forcing_false")
            user.is_verified = False
            db.session.commit()
        auth_log(
            f"register_ok user_id={user.id} otp_queued=1 is_verified={user.is_verified}"
        )
        return _auth_page(
            auth_mode="otp",
            success="Account created. Check your email for a 6-digit code.",
            masked_email=mask_email(user.email),
            resend_cooldown=OTP_RESEND_COOLDOWN_SECONDS,
        )

    return _auth_page(auth_mode="register", error=error, form_username=username)


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    pending_id = session.get("pending_user_id")
    code = request.form.get("otp_code", "").strip()
    auth_log(f"otp_verify_start pending_user_id={pending_id!r}")

    if not pending_id:
        return _auth_page(
            auth_mode="login",
            error="Your verification session expired. Please sign in again.",
        )

    user = db.session.get(User, int(pending_id))
    if user is None:
        session.pop("pending_user_id", None)
        return _auth_page(
            auth_mode="login",
            error="Account not found. Please register again.",
        )

    # Already verified earlier — do not re-run OTP; treat as returning login.
    if user.is_verified:
        clear_user_otp(user)
        db.session.commit()
        login_user(user)
        session.pop("pending_user_id", None)
        session["welcome_message"] = f"Welcome back, {user.username}!"
        return redirect(url_for("index"))

    # ONLY place a new account may become verified: correct, non-expired OTP.
    if not verify_user_otp(user, code):
        auth_log(f"otp_verify_fail user_id={user.id}")
        return _auth_page(
            auth_mode="otp",
            error="Invalid or expired code. Try again or resend a new code.",
            masked_email=mask_email(user.email),
            resend_cooldown=resend_cooldown_remaining(user),
        )

    user.is_verified = True
    clear_user_otp(user)
    db.session.commit()
    # login_user respects User.is_active (== is_verified)
    if not login_user(user):
        auth_log(f"otp_verify_login_rejected user_id={user.id}")
        return _auth_page(
            auth_mode="login",
            error="Verification saved but sign-in failed. Please sign in.",
        )
    session.pop("pending_user_id", None)
    session["welcome_message"] = f"Welcome, {user.username}!"
    auth_log(f"otp_verify_ok user_id={user.id} is_verified={user.is_verified}")
    return redirect(url_for("index"))


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    pending_id = session.get("pending_user_id")
    auth_log(f"otp_resend_start pending_user_id={pending_id!r}")

    if not pending_id:
        return _auth_page(
            auth_mode="login",
            error="Your verification session expired. Please sign in again.",
        )

    user = db.session.get(User, int(pending_id))
    if user is None:
        session.pop("pending_user_id", None)
        return _auth_page(auth_mode="login", error="Account not found.")

    if user.is_verified:
        return redirect(url_for("login", success="This account is already verified."))

    if not mail_configured():
        return _auth_page(
            auth_mode="otp",
            error="Email is not configured. Add BREVO_API_KEY on Render.",
            masked_email=mask_email(user.email),
            resend_cooldown=resend_cooldown_remaining(user),
        )

    remaining = resend_cooldown_remaining(user)
    if remaining > 0:
        return _auth_page(
            auth_mode="otp",
            error=f"Please wait {remaining}s before requesting another code.",
            masked_email=mask_email(user.email),
            resend_cooldown=remaining,
        )

    _issue_and_queue_otp(user, force=True)
    return _auth_page(
        auth_mode="otp",
        success="A new verification code was sent.",
        masked_email=mask_email(user.email),
        resend_cooldown=OTP_RESEND_COOLDOWN_SECONDS,
    )


@app.route("/verify/<token>")
def verify_email(token):
    """Legacy link-based verify — OTP replaced this flow."""
    return redirect(
        url_for(
            "login",
            success=(
                "Email links are no longer used. Sign in and enter the 6-digit "
                "code from your email instead."
            ),
        )
    )


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


def _settings_page(**extra):
    metrics = _load_metrics()
    return render_template(
        "settings.html",
        accuracy=metrics.get("accuracy", 0),
        active_page="settings",
        theme=getattr(current_user, "theme", None) or "dark",
        notify_scan_email=bool(getattr(current_user, "notify_scan_email", False)),
        **extra,
    )


def _require_current_password(password: str) -> str | None:
    if not password:
        return "Current password is required."
    if not check_password_hash(current_user.password, password):
        return "Current password is incorrect."
    return None


@app.route("/settings")
@login_required
def settings():
    return _settings_page()


@app.route("/settings/username", methods=["POST"])
@login_required
def settings_username():
    new_username = (request.form.get("username") or "").strip()
    current_password = request.form.get("current_password") or ""
    err = _require_current_password(current_password)
    if err:
        flash(err, "error")
        return redirect(url_for("settings"))
    if not new_username or len(new_username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return redirect(url_for("settings"))
    if new_username == current_user.username:
        flash("That is already your username.", "error")
        return redirect(url_for("settings"))
    taken = User.query.filter(
        User.username == new_username, User.id != current_user.id
    ).first()
    if taken:
        flash("That username is already taken.", "error")
        return redirect(url_for("settings"))
    current_user.username = new_username
    db.session.commit()
    flash("Username updated.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/email", methods=["POST"])
@login_required
def settings_email():
    new_email = (request.form.get("email") or "").strip().lower()
    current_password = request.form.get("current_password") or ""
    err = _require_current_password(current_password)
    if err:
        flash(err, "error")
        return redirect(url_for("settings"))
    if not new_email or "@" not in new_email:
        flash("Enter a valid email address.", "error")
        return redirect(url_for("settings"))
    if new_email == (current_user.email or "").lower():
        flash("That is already your email.", "error")
        return redirect(url_for("settings"))
    taken = User.query.filter(
        User.email == new_email, User.id != current_user.id
    ).first()
    if taken:
        flash("That email is already in use.", "error")
        return redirect(url_for("settings"))
    if not mail_configured():
        flash("Email is not configured. Add BREVO_API_KEY on Render.", "error")
        return redirect(url_for("settings"))

    current_user.email = new_email
    current_user.is_verified = False
    db.session.commit()
    user_id = current_user.id
    logout_user()
    session["pending_user_id"] = user_id
    user = db.session.get(User, user_id)
    _issue_and_queue_otp(user, force=True)
    flash(
        "Email updated. Enter the verification code sent to your new address.",
        "success",
    )
    return _auth_page(
        auth_mode="otp",
        success="Enter the verification code sent to your new email.",
        masked_email=mask_email(new_email),
        resend_cooldown=resend_cooldown_remaining(user),
    )


@app.route("/settings/password", methods=["POST"])
@login_required
def settings_password():
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""
    err = _require_current_password(current_password)
    if err:
        flash(err, "error")
        return redirect(url_for("settings"))
    if len(new_password) < 6:
        flash("New password must be at least 6 characters.", "error")
        return redirect(url_for("settings"))
    if new_password != confirm:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("settings"))
    current_user.password = generate_password_hash(new_password)
    db.session.commit()
    flash("Password updated.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/appearance", methods=["POST"])
@login_required
def settings_appearance():
    theme = (request.form.get("theme") or "dark").strip().lower()
    if theme not in ("dark", "light"):
        theme = "dark"
    current_user.theme = theme
    db.session.commit()
    flash("Appearance updated.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/notifications", methods=["POST"])
@login_required
def settings_notifications():
    enabled = request.form.get("notify_scan_email") in ("1", "true", "on", "yes")
    current_user.notify_scan_email = enabled
    db.session.commit()
    flash("Notification preference saved.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/delete", methods=["POST"])
@login_required
def settings_delete():
    confirm = (request.form.get("confirm_text") or "").strip()
    current_password = request.form.get("current_password") or ""
    err = _require_current_password(current_password)
    if err:
        flash(err, "error")
        return redirect(url_for("settings"))
    expected_user = current_user.username
    if confirm != expected_user and confirm.upper() != "DELETE":
        flash('Type your username or "DELETE" to confirm account deletion.', "error")
        return redirect(url_for("settings"))

    user_id = current_user.id
    username = current_user.username
    UrlScan.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    DomainScan.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    DnsScan.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    user = db.session.get(User, user_id)
    logout_user()
    if user is not None:
        db.session.delete(user)
    db.session.commit()
    flash(f"Account '{username}' and all associated scans were permanently deleted.", "success")
    return redirect(url_for("index"))


@app.route("/ping")
def ping():
    """Simple reachability check for phone/tablet LAN testing."""
    return jsonify(
        {
            "ok": True,
            "app_base_url": app.config.get("APP_BASE_URL") or None,
            "host": request.host,
            "message": "CyberScan is reachable from this device.",
        }
    )


if __name__ == "__main__":
    # Local/dev only. Production (Render) uses: gunicorn app:app
    port = int(os.environ.get("PORT", 5000))
    lan_url = app.config.get("APP_BASE_URL") or f"http://{_detect_lan_ip()}:{port}"
    print("\n=== CyberScan ===")
    print(f"Local:   http://127.0.0.1:{port}")
    print(f"LAN/App: {lan_url}")
    print("=================\n")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
    )
