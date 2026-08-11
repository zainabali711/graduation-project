"""Admin dashboard routes — separate from Flask-Login user auth."""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash

from admin_auth import admin_required, current_admin, login_admin, logout_admin
from models import Admin, DomainScan, UrlScan, User, db

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

PER_PAGE = 20


def _paginate(query, page: int, per_page: int = PER_PAGE):
    page = max(page or 1, 1)
    return query.paginate(page=page, per_page=per_page, error_out=False)


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_admin() is not None:
        return redirect(url_for("admin.dashboard"))

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        admin = Admin.query.filter_by(username=username).first()
        if admin is None or not check_password_hash(admin.password_hash, password):
            error = "Invalid admin username or password."
        else:
            login_admin(admin)
            return redirect(url_for("admin.dashboard"))

    return render_template("admin/login.html", error=error)


@admin_bp.route("/logout", methods=["POST", "GET"])
@admin_required
def logout():
    logout_admin()
    return redirect(url_for("admin.login"))


@admin_bp.route("/")
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    total_users = User.query.count()
    total_url_scans = UrlScan.query.count()
    total_domain_scans = DomainScan.query.count()

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = (
        UrlScan.query.filter(UrlScan.scan_date >= today_start).count()
        + DomainScan.query.filter(DomainScan.scan_date >= today_start).count()
    )

    malicious_count = UrlScan.query.filter(UrlScan.result == "Malicious").count()
    safe_count = UrlScan.query.filter(UrlScan.result == "Safe").count()
    labeled_total = malicious_count + safe_count
    malicious_pct = round((malicious_count / labeled_total) * 100, 1) if labeled_total else 0.0
    safe_pct = round((safe_count / labeled_total) * 100, 1) if labeled_total else 0.0

    return render_template(
        "admin/dashboard.html",
        admin=current_admin(),
        active_section="dashboard",
        total_users=total_users,
        total_url_scans=total_url_scans,
        total_domain_scans=total_domain_scans,
        scans_today=scans_today,
        malicious_count=malicious_count,
        safe_count=safe_count,
        malicious_pct=malicious_pct,
        safe_pct=safe_pct,
    )


@admin_bp.route("/users")
@admin_required
def users():
    page = request.args.get("page", 1, type=int)
    users_pagination = _paginate(User.query.order_by(User.created_at.desc()), page)
    return render_template(
        "admin/users.html",
        admin=current_admin(),
        active_section="users",
        users_pagination=users_pagination,
    )


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id: int):
    user = db.session.get(User, user_id)
    page = request.args.get("page", 1, type=int) or 1
    if user is None:
        flash("User not found.", "error")
        return redirect(url_for("admin.users", page=page))

    username = user.username
    UrlScan.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    DomainScan.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted user '{username}' and their scan history.", "success")
    return redirect(url_for("admin.users", page=page))


@admin_bp.route("/url-scans")
@admin_required
def url_scans():
    page = request.args.get("page", 1, type=int)
    urls_pagination = _paginate(UrlScan.query.order_by(UrlScan.scan_date.desc()), page)
    return render_template(
        "admin/url_scans.html",
        admin=current_admin(),
        active_section="url_scans",
        urls_pagination=urls_pagination,
    )


@admin_bp.route("/domain-scans")
@admin_required
def domain_scans():
    page = request.args.get("page", 1, type=int)
    domains_pagination = _paginate(
        DomainScan.query.order_by(DomainScan.scan_date.desc()), page
    )
    return render_template(
        "admin/domain_scans.html",
        admin=current_admin(),
        active_section="domain_scans",
        domains_pagination=domains_pagination,
    )
