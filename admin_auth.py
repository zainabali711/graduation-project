"""Separate session-based admin authentication (not Flask-Login)."""

from functools import wraps

from flask import redirect, session, url_for

from models import Admin, db

ADMIN_SESSION_ID = "admin_id"
ADMIN_SESSION_NAME = "admin_username"


def login_admin(admin: Admin) -> None:
    session[ADMIN_SESSION_ID] = admin.id
    session[ADMIN_SESSION_NAME] = admin.username
    session.permanent = True


def logout_admin() -> None:
    session.pop(ADMIN_SESSION_ID, None)
    session.pop(ADMIN_SESSION_NAME, None)


def current_admin() -> Admin | None:
    admin_id = session.get(ADMIN_SESSION_ID)
    if not admin_id:
        return None
    return db.session.get(Admin, int(admin_id))


def admin_required(view):
    """Protect /admin/* routes — regular Flask-Login users are not enough."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_admin() is None:
            return redirect(url_for("admin.login"))
        return view(*args, **kwargs)

    return wrapped
