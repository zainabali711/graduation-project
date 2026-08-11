"""SQLAlchemy models for CyberScan authentication and scan history."""

from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    url_scans = db.relationship("UrlScan", back_populates="user", lazy=True)
    domain_scans = db.relationship("DomainScan", back_populates="user", lazy=True)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Admin(db.Model):
    """Separate admin accounts — not Flask-Login users."""

    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<Admin {self.username}>"


class UrlScan(db.Model):
    __tablename__ = "url_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    url = db.Column(db.String(2048), nullable=False)
    result = db.Column(db.String(32), nullable=False)
    risk_level = db.Column(db.String(32), nullable=False)
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="url_scans")


class DomainScan(db.Model):
    __tablename__ = "domain_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    domain = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    country = db.Column(db.String(128), nullable=True)
    organization = db.Column(db.String(255), nullable=True)
    ssl_status = db.Column(db.String(64), nullable=True)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="domain_scans")
