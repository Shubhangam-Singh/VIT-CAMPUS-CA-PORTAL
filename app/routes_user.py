"""Public (user-facing) pages.

Phase 0 has only the home page. The enrollment form and request status pages arrive in Phase 3.
"""
from flask import Blueprint, render_template

bp = Blueprint("user", __name__)


@bp.route("/")
def home():
    return render_template("home.html")
