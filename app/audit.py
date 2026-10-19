"""Audit log: who did what, and when.

Every step of the workflow (request submitted, approved, rejected, certificate issued, downloaded,
...) appends one row to the audit_log table. SQLite fills in the time (UTC).
"""
from .db import get_db


def log_event(actor, action, target=None, details=None):
    """Append one audit row and commit it.

    actor    who: the applicant's e-mail, 'ra-admin', 'cli' or 'system'
    action   what: e.g. REQUEST_SUBMITTED, REQUEST_APPROVED, CERT_ISSUED
    target   what it was done to: a tracking ID or a certificate serial
    details  any extra context (template, rejection reason, ...)
    """
    db = get_db()
    db.execute("INSERT INTO audit_log (actor, action, target, details) VALUES (?, ?, ?, ?)",
               (actor, action, target, details))
    db.commit()
