"""Email delivery module for security reports."""

from .sender import send_report, should_send_email

__all__ = ["send_report", "should_send_email"]
