"""Short-lived email verification codes for new account registration."""
import hashlib
import hmac
import os
import secrets
import smtplib
import ssl
from email.message import EmailMessage

import httpx


CODE_LIFETIME = 600
RESEND_COOLDOWN = 60
MAX_ATTEMPTS = 5


def new_code():
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_code(code):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", code.encode("ascii"), bytes.fromhex(salt), 100_000).hex()
    return salt + ":" + digest


def matches(code, stored):
    try:
        salt, expected = stored.split(":", 1)
        actual = hashlib.pbkdf2_hmac("sha256", code.encode("ascii"), bytes.fromhex(salt), 100_000).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, UnicodeEncodeError):
        return False


def send_code(email, code):
    """Send via Resend or a configured TLS SMTP account; never log the code."""
    api_key = os.getenv("RESEND_API_KEY")
    sender = os.getenv("PHISHGUARD_EMAIL_FROM")
    if not sender:
        raise RuntimeError("Email verification is not configured yet.")
    message = f"Your PhishGuard account verification code is {code}. It expires in 10 minutes. If you did not request this, ignore this email."
    if api_key:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"from": sender, "to": [email], "subject": "Your PhishGuard verification code", "text": message},
            timeout=10,
        )
        response.raise_for_status()
        return
    host = os.getenv("PHISHGUARD_SMTP_HOST")
    username = os.getenv("PHISHGUARD_SMTP_USERNAME")
    password = os.getenv("PHISHGUARD_SMTP_PASSWORD")
    port = int(os.getenv("PHISHGUARD_SMTP_PORT", "587"))
    if not host or not username or not password or port not in (465, 587):
        raise RuntimeError("Email verification is not configured yet.")
    mail = EmailMessage()
    mail["From"] = sender
    mail["To"] = email
    mail["Subject"] = "Your PhishGuard verification code"
    mail.set_content(message)
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10, context=context) as smtp:
            smtp.login(username, password)
            smtp.send_message(mail)
    else:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.starttls(context=context)
            smtp.login(username, password)
            smtp.send_message(mail)
