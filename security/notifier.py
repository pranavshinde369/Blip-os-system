# ============================================================
# BLIP ENDPOINT SENTINEL — security/notifier.py
# Admin Alert Notifier — SMTP + Telegram + Pushover
# ============================================================

import smtplib
import threading
from email.mime.text import MIMEText
from typing import Optional

import requests


def send_alert(subject: str, body: str, config: dict):
    """
    Fire admin alert via all enabled channels.
    Runs in a background thread — never blocks daemon.
    """
    threading.Thread(
        target=_send_all,
        args=(subject, body, config),
        daemon=True,
    ).start()


def _send_all(subject: str, body: str, config: dict):
    notif = config.get("notifications", {})

    if notif.get("email_enabled"):
        _send_email(subject, body, notif)

    if notif.get("telegram_enabled"):
        _send_telegram(subject, body, notif)

    if notif.get("pushover_enabled"):
        _send_pushover(subject, body, notif)


def _send_email(subject: str, body: str, cfg: dict):
    try:
        msg            = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = cfg["smtp_user"]
        msg["To"]      = cfg["admin_email"]

        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as s:
            s.starttls()
            s.login(cfg["smtp_user"], cfg["smtp_password"])
            s.send_message(msg)
        print("[Notifier] Email alert sent")
    except Exception as e:
        print(f"[Notifier] Email failed: {e}")


def _send_telegram(subject: str, body: str, cfg: dict):
    try:
        text = f"🚨 *{subject}*\n\n```\n{body}\n```"
        requests.post(
            f"https://api.telegram.org/bot"
            f"{cfg['telegram_bot_token']}/sendMessage",
            json={
                "chat_id":    cfg["telegram_chat_id"],
                "text":       text,
                "parse_mode": "Markdown",
            },
            timeout=5,
        )
        print("[Notifier] Telegram alert sent")
    except Exception as e:
        print(f"[Notifier] Telegram failed: {e}")


def _send_pushover(subject: str, body: str, cfg: dict):
    try:
        requests.post(
            "https://api.pushover.net/1/messages.json",
            data={
                "token":   cfg["pushover_token"],
                "user":    cfg["pushover_user"],
                "title":   subject,
                "message": body,
                "priority": 1,
            },
            timeout=5,
        )
        print("[Notifier] Pushover alert sent")
    except Exception as e:
        print(f"[Notifier] Pushover failed: {e}")