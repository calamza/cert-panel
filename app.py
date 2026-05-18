import io
import os
import re
import smtplib
import sqlite3
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from threading import Lock

from apscheduler.schedulers.background import BackgroundScheduler
from authlib.integrations.flask_client import OAuth
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from flask import Flask, flash, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "domains.db"
CREDENTIALS_DIR = BASE_DIR / "credentials"
SCRIPTS_DIR = BASE_DIR / "scripts"
load_dotenv(BASE_DIR / ".env")

CERTBOT_CONFIG_DIR = Path(os.getenv("CERTBOT_CONFIG_DIR", "/etc/letsencrypt"))
CERTBOT_WORK_DIR = Path(os.getenv("CERTBOT_WORK_DIR", "/var/lib/letsencrypt"))
CERTBOT_LOGS_DIR = Path(os.getenv("CERTBOT_LOGS_DIR", "/var/log/letsencrypt"))
AUTO_RENEW_DAYS_BEFORE = int(os.getenv("AUTO_RENEW_DAYS_BEFORE", "15"))
AUTO_RENEW_INTERVAL_DAYS = int(os.getenv("AUTO_RENEW_INTERVAL_DAYS", "15"))
WEEKLY_STATUS_INTERVAL_DAYS = int(os.getenv("WEEKLY_STATUS_INTERVAL_DAYS", "7"))
INITIAL_ALLOWED_USER_EMAIL = os.getenv("INITIAL_ALLOWED_USER_EMAIL", "").strip().lower()
INITIAL_ALLOWED_USER_ROLE = os.getenv("INITIAL_ALLOWED_USER_ROLE", "admin").strip().lower()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL", "https://accounts.google.com/.well-known/openid-configuration")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").strip().lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()
SMTP_TO = [item.strip().lower() for item in os.getenv("SMTP_TO", "").split(",") if item.strip()]
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").strip().lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").strip().lower() == "true"

DNS_AUTH_HOOK = str(SCRIPTS_DIR / "dns_auth_hook.py")
DNS_CLEANUP_HOOK = str(SCRIPTS_DIR / "dns_cleanup_hook.py")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
renew_lock = Lock()
oauth = OAuth(app)

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        server_metadata_url=GOOGLE_DISCOVERY_URL,
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        client_kwargs={"scope": "openid email profile"},
    )


def db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_storage():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    CERTBOT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CERTBOT_WORK_DIR.mkdir(parents=True, exist_ok=True)
    CERTBOT_LOGS_DIR.mkdir(parents=True, exist_ok=True)

    with db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_name TEXT NOT NULL,
                provider TEXT NOT NULL CHECK (provider IN ('cloudflare', 'aws')),
                credential_id INTEGER,
                contact_email TEXT NOT NULL,
                include_wildcard INTEGER NOT NULL DEFAULT 0,
                cloudflare_api_token TEXT,
                aws_access_key_id TEXT,
                aws_secret_access_key TEXT,
                aws_region TEXT,
                cert_name TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (credential_id) REFERENCES dns_credentials(id)
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(domains)").fetchall()}
        if "credential_id" not in columns:
            conn.execute("ALTER TABLE domains ADD COLUMN credential_id INTEGER")
        if "last_expiry_notice_at" not in columns:
            conn.execute("ALTER TABLE domains ADD COLUMN last_expiry_notice_at TEXT")
        if "last_renew_notice_at" not in columns:
            conn.execute("ALTER TABLE domains ADD COLUMN last_renew_notice_at TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                provider TEXT NOT NULL CHECK (provider IN ('cloudflare', 'aws')),
                cloudflare_api_token TEXT,
                aws_access_key_id TEXT,
                aws_secret_access_key TEXT,
                aws_region TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK (role IN ('admin', 'readonly')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_usages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                system_name TEXT NOT NULL,
                usage_type TEXT,
                host_ip TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_recipients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(domain_id, email),
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificate_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                base_domain TEXT NOT NULL,
                provider TEXT NOT NULL CHECK (provider IN ('cloudflare', 'aws')),
                credential_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(domain_id, base_domain),
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                FOREIGN KEY (credential_id) REFERENCES dns_credentials(id)
            )
            """
        )

    ensure_initial_user()
    ensure_certificate_domain_specs()


def ensure_initial_user():
    if not INITIAL_ALLOWED_USER_EMAIL:
        return

    role = INITIAL_ALLOWED_USER_ROLE if INITIAL_ALLOWED_USER_ROLE in {"admin", "readonly"} else "admin"
    now = datetime.now(timezone.utc).isoformat()
    with db_connection() as conn:
        row = conn.execute("SELECT id FROM users WHERE email = ?", (INITIAL_ALLOWED_USER_EMAIL,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO users (email, role, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (INITIAL_ALLOWED_USER_EMAIL, role, now, now),
            )


def ensure_certificate_domain_specs():
    now = datetime.now(timezone.utc).isoformat()
    with db_connection() as conn:
        rows = conn.execute("SELECT id, domain_name, provider, credential_id FROM domains").fetchall()
        for row in rows:
            existing = conn.execute(
                "SELECT id FROM certificate_domains WHERE domain_id = ? LIMIT 1",
                (row["id"],),
            ).fetchone()
            if existing:
                continue

            domains = parse_domain_names(row["domain_name"]) or [normalize_domain(row["domain_name"])]
            for domain_item in domains:
                if not domain_item:
                    continue
                conn.execute(
                    """
                    INSERT OR IGNORE INTO certificate_domains (
                        domain_id, base_domain, provider, credential_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (row["id"], domain_item, row["provider"], row["credential_id"], now, now),
                )


def sanitize_cert_name(domain_name: str) -> str:
    clean = domain_name.strip().lower().replace("*.", "wildcard-")
    return "".join(c if c.isalnum() or c in "-." else "-" for c in clean)


def normalize_domain(domain_name: str) -> str:
    return domain_name.strip().lower().replace("*.", "")


def cert_paths(cert_name: str):
    base = CERTBOT_CONFIG_DIR / "live" / cert_name
    return {
        "fullchain": base / "fullchain.pem",
        "privkey": base / "privkey.pem",
        "chain": base / "chain.pem",
        "cert": base / "cert.pem",
    }


def get_certificate_expiry(cert_name: str):
    paths = cert_paths(cert_name)
    fullchain = paths["fullchain"]
    if not fullchain.exists():
        return None

    cert_data = fullchain.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert.not_valid_after_utc


def parse_iso_datetime(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def build_domains(domain_name: str, include_wildcard: bool):
    base_domains = parse_domain_names(domain_name)
    if not base_domains:
        single = normalize_domain(domain_name)
        base_domains = [single] if single else []

    domains = []
    seen = set()
    for base_domain in base_domains:
        requested = [base_domain]
        if include_wildcard:
            requested.append(f"*.{base_domain}")
        for item in requested:
            if item not in seen:
                domains.append(item)
                seen.add(item)
    return domains


def write_cloudflare_credentials(domain_id: int, api_token: str):
    cred_path = CREDENTIALS_DIR / f"cloudflare-{domain_id}.ini"
    cred_path.write_text(f"dns_cloudflare_api_token = {api_token}\n", encoding="utf-8")
    os.chmod(cred_path, 0o600)
    return cred_path


def certbot_command(domain_row, renew=False):
    specs = get_certificate_domain_specs(domain_row["id"])
    base_domains = [item["base_domain"] for item in specs] if specs else parse_domain_names(domain_row["domain_name"])
    if not base_domains:
        base_domains = [normalize_domain(domain_row["domain_name"])]

    domains = []
    seen = set()
    for base_domain in base_domains:
        requested = [base_domain]
        if bool(domain_row["include_wildcard"]):
            requested.append(f"*.{base_domain}")
        for item in requested:
            if item not in seen:
                domains.append(item)
                seen.add(item)

    base_cmd = [
        "certbot",
        "certonly",
        "--manual",
        "--preferred-challenges",
        "dns",
        "--manual-public-ip-logging-ok",
        "--manual-auth-hook",
        f"python {DNS_AUTH_HOOK} --domain-id {domain_row['id']}",
        "--manual-cleanup-hook",
        f"python {DNS_CLEANUP_HOOK} --domain-id {domain_row['id']}",
        "--non-interactive",
        "--agree-tos",
        "--email",
        domain_row["contact_email"],
        "--cert-name",
        domain_row["cert_name"],
        "--config-dir",
        str(CERTBOT_CONFIG_DIR),
        "--work-dir",
        str(CERTBOT_WORK_DIR),
        "--logs-dir",
        str(CERTBOT_LOGS_DIR),
    ]

    if renew:
        base_cmd.append("--keep-until-expiring")

    for item in domains:
        base_cmd.extend(["-d", item])

    return base_cmd


def run_certbot(domain_row, renew=False):
    try:
        cmd = certbot_command(domain_row, renew=renew)
    except ValueError as exc:
        return False, str(exc)

    env = os.environ.copy()
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    ok = result.returncode == 0
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    return ok, output.strip()


def list_domains():
    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                d.*,
                c.name AS credential_name,
                c.cloudflare_api_token AS cred_cloudflare_api_token,
                c.aws_access_key_id AS cred_aws_access_key_id,
                c.aws_secret_access_key AS cred_aws_secret_access_key,
                c.aws_region AS cred_aws_region,
                (SELECT COUNT(DISTINCT cd.provider) FROM certificate_domains cd WHERE cd.domain_id = d.id) AS providers_count,
                (SELECT COUNT(1) FROM domain_usages u WHERE u.domain_id = d.id) AS usage_count,
                (SELECT COUNT(1) FROM domain_recipients r WHERE r.domain_id = d.id) AS recipients_count
            FROM domains d
            LEFT JOIN dns_credentials c ON c.id = d.credential_id
            ORDER BY d.domain_name
            """
        ).fetchall()

    items = []
    now = datetime.now(timezone.utc)
    for row in rows:
        expires_at = get_certificate_expiry(row["cert_name"])
        days_left = None
        if expires_at:
            days_left = (expires_at - now).days

        items.append(
            {
                "id": row["id"],
                "domain_name": row["domain_name"],
                "provider": "mixed" if int(row["providers_count"] or 0) > 1 else row["provider"],
                "credential_name": row["credential_name"],
                "usage_count": int(row["usage_count"] or 0),
                "recipients_count": int(row["recipients_count"] or 0),
                "contact_email": row["contact_email"],
                "include_wildcard": bool(row["include_wildcard"]),
                "cert_name": row["cert_name"],
                "expires_at": expires_at,
                "days_left": days_left,
                "last_error": row["last_error"],
                "has_cert": expires_at is not None,
            }
        )
    return items


def update_last_error(domain_id: int, message: str | None):
    with db_connection() as conn:
        conn.execute(
            "UPDATE domains SET last_error = ?, updated_at = ? WHERE id = ?",
            (message, datetime.now(timezone.utc).isoformat(), domain_id),
        )


def get_user_by_email(email: str):
    with db_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()


def get_credentials(provider: str | None = None):
    with db_connection() as conn:
        if provider:
            return conn.execute(
                """
                SELECT c.*, COUNT(d.id) AS domains_count
                FROM dns_credentials c
                LEFT JOIN domains d ON d.credential_id = c.id
                WHERE c.provider = ?
                GROUP BY c.id
                ORDER BY c.name
                """,
                (provider,),
            ).fetchall()
        return conn.execute(
            """
            SELECT c.*, COUNT(d.id) AS domains_count
            FROM dns_credentials c
            LEFT JOIN domains d ON d.credential_id = c.id
            GROUP BY c.id
            ORDER BY c.provider, c.name
            """
        ).fetchall()


def get_credential_by_id(credential_id: int):
    with db_connection() as conn:
        return conn.execute(
            """
            SELECT c.*, COUNT(d.id) AS domains_count
            FROM dns_credentials c
            LEFT JOIN domains d ON d.credential_id = c.id
            WHERE c.id = ?
            GROUP BY c.id
            """,
            (credential_id,),
        ).fetchone()


def get_credential_by_name(provider: str, name: str):
    with db_connection() as conn:
        return conn.execute(
            "SELECT * FROM dns_credentials WHERE provider = ? AND lower(name) = lower(?) LIMIT 1",
            (provider, name.strip()),
        ).fetchone()


def get_certificate_domain_specs(domain_id: int):
    with db_connection() as conn:
        return conn.execute(
            """
            SELECT
                cd.*,
                c.cloudflare_api_token AS cred_cloudflare_api_token,
                c.aws_access_key_id AS cred_aws_access_key_id,
                c.aws_secret_access_key AS cred_aws_secret_access_key,
                c.aws_region AS cred_aws_region,
                d.cloudflare_api_token AS legacy_cloudflare_api_token,
                d.aws_access_key_id AS legacy_aws_access_key_id,
                d.aws_secret_access_key AS legacy_aws_secret_access_key,
                d.aws_region AS legacy_aws_region
            FROM certificate_domains cd
            LEFT JOIN dns_credentials c ON c.id = cd.credential_id
            JOIN domains d ON d.id = cd.domain_id
            WHERE cd.domain_id = ?
            ORDER BY cd.id
            """,
            (domain_id,),
        ).fetchall()


def resolve_credential_id(provider: str, credential_hint: str):
    hint = (credential_hint or "").strip()
    if not hint:
        return None

    if hint.isdigit():
        row = get_credential_by_id(int(hint))
        if row and row["provider"] == provider:
            return row["id"]
        return None

    row = get_credential_by_name(provider, hint)
    return row["id"] if row else None


def get_legacy_domains_without_credential():
    with db_connection() as conn:
        return conn.execute(
            """
            SELECT *
            FROM domains
            WHERE credential_id IS NULL
              AND (
                (provider = 'cloudflare' AND COALESCE(cloudflare_api_token, '') <> '')
                OR
                (provider = 'aws' AND COALESCE(aws_access_key_id, '') <> '' AND COALESCE(aws_secret_access_key, '') <> '')
              )
            ORDER BY domain_name
            """
        ).fetchall()


def migrate_legacy_domain_credentials():
    now = datetime.now(timezone.utc).isoformat()
    created = 0
    assigned = 0
    skipped = 0

    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM domains
            WHERE credential_id IS NULL
              AND (
                (provider = 'cloudflare' AND COALESCE(cloudflare_api_token, '') <> '')
                OR
                (provider = 'aws' AND COALESCE(aws_access_key_id, '') <> '' AND COALESCE(aws_secret_access_key, '') <> '')
              )
            ORDER BY id
            """
        ).fetchall()

        for row in rows:
            credential_id = None
            if row["provider"] == "cloudflare":
                token = row["cloudflare_api_token"]
                credential = conn.execute(
                    "SELECT id FROM dns_credentials WHERE provider = 'cloudflare' AND cloudflare_api_token = ? LIMIT 1",
                    (token,),
                ).fetchone()
                if credential:
                    credential_id = credential["id"]
                else:
                    name = f"Migrada CF {row['domain_name']}"
                    cursor = conn.execute(
                        """
                        INSERT INTO dns_credentials (
                            name, provider, cloudflare_api_token, aws_access_key_id,
                            aws_secret_access_key, aws_region, created_at, updated_at
                        ) VALUES (?, 'cloudflare', ?, NULL, NULL, NULL, ?, ?)
                        """,
                        (name, token, now, now),
                    )
                    credential_id = cursor.lastrowid
                    created += 1
            elif row["provider"] == "aws":
                access = row["aws_access_key_id"]
                secret = row["aws_secret_access_key"]
                region = row["aws_region"] or ""
                credential = conn.execute(
                    """
                    SELECT id
                    FROM dns_credentials
                    WHERE provider = 'aws'
                      AND aws_access_key_id = ?
                      AND aws_secret_access_key = ?
                      AND COALESCE(aws_region, '') = ?
                    LIMIT 1
                    """,
                    (access, secret, region),
                ).fetchone()
                if credential:
                    credential_id = credential["id"]
                else:
                    name = f"Migrada AWS {row['domain_name']}"
                    cursor = conn.execute(
                        """
                        INSERT INTO dns_credentials (
                            name, provider, cloudflare_api_token, aws_access_key_id,
                            aws_secret_access_key, aws_region, created_at, updated_at
                        ) VALUES (?, 'aws', NULL, ?, ?, ?, ?, ?)
                        """,
                        (name, access, secret, row["aws_region"], now, now),
                    )
                    credential_id = cursor.lastrowid
                    created += 1

            if not credential_id:
                skipped += 1
                continue

            conn.execute(
                """
                UPDATE domains
                SET credential_id = ?,
                    cloudflare_api_token = NULL,
                    aws_access_key_id = NULL,
                    aws_secret_access_key = NULL,
                    aws_region = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (credential_id, now, row["id"]),
            )
            assigned += 1

    return created, assigned, skipped


def get_domain_by_id(domain_id: int):
    with db_connection() as conn:
        return conn.execute(
            """
            SELECT
                d.*,
                c.name AS credential_name,
                c.cloudflare_api_token AS cred_cloudflare_api_token,
                c.aws_access_key_id AS cred_aws_access_key_id,
                c.aws_secret_access_key AS cred_aws_secret_access_key,
                c.aws_region AS cred_aws_region,
                d.last_expiry_notice_at,
                d.last_renew_notice_at
            FROM domains d
            LEFT JOIN dns_credentials c ON c.id = d.credential_id
            WHERE d.id = ?
            """,
            (domain_id,),
        ).fetchone()


def get_domain_usages(domain_id: int):
    with db_connection() as conn:
        return conn.execute(
            "SELECT * FROM domain_usages WHERE domain_id = ? ORDER BY system_name",
            (domain_id,),
        ).fetchall()


def get_domain_recipients(domain_id: int):
    with db_connection() as conn:
        return conn.execute(
            "SELECT * FROM domain_recipients WHERE domain_id = ? ORDER BY email",
            (domain_id,),
        ).fetchall()


def get_domain_recipient_emails(domain_id: int):
    return [row["email"] for row in get_domain_recipients(domain_id)]


def usages_text_block(domain_id: int):
    usages = get_domain_usages(domain_id)
    if not usages:
        return "Sin usos cargados."

    lines = []
    for item in usages:
        segment = item["system_name"]
        if item["usage_type"]:
            segment += f" ({item['usage_type']})"
        if item["host_ip"]:
            segment += f" - IP {item['host_ip']}"
        if item["notes"]:
            segment += f" - {item['notes']}"
        lines.append(f"- {segment}")
    return "\n".join(lines)


def notification_recipients(domain_row):
    recipients = get_domain_recipient_emails(domain_row["id"])
    if not recipients:
        recipients = list(SMTP_TO)
        contact = (domain_row["contact_email"] or "").strip().lower()
        if contact and contact not in recipients:
            recipients.append(contact)
    return recipients


def send_notification_email(subject: str, body: str, recipients: list[str]):
    if not SMTP_HOST or not SMTP_FROM or not recipients:
        return False, "SMTP no configurado o sin destinatarios"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    try:
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)

        with server:
            if SMTP_USE_TLS and not SMTP_USE_SSL:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def update_notice_timestamps(domain_id: int, *, expiry_notice: bool = False, renew_notice: bool = False):
    sets = []
    values = []
    now = datetime.now(timezone.utc).isoformat()
    if expiry_notice:
        sets.append("last_expiry_notice_at = ?")
        values.append(now)
    if renew_notice:
        sets.append("last_renew_notice_at = ?")
        values.append(now)
    if not sets:
        return

    values.append(domain_id)
    with db_connection() as conn:
        conn.execute(f"UPDATE domains SET {', '.join(sets)}, updated_at = ? WHERE id = ?", (*values[:-1], now, values[-1]))


def send_expiry_warning(domain_row, expires_at, days_left: int):
    last_notice = parse_iso_datetime(domain_row["last_expiry_notice_at"])
    now = datetime.now(timezone.utc)
    if last_notice and last_notice >= now - timedelta(days=1):
        return

    recipients = notification_recipients(domain_row)
    if not recipients:
        return

    subject = f"[Cert-Panel] Certificado próximo a vencer: {domain_row['domain_name']}"
    body = (
        f"El certificado {domain_row['domain_name']} vence el {expires_at.strftime('%d/%m/%Y %H:%M UTC')}\n"
        f"Días restantes: {days_left}\n\n"
        f"Dónde está en uso:\n{usages_text_block(domain_row['id'])}\n"
    )
    ok, _ = send_notification_email(subject, body, recipients)
    if ok:
        update_notice_timestamps(domain_row["id"], expiry_notice=True)


def send_renewal_notice(domain_row, expires_at, outcome: str):
    recipients = notification_recipients(domain_row)
    if not recipients:
        return

    subject = f"[Cert-Panel] Renovación {outcome}: {domain_row['domain_name']}"
    expiry_text = expires_at.strftime('%d/%m/%Y %H:%M UTC') if expires_at else "no disponible"
    body = (
        f"Resultado de renovación para {domain_row['domain_name']}: {outcome}\n"
        f"Nuevo vencimiento: {expiry_text}\n\n"
        f"Dónde está en uso:\n{usages_text_block(domain_row['id'])}\n"
    )
    ok, _ = send_notification_email(subject, body, recipients)
    if ok and outcome.lower() == "ok":
        update_notice_timestamps(domain_row["id"], renew_notice=True)


def send_weekly_status_report(manual: bool = False, requested_by: str | None = None):
    domains = list_domains()
    if not domains:
        return False, "No hay certificados cargados para reportar"

    recipients = list(SMTP_TO)
    if manual and requested_by and requested_by not in recipients:
        recipients.append(requested_by)
    if not recipients:
        return False, "No hay destinatarios configurados en SMTP_TO"

    lines = []
    for item in domains:
        expires_text = item["expires_at"].strftime("%d/%m/%Y %H:%M UTC") if item["expires_at"] else "Sin certificado emitido"
        days_text = f"{item['days_left']} días" if item["days_left"] is not None else "n/a"
        usages = usages_text_block(item["id"]).replace("\n", " | ")
        lines.append(
            f"- {item['domain_name']} | proveedor={item['provider']} | expira={expires_text} | restantes={days_text} | usos={usages}"
        )

    subject = "[Cert-Panel] Estado semanal de certificados"
    body = "Reporte semanal de estado:\n\n" + "\n".join(lines)
    return send_notification_email(subject, body, recipients)


def parse_domain_names(raw_value: str):
    items = []
    for token in re.split(r"[\n,;]+", raw_value or ""):
        clean = normalize_domain(token)
        if clean:
            items.append(clean)
    # Mantiene orden y elimina duplicados.
    return list(dict.fromkeys(items))


def current_user():
    email = session.get("user_email")
    if not email:
        return None
    return get_user_by_email(email)


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Necesitás iniciar sesión con Google.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Necesitás iniciar sesión con Google.", "error")
            return redirect(url_for("login"))
        if g.user["role"] != "admin":
            flash("No tenés permisos para esta acción.", "error")
            return redirect(url_for("index"))
        return view_func(*args, **kwargs)

    return wrapped


def can_manage() -> bool:
    return bool(g.user and g.user["role"] == "admin")


@app.before_request
def load_user_context():
    g.user = current_user()


@app.context_processor
def inject_user_context():
    return {
        "logged_user": g.user,
        "can_manage": can_manage(),
    }


def monitor_and_renew():
    if not renew_lock.acquire(blocking=False):
        return

    try:
        with db_connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    d.*,
                    c.name AS credential_name,
                    c.cloudflare_api_token AS cred_cloudflare_api_token,
                    c.aws_access_key_id AS cred_aws_access_key_id,
                    c.aws_secret_access_key AS cred_aws_secret_access_key,
                    c.aws_region AS cred_aws_region
                FROM domains d
                LEFT JOIN dns_credentials c ON c.id = d.credential_id
                """
            ).fetchall()

        for row in rows:
            expires_at = get_certificate_expiry(row["cert_name"])
            now = datetime.now(timezone.utc)
            days_left = (expires_at - now).days if expires_at else -1

            if expires_at and days_left <= AUTO_RENEW_DAYS_BEFORE:
                send_expiry_warning(row, expires_at, days_left)

            should_renew = expires_at is None or expires_at <= now + timedelta(days=AUTO_RENEW_DAYS_BEFORE)
            if should_renew:
                ok, output = run_certbot(row, renew=True)
                update_last_error(row["id"], None if ok else output[-4000:])
                if ok:
                    updated_expiry = get_certificate_expiry(row["cert_name"])
                    send_renewal_notice(row, updated_expiry, "OK")
                else:
                    send_renewal_notice(row, expires_at, f"ERROR ({output[-200:]})")
    finally:
        renew_lock.release()


@app.route("/")
@login_required
def index():
    return render_template("index.html", domains=list_domains(), renew_days=AUTO_RENEW_DAYS_BEFORE)


@app.get("/login")
def login():
    if g.user:
        return redirect(url_for("index"))

    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Falta configurar GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET en .env", "error")
        return render_template("login.html")

    return render_template("login.html")


@app.get("/auth/google")
def auth_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Google OAuth no está configurado.", "error")
        return redirect(url_for("login"))

    if PUBLIC_BASE_URL:
        redirect_uri = f"{PUBLIC_BASE_URL}{url_for('auth_google_callback')}"
    else:
        redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.get("/auth/google/callback")
def auth_google_callback():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Google OAuth no está configurado.", "error")
        return redirect(url_for("login"))

    token = oauth.google.authorize_access_token()
    user_info = token.get("userinfo")
    if not user_info:
        user_info = oauth.google.userinfo()

    email = (user_info.get("email") or "").strip().lower()
    if not email:
        flash("No se pudo obtener el email de Google.", "error")
        return redirect(url_for("login"))

    row = get_user_by_email(email)
    if not row:
        flash("Tu cuenta no tiene acceso a esta plataforma.", "error")
        return redirect(url_for("login"))

    session["user_email"] = email
    flash("Sesión iniciada correctamente.", "success")
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("login"))


@app.route("/domains/new", methods=["GET", "POST"])
@admin_required
def new_domain():
    if request.method == "POST":
        domain_names = parse_domain_names(request.form.get("domain_names", ""))
        provider = request.form.get("provider", "").strip().lower()
        contact_email = request.form.get("contact_email", "").strip().lower()
        include_wildcard = 1 if request.form.get("include_wildcard") == "on" else 0
        credential_id_value = request.form.get("credential_id", "").strip()
        domain_provider_map = request.form.get("domain_provider_map", "").strip()

        if not domain_names or not contact_email:
            flash("Completá dominios y email de contacto.", "error")
            return redirect(url_for("new_domain"))

        domain_specs = []
        domain_spec_map = {}

        if provider and credential_id_value:
            if provider not in {"cloudflare", "aws"}:
                flash("Proveedor por defecto inválido.", "error")
                return redirect(url_for("new_domain"))
            default_credential_id = resolve_credential_id(provider, credential_id_value)
            if not default_credential_id:
                flash("La credencial DNS por defecto no es válida.", "error")
                return redirect(url_for("new_domain"))

            for item in domain_names:
                domain_spec_map[item] = {
                    "base_domain": item,
                    "provider": provider,
                    "credential_id": default_credential_id,
                }

        if domain_provider_map:
            for line in domain_provider_map.splitlines():
                if not line.strip():
                    continue
                parts = [part.strip() for part in line.split("|")]
                if len(parts) != 3:
                    flash("Formato inválido en 'Proveedor por dominio'. Usá: dominio|proveedor|credencial", "error")
                    return redirect(url_for("new_domain"))

                base_domain = normalize_domain(parts[0])
                map_provider = parts[1].lower()
                credential_hint = parts[2]

                if map_provider not in {"cloudflare", "aws"}:
                    flash(f"Proveedor inválido en mapeo: {map_provider}", "error")
                    return redirect(url_for("new_domain"))

                credential_id = resolve_credential_id(map_provider, credential_hint)
                if not credential_id:
                    flash(f"No se encontró credencial '{credential_hint}' para proveedor {map_provider}.", "error")
                    return redirect(url_for("new_domain"))

                if base_domain not in domain_names:
                    domain_names.append(base_domain)

                domain_spec_map[base_domain] = {
                    "base_domain": base_domain,
                    "provider": map_provider,
                    "credential_id": credential_id,
                }

        for item in domain_names:
            if item not in domain_spec_map:
                flash(
                    f"Falta proveedor/credencial para {item}. Definí un valor por defecto o completá el mapeo por dominio.",
                    "error",
                )
                return redirect(url_for("new_domain"))
            domain_specs.append(domain_spec_map[item])

        now = datetime.now(timezone.utc).isoformat()
        primary_domain = domain_names[0]
        cert_name = sanitize_cert_name(primary_domain)
        domains_value = ",".join(domain_names)
        first_provider = domain_specs[0]["provider"]
        first_credential_id = domain_specs[0]["credential_id"]

        with db_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO domains (
                    domain_name, provider, credential_id, contact_email, include_wildcard,
                    cloudflare_api_token, aws_access_key_id, aws_secret_access_key, aws_region,
                    cert_name, last_error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, NULL, ?, ?)
                """,
                (
                    domains_value,
                    first_provider,
                    first_credential_id,
                    contact_email,
                    include_wildcard,
                    cert_name,
                    now,
                    now,
                ),
            )
            domain_id = cursor.lastrowid
            for spec in domain_specs:
                conn.execute(
                    """
                    INSERT INTO certificate_domains (
                        domain_id, base_domain, provider, credential_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        domain_id,
                        spec["base_domain"],
                        spec["provider"],
                        spec["credential_id"],
                        now,
                        now,
                    ),
                )

        flash(
            f"Se guardó 1 certificado SAN con {len(domain_names)} dominios.",
            "success",
        )
        return redirect(url_for("index"))

    credentials = get_credentials()
    return render_template("domain_form.html", credentials=credentials)


@app.post("/domains/<int:domain_id>/issue")
@admin_required
def issue(domain_id: int):
    row = get_domain_by_id(domain_id)

    if not row:
        flash("Dominio no encontrado.", "error")
        return redirect(url_for("index"))

    ok, output = run_certbot(row, renew=False)
    update_last_error(domain_id, None if ok else output[-4000:])

    if ok:
        flash(f"Certificado emitido para {row['domain_name']}", "success")
    else:
        flash(f"Error emitiendo {row['domain_name']}. Revisá el detalle.", "error")

    return redirect(url_for("index"))


@app.post("/domains/<int:domain_id>/renew")
@admin_required
def renew(domain_id: int):
    row = get_domain_by_id(domain_id)

    if not row:
        flash("Dominio no encontrado.", "error")
        return redirect(url_for("index"))

    ok, output = run_certbot(row, renew=True)
    update_last_error(domain_id, None if ok else output[-4000:])

    if ok:
        flash(f"Renovación ejecutada para {row['domain_name']}", "success")
        updated_expiry = get_certificate_expiry(row["cert_name"])
        send_renewal_notice(row, updated_expiry, "OK")
    else:
        flash(f"Error renovando {row['domain_name']}. Revisá el detalle.", "error")
        send_renewal_notice(row, get_certificate_expiry(row["cert_name"]), f"ERROR ({output[-200:]})")

    return redirect(url_for("index"))


@app.get("/domains/<int:domain_id>/download")
@login_required
def download(domain_id: int):
    row = get_domain_by_id(domain_id)

    if not row:
        flash("Dominio no encontrado.", "error")
        return redirect(url_for("index"))

    paths = cert_paths(row["cert_name"])
    missing = [name for name, path in paths.items() if not path.exists()]
    if missing:
        flash("Todavía no hay certificados emitidos para descargar.", "error")
        return redirect(url_for("index"))

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for key, path in paths.items():
            zf.writestr(f"{row['domain_name']}/{key}.pem", path.read_text(encoding="utf-8"))

    memory_file.seek(0)
    filename = f"{row['domain_name']}-certs.zip"
    return send_file(memory_file, as_attachment=True, download_name=filename, mimetype="application/zip")


@app.route("/domains/<int:domain_id>/usages", methods=["GET", "POST"])
@admin_required
def domain_usages(domain_id: int):
    row = get_domain_by_id(domain_id)
    if not row:
        flash("Registro no encontrado.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        system_name = request.form.get("system_name", "").strip()
        usage_type = request.form.get("usage_type", "").strip()
        host_ip = request.form.get("host_ip", "").strip()
        notes = request.form.get("notes", "").strip()

        if not system_name:
            flash("El nombre del sistema es obligatorio.", "error")
            return redirect(url_for("domain_usages", domain_id=domain_id))

        now = datetime.now(timezone.utc).isoformat()
        with db_connection() as conn:
            conn.execute(
                """
                INSERT INTO domain_usages (domain_id, system_name, usage_type, host_ip, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (domain_id, system_name, usage_type or None, host_ip or None, notes or None, now, now),
            )

        flash("Uso agregado.", "success")
        return redirect(url_for("domain_usages", domain_id=domain_id))

    return render_template("domain_usages.html", domain=row, usages=get_domain_usages(domain_id))


@app.route("/domains/<int:domain_id>/recipients", methods=["GET", "POST"])
@admin_required
def domain_recipients(domain_id: int):
    row = get_domain_by_id(domain_id)
    if not row:
        flash("Registro no encontrado.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("El email es obligatorio.", "error")
            return redirect(url_for("domain_recipients", domain_id=domain_id))

        now = datetime.now(timezone.utc).isoformat()
        try:
            with db_connection() as conn:
                conn.execute(
                    "INSERT INTO domain_recipients (domain_id, email, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (domain_id, email, now, now),
                )
            flash("Destinatario agregado.", "success")
        except sqlite3.IntegrityError:
            flash("Ese destinatario ya está configurado para este certificado.", "error")
        return redirect(url_for("domain_recipients", domain_id=domain_id))

    return render_template("domain_recipients.html", domain=row, recipients=get_domain_recipients(domain_id))


@app.post("/domains/<int:domain_id>/recipients/<int:recipient_id>/delete")
@admin_required
def delete_domain_recipient(domain_id: int, recipient_id: int):
    with db_connection() as conn:
        deleted = conn.execute(
            "DELETE FROM domain_recipients WHERE id = ? AND domain_id = ?",
            (recipient_id, domain_id),
        ).rowcount

    if deleted:
        flash("Destinatario eliminado.", "success")
    else:
        flash("Destinatario no encontrado.", "error")
    return redirect(url_for("domain_recipients", domain_id=domain_id))


@app.post("/domains/<int:domain_id>/usages/<int:usage_id>/delete")
@admin_required
def delete_domain_usage(domain_id: int, usage_id: int):
    with db_connection() as conn:
        deleted = conn.execute(
            "DELETE FROM domain_usages WHERE id = ? AND domain_id = ?",
            (usage_id, domain_id),
        ).rowcount

    if deleted:
        flash("Uso eliminado.", "success")
    else:
        flash("Uso no encontrado.", "error")
    return redirect(url_for("domain_usages", domain_id=domain_id))


@app.post("/domains/<int:domain_id>/delete")
@admin_required
def delete_domain(domain_id: int):
    row = get_domain_by_id(domain_id)
    if not row:
        flash("Registro no encontrado.", "error")
        return redirect(url_for("index"))

    with db_connection() as conn:
        conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))

    flash(f"Se eliminó el registro {row['domain_name']}", "success")
    return redirect(url_for("index"))


@app.post("/domains/cleanup-empty")
@admin_required
def cleanup_empty_domains():
    with db_connection() as conn:
        rows = conn.execute("SELECT id, cert_name FROM domains").fetchall()

    to_delete_ids = []
    for row in rows:
        if get_certificate_expiry(row["cert_name"]) is None:
            to_delete_ids.append(row["id"])

    if not to_delete_ids:
        flash("No había registros sin certificado emitido para limpiar.", "success")
        return redirect(url_for("index"))

    with db_connection() as conn:
        conn.executemany("DELETE FROM domains WHERE id = ?", [(item_id,) for item_id in to_delete_ids])

    flash(f"Se eliminaron {len(to_delete_ids)} registros sin certificado emitido.", "success")
    return redirect(url_for("index"))


@app.route("/credentials", methods=["GET", "POST"])
@admin_required
def credentials():
    if request.method == "POST":
        provider = request.form.get("provider", "").strip().lower()
        name = request.form.get("name", "").strip()
        cloudflare_api_token = request.form.get("cloudflare_api_token", "").strip()
        aws_access_key_id = request.form.get("aws_access_key_id", "").strip()
        aws_secret_access_key = request.form.get("aws_secret_access_key", "").strip()
        aws_region = request.form.get("aws_region", "").strip()

        if provider not in {"cloudflare", "aws"}:
            flash("Proveedor inválido para la credencial.", "error")
            return redirect(url_for("credentials"))

        if not name:
            flash("La credencial debe tener un nombre descriptivo.", "error")
            return redirect(url_for("credentials"))

        if provider == "cloudflare" and not cloudflare_api_token:
            flash("Para Cloudflare tenés que informar API token.", "error")
            return redirect(url_for("credentials"))

        if provider == "aws" and (not aws_access_key_id or not aws_secret_access_key):
            flash("Para AWS tenés que informar Access Key ID y Secret Access Key.", "error")
            return redirect(url_for("credentials"))

        now = datetime.now(timezone.utc).isoformat()
        with db_connection() as conn:
            conn.execute(
                """
                INSERT INTO dns_credentials (
                    name, provider, cloudflare_api_token, aws_access_key_id,
                    aws_secret_access_key, aws_region, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    provider,
                    cloudflare_api_token or None,
                    aws_access_key_id or None,
                    aws_secret_access_key or None,
                    aws_region or None,
                    now,
                    now,
                ),
            )
        flash("Credencial guardada correctamente.", "success")
        return redirect(url_for("credentials"))

    return render_template(
        "credentials.html",
        cloudflare_credentials=get_credentials("cloudflare"),
        aws_credentials=get_credentials("aws"),
        legacy_domains=get_legacy_domains_without_credential(),
    )


@app.post("/credentials/<int:credential_id>/update")
@admin_required
def update_credential(credential_id: int):
    credential = get_credential_by_id(credential_id)
    if not credential:
        flash("Credencial no encontrada.", "error")
        return redirect(url_for("credentials"))

    name = request.form.get("name", "").strip()
    if not name:
        flash("El nombre de la credencial es obligatorio.", "error")
        return redirect(url_for("credentials"))

    now = datetime.now(timezone.utc).isoformat()
    with db_connection() as conn:
        if credential["provider"] == "cloudflare":
            cloudflare_api_token = request.form.get("cloudflare_api_token", "").strip()
            token_to_save = cloudflare_api_token or credential["cloudflare_api_token"]
            if not token_to_save:
                flash("La credencial Cloudflare requiere API token.", "error")
                return redirect(url_for("credentials"))
            conn.execute(
                """
                UPDATE dns_credentials
                SET name = ?, cloudflare_api_token = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, token_to_save, now, credential_id),
            )
        else:
            aws_access_key_id = request.form.get("aws_access_key_id", "").strip()
            aws_secret_access_key = request.form.get("aws_secret_access_key", "").strip()
            aws_region = request.form.get("aws_region", "").strip()

            access_to_save = aws_access_key_id or credential["aws_access_key_id"]
            secret_to_save = aws_secret_access_key or credential["aws_secret_access_key"]
            region_to_save = aws_region if aws_region else credential["aws_region"]

            if not access_to_save or not secret_to_save:
                flash("La credencial AWS requiere Access Key ID y Secret Access Key.", "error")
                return redirect(url_for("credentials"))

            conn.execute(
                """
                UPDATE dns_credentials
                SET name = ?, aws_access_key_id = ?, aws_secret_access_key = ?, aws_region = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, access_to_save, secret_to_save, region_to_save, now, credential_id),
            )

    flash("Credencial actualizada.", "success")
    return redirect(url_for("credentials"))


@app.post("/credentials/<int:credential_id>/delete")
@admin_required
def delete_credential(credential_id: int):
    credential = get_credential_by_id(credential_id)
    if not credential:
        flash("Credencial no encontrada.", "error")
        return redirect(url_for("credentials"))

    if int(credential["domains_count"] or 0) > 0:
        flash(
            f"No se puede borrar {credential['name']} porque está asignada a {credential['domains_count']} dominio(s).",
            "error",
        )
        return redirect(url_for("credentials"))

    with db_connection() as conn:
        conn.execute("DELETE FROM dns_credentials WHERE id = ?", (credential_id,))

    flash("Credencial eliminada.", "success")
    return redirect(url_for("credentials"))


@app.post("/credentials/migrate-legacy")
@admin_required
def migrate_legacy_credentials():
    created, assigned, skipped = migrate_legacy_domain_credentials()
    flash(
        f"Migración finalizada. Credenciales creadas: {created}. Dominios migrados: {assigned}. Omitidos: {skipped}.",
        "success",
    )
    return redirect(url_for("credentials"))


@app.post("/notifications/test")
@admin_required
def send_test_notification():
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
    recipients = list(SMTP_TO)
    if g.user and g.user["email"] and g.user["email"] not in recipients:
        recipients.append(g.user["email"])

    subject = "[Cert-Panel] Prueba de notificaciones SMTP"
    body = (
        "Este es un correo de prueba generado manualmente desde el panel.\n\n"
        f"Fecha: {now}\n"
        f"Usuario: {g.user['email'] if g.user else 'desconocido'}\n"
    )

    ok, detail = send_notification_email(subject, body, recipients)
    if ok:
        flash("Mail de prueba enviado correctamente.", "success")
    else:
        flash(f"No se pudo enviar el mail de prueba: {detail}", "error")

    return redirect(url_for("index"))


@app.post("/notifications/weekly-status")
@admin_required
def send_weekly_status_now():
    requester = g.user["email"] if g.user else None
    ok, detail = send_weekly_status_report(manual=True, requested_by=requester)
    if ok:
        flash("Estado semanal enviado correctamente.", "success")
    else:
        flash(f"No se pudo enviar el estado semanal: {detail}", "error")
    return redirect(url_for("index"))


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "readonly").strip().lower()
        if role not in {"admin", "readonly"}:
            flash("Rol inválido.", "error")
            return redirect(url_for("users"))
        if not email:
            flash("El email es obligatorio.", "error")
            return redirect(url_for("users"))

        now = datetime.now(timezone.utc).isoformat()
        with db_connection() as conn:
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                conn.execute("UPDATE users SET role = ?, updated_at = ? WHERE email = ?", (role, now, email))
                flash("Usuario actualizado.", "success")
            else:
                conn.execute(
                    "INSERT INTO users (email, role, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (email, role, now, now),
                )
                flash("Usuario agregado.", "success")
        return redirect(url_for("users"))

    with db_connection() as conn:
        rows = conn.execute("SELECT email, role, created_at, updated_at FROM users ORDER BY email").fetchall()
    return render_template("users.html", users=rows)


def boot_scheduler():
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(monitor_and_renew, "interval", days=AUTO_RENEW_INTERVAL_DAYS, id="renew-monitor")
    scheduler.add_job(send_weekly_status_report, "interval", days=WEEKLY_STATUS_INTERVAL_DAYS, id="weekly-status")
    scheduler.start()


init_storage()
boot_scheduler()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
