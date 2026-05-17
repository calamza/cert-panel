import io
import os
import sqlite3
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock

from apscheduler.schedulers.background import BackgroundScheduler
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Flask, flash, redirect, render_template, request, send_file, url_for

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "domains.db"
CREDENTIALS_DIR = BASE_DIR / "credentials"
CERTBOT_CONFIG_DIR = Path(os.getenv("CERTBOT_CONFIG_DIR", "/etc/letsencrypt"))
CERTBOT_WORK_DIR = Path(os.getenv("CERTBOT_WORK_DIR", "/var/lib/letsencrypt"))
CERTBOT_LOGS_DIR = Path(os.getenv("CERTBOT_LOGS_DIR", "/var/log/letsencrypt"))
AUTO_RENEW_DAYS_BEFORE = int(os.getenv("AUTO_RENEW_DAYS_BEFORE", "30"))
AUTO_RENEW_INTERVAL_HOURS = int(os.getenv("AUTO_RENEW_INTERVAL_HOURS", "12"))

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-in-production")
renew_lock = Lock()


def db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_storage():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
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
                contact_email TEXT NOT NULL,
                include_wildcard INTEGER NOT NULL DEFAULT 0,
                cloudflare_api_token TEXT,
                aws_access_key_id TEXT,
                aws_secret_access_key TEXT,
                aws_region TEXT,
                cert_name TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
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


def build_domains(domain_name: str, include_wildcard: bool):
    base_domain = normalize_domain(domain_name)
    domains = [base_domain]
    if include_wildcard:
        domains.append(f"*.{base_domain}")
    return domains


def write_cloudflare_credentials(domain_id: int, api_token: str):
    cred_path = CREDENTIALS_DIR / f"cloudflare-{domain_id}.ini"
    cred_path.write_text(f"dns_cloudflare_api_token = {api_token}\n", encoding="utf-8")
    os.chmod(cred_path, 0o600)
    return cred_path


def certbot_command(domain_row, renew=False):
    domains = build_domains(domain_row["domain_name"], bool(domain_row["include_wildcard"]))
    base_cmd = [
        "certbot",
        "certonly",
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

    if domain_row["provider"] == "cloudflare":
        cred_path = write_cloudflare_credentials(domain_row["id"], domain_row["cloudflare_api_token"])
        base_cmd.extend(
            [
                "--dns-cloudflare",
                "--dns-cloudflare-credentials",
                str(cred_path),
            ]
        )
    else:
        base_cmd.append("--dns-route53")

    for item in domains:
        base_cmd.extend(["-d", item])

    return base_cmd


def run_certbot(domain_row, renew=False):
    cmd = certbot_command(domain_row, renew=renew)
    env = os.environ.copy()

    if domain_row["provider"] == "aws":
        env["AWS_ACCESS_KEY_ID"] = domain_row["aws_access_key_id"] or ""
        env["AWS_SECRET_ACCESS_KEY"] = domain_row["aws_secret_access_key"] or ""
        if domain_row["aws_region"]:
            env["AWS_DEFAULT_REGION"] = domain_row["aws_region"]

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    ok = result.returncode == 0
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    return ok, output.strip()


def list_domains():
    with db_connection() as conn:
        rows = conn.execute("SELECT * FROM domains ORDER BY domain_name").fetchall()

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
                "provider": row["provider"],
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


def monitor_and_renew():
    if not renew_lock.acquire(blocking=False):
        return

    try:
        with db_connection() as conn:
            rows = conn.execute("SELECT * FROM domains").fetchall()

        for row in rows:
            expires_at = get_certificate_expiry(row["cert_name"])
            should_renew = expires_at is None or expires_at <= datetime.now(timezone.utc) + timedelta(days=AUTO_RENEW_DAYS_BEFORE)
            if should_renew:
                ok, output = run_certbot(row, renew=True)
                update_last_error(row["id"], None if ok else output[-4000:])
    finally:
        renew_lock.release()


@app.route("/")
def index():
    return render_template("index.html", domains=list_domains(), renew_days=AUTO_RENEW_DAYS_BEFORE)


@app.route("/domains/new", methods=["GET", "POST"])
def new_domain():
    if request.method == "POST":
        domain_name = normalize_domain(request.form.get("domain_name", ""))
        provider = request.form.get("provider", "").strip().lower()
        contact_email = request.form.get("contact_email", "").strip().lower()
        include_wildcard = 1 if request.form.get("include_wildcard") == "on" else 0

        cloudflare_api_token = request.form.get("cloudflare_api_token", "").strip()
        aws_access_key_id = request.form.get("aws_access_key_id", "").strip()
        aws_secret_access_key = request.form.get("aws_secret_access_key", "").strip()
        aws_region = request.form.get("aws_region", "").strip()

        if not domain_name or not provider or not contact_email:
            flash("Completá dominio, proveedor y email de contacto.", "error")
            return redirect(url_for("new_domain"))

        if provider == "cloudflare" and not cloudflare_api_token:
            flash("Para Cloudflare tenés que informar un API token.", "error")
            return redirect(url_for("new_domain"))

        if provider == "aws" and (not aws_access_key_id or not aws_secret_access_key):
            flash("Para AWS tenés que informar Access Key ID y Secret Access Key.", "error")
            return redirect(url_for("new_domain"))

        cert_name = sanitize_cert_name(domain_name)
        now = datetime.now(timezone.utc).isoformat()

        with db_connection() as conn:
            conn.execute(
                """
                INSERT INTO domains (
                    domain_name, provider, contact_email, include_wildcard,
                    cloudflare_api_token, aws_access_key_id, aws_secret_access_key, aws_region,
                    cert_name, last_error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    domain_name,
                    provider,
                    contact_email,
                    include_wildcard,
                    cloudflare_api_token or None,
                    aws_access_key_id or None,
                    aws_secret_access_key or None,
                    aws_region or None,
                    cert_name,
                    now,
                    now,
                ),
            )

        flash("Dominio guardado. Ya podés emitir el certificado.", "success")
        return redirect(url_for("index"))

    return render_template("domain_form.html")


@app.post("/domains/<int:domain_id>/issue")
def issue(domain_id: int):
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()

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
def renew(domain_id: int):
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()

    if not row:
        flash("Dominio no encontrado.", "error")
        return redirect(url_for("index"))

    ok, output = run_certbot(row, renew=True)
    update_last_error(domain_id, None if ok else output[-4000:])

    if ok:
        flash(f"Renovación ejecutada para {row['domain_name']}", "success")
    else:
        flash(f"Error renovando {row['domain_name']}. Revisá el detalle.", "error")

    return redirect(url_for("index"))


@app.get("/domains/<int:domain_id>/download")
def download(domain_id: int):
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()

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


def boot_scheduler():
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(monitor_and_renew, "interval", hours=AUTO_RENEW_INTERVAL_HOURS, id="renew-monitor")
    scheduler.start()


init_storage()
boot_scheduler()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
