import argparse
import os
import sqlite3
import sys

import boto3
import requests

DB_PATH = os.getenv("DB_PATH", "/app/data/domains.db")


def db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    if domain.startswith("*."):
        domain = domain[2:]
    return domain


def get_domain_spec(domain_id: int, requested_domain: str):
    base = normalize_domain(requested_domain)
    with db_connection() as conn:
        row = conn.execute(
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
            WHERE cd.domain_id = ? AND cd.base_domain = ?
            LIMIT 1
            """,
            (domain_id, base),
        ).fetchone()
    return row


def cf_api_request(token: str, method: str, path: str, payload=None, params=None):
    url = f"https://api.cloudflare.com/client/v4{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.request(method, url, headers=headers, json=payload, params=params, timeout=30)
    data = response.json()
    if not response.ok or not data.get("success"):
        raise RuntimeError(f"Cloudflare API error: {data}")
    return data


def cf_find_zone_id(token: str, base_domain: str):
    labels = base_domain.split(".")
    for idx in range(0, len(labels) - 1):
        candidate = ".".join(labels[idx:])
        data = cf_api_request(token, "GET", "/zones", params={"name": candidate, "status": "active", "per_page": 1})
        result = data.get("result") or []
        if result:
            return result[0]["id"]
    raise RuntimeError(f"No se encontró zona Cloudflare para {base_domain}")


def cf_delete_txt(token: str, base_domain: str, value: str):
    zone_id = cf_find_zone_id(token, base_domain)
    name = f"_acme-challenge.{base_domain}"
    data = cf_api_request(
        token,
        "GET",
        f"/zones/{zone_id}/dns_records",
        params={"type": "TXT", "name": name, "content": value, "per_page": 100},
    )
    for record in data.get("result") or []:
        cf_api_request(token, "DELETE", f"/zones/{zone_id}/dns_records/{record['id']}")


def route53_find_zone_id(client, base_domain: str):
    zones = client.list_hosted_zones().get("HostedZones", [])
    best = None
    for zone in zones:
        zone_name = zone["Name"].rstrip(".")
        if base_domain == zone_name or base_domain.endswith("." + zone_name):
            if best is None or len(zone_name) > len(best["Name"].rstrip(".")):
                best = zone
    if not best:
        raise RuntimeError(f"No se encontró hosted zone Route53 para {base_domain}")
    return best["Id"].split("/")[-1]


def route53_change_txt(access_key: str, secret_key: str, region: str, base_domain: str, value: str, action: str):
    client = boto3.client(
        "route53",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region or "us-east-1",
    )
    zone_id = route53_find_zone_id(client, base_domain)
    fqdn = f"_acme-challenge.{base_domain}."
    client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": fqdn,
                        "Type": "TXT",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": f'"{value}"'}],
                    },
                }
            ]
        },
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain-id", type=int, required=True)
    args = parser.parse_args()

    requested_domain = os.getenv("CERTBOT_DOMAIN", "")
    validation = os.getenv("CERTBOT_VALIDATION", "")
    if not requested_domain or not validation:
        return 0

    spec = get_domain_spec(args.domain_id, requested_domain)
    if not spec:
        return 0

    base_domain = normalize_domain(requested_domain)
    provider = spec["provider"]

    try:
        if provider == "cloudflare":
            token = spec["cred_cloudflare_api_token"] or spec["legacy_cloudflare_api_token"]
            if token:
                cf_delete_txt(token, base_domain, validation)
        elif provider == "aws":
            access_key = spec["cred_aws_access_key_id"] or spec["legacy_aws_access_key_id"]
            secret_key = spec["cred_aws_secret_access_key"] or spec["legacy_aws_secret_access_key"]
            region = spec["cred_aws_region"] or spec["legacy_aws_region"] or "us-east-1"
            if access_key and secret_key:
                route53_change_txt(access_key, secret_key, region, base_domain, validation, "DELETE")
    except Exception as exc:
        print(f"Cleanup warning: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
