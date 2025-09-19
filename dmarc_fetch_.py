#!/usr/bin/env python3
"""
DMARC/SPF/DKIM Report Fetcher & Analyzer (2025 Edition, Public Safe) ..beta..

Features:
- Connects via IMAP and fetches DMARC aggregate report emails
- Extracts ZIP/GZ/XML attachments safely
- Parses XML reports for DMARC/SPF/DKIM results
- Exports structured data to JSON + CSV
- Credentials, domains, and emails anonymized for public release
"""

import imaplib
import email
import zipfile
import gzip
import logging
import xml.etree.ElementTree as ET
import json
import csv
from pathlib import Path
from typing import Optional, Dict, Any, List

# ==== CONFIGURATION ====
IMAP_SERVER = "imap.example.com"          # 🔐 Replace with your IMAP server
IMAP_USER = "user@example.com"            # 🔐 Replace with IMAP user
IMAP_PASSWORD = "CHANGE_ME_PASSWORD"      # 🔐 Prefer ENV VAR in production
SUBJECT_MATCH = "Report domain:"          # DMARC aggregate reports subject
OUTPUT_DIR = Path("./output")             # Local output folder

# ==== LOGGING SETUP ====
logging.basicConfig(level=logging.INFO, format="[*] %(message)s")
log = logging.getLogger(__name__)


# -------------------- IMAP FUNCTIONS --------------------
def connect_imap(server: str, user: str, password: str) -> imaplib.IMAP4_SSL:
    log.info(f"Connecting to IMAP server: {server}")
    m = imaplib.IMAP4_SSL(server)
    m.login(user, password)
    m.select("INBOX")
    return m


def fetch_by_subject(subject: str, output_dir: Path):
    mailbox = connect_imap(IMAP_SERVER, IMAP_USER, IMAP_PASSWORD)
    try:
        status, message_ids = mailbox.search(None, f'(SUBJECT "{subject}")')
        if status != "OK":
            log.warning("No messages found.")
            return

        ids = message_ids[0].split()
        log.info(f"Found {len(ids)} reports with subject filter")

        output_dir.mkdir(parents=True, exist_ok=True)

        for email_id in ids:
            download_attachments(mailbox, email_id, output_dir)
    finally:
        mailbox.logout()


def download_attachments(mailbox: imaplib.IMAP4_SSL, email_id: bytes, output_dir: Path) -> None:
    typ, data = mailbox.fetch(email_id, "(BODY.PEEK[])")
    if typ != "OK" or not data or not data[0]:
        log.warning(f"Failed to fetch email ID {email_id}")
        return

    msg = email.message_from_bytes(data[0][1])

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        disposition = part.get("Content-Disposition", "")
        if "attachment" not in disposition:
            continue

        filename = part.get_filename()
        if not filename:
            continue

        safe_name = Path(filename).name
        target_path = output_dir / safe_name

        log.info(f"Saving attachment → {target_path}")
        with open(target_path, "wb") as f:
            f.write(part.get_payload(decode=True))


# -------------------- EXTRACTION FUNCTIONS --------------------
def safe_extract_zip(zip_path: Path, extract_dir: Path) -> List[Path]:
    extracted_files = []
    log.info(f"Extracting ZIP: {zip_path}")
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for member in zip_ref.infolist():
            member_path = extract_dir / member.filename
            # Prevent zip-slip
            if not str(member_path.resolve()).startswith(str(extract_dir.resolve())):
                log.warning(f"Skipping suspicious path: {member.filename}")
                continue
            zip_ref.extract(member, extract_dir)
            extracted_files.append(member_path)
    return extracted_files


def safe_extract_gz(gz_path: Path, extract_dir: Path) -> Optional[Path]:
    out_path = extract_dir / gz_path.stem  # remove .gz
    log.info(f"Extracting GZ: {gz_path} → {out_path}")
    with gzip.open(gz_path, "rb") as f_in, open(out_path, "wb") as f_out:
        f_out.write(f_in.read())
    return out_path


def extract_all_reports(dir_path: Path) -> List[Path]:
    extracted = []
    for item in dir_path.glob("*.zip"):
        extracted.extend(safe_extract_zip(item, dir_path))
    for item in dir_path.glob("*.gz"):
        p = safe_extract_gz(item, dir_path)
        if p:
            extracted.append(p)
    for item in dir_path.glob("*.xml"):
        extracted.append(item)
    return extracted


# -------------------- PARSING FUNCTIONS --------------------
def parse_dmarc_report(xml_path: Path) -> Dict[str, Any]:
    log.info(f"Parsing DMARC XML report: {xml_path}")
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # DMARC Feedback Report Schema
        report_metadata = root.find("report_metadata")
        policy_published = root.find("policy_published")
        records = root.findall("record")

        result = {
            "file": xml_path.name,
            "report_metadata": (
                {child.tag: child.text for child in report_metadata}
                if report_metadata is not None else {}
            ),
            "policy_published": (
                {child.tag: child.text for child in policy_published}
                if policy_published is not None else {}
            ),
            "records": [],
        }

        for rec in records:
            row = rec.find("row")
            identifiers = rec.find("identifiers")
            auth_results = rec.find("auth_results")

            record = {
                "source_ip": row.findtext("source_ip") if row is not None else None,
                "count": row.findtext("count") if row is not None else None,
                "header_from": identifiers.findtext("header_from") if identifiers is not None else None,
                "spf": {
                    "domain": auth_results.find("spf/domain").text if auth_results is not None and auth_results.find("spf/domain") is not None else None,
                    "result": auth_results.find("spf/result").text if auth_results is not None and auth_results.find("spf/result") is not None else None,
                },
                "dkim": {
                    "domain": auth_results.find("dkim/domain").text if auth_results is not None and auth_results.find("dkim/domain") is not None else None,
                    "result": auth_results.find("dkim/result").text if auth_results is not None and auth_results.find("dkim/result") is not None else None,
                },
            }
            result["records"].append(record)

        return result

    except Exception as e:
        log.error(f"Failed to parse {xml_path}: {e}")
        return {}


# -------------------- EXPORT FUNCTIONS --------------------
def export_json(all_reports: List[Dict[str, Any]], output_dir: Path):
    path = output_dir / "dmarc_reports.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(all_reports, f, indent=2)
    log.info(f"✅ Exported JSON → {path}")


def export_csv(all_records: List[Dict[str, Any]], output_dir: Path):
    if not all_records:
        return
    path = output_dir / "dmarc_records.csv"
    fields = ["file", "source_ip", "count", "header_from", "spf_domain", "spf_result", "dkim_domain", "dkim_result"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in all_records:
            writer.writerow(r)
    log.info(f"✅ Exported CSV → {path}")


# -------------------- MAIN FLOW --------------------
def main():
    # 1. Fetch emails
    fetch_by_subject(SUBJECT_MATCH, OUTPUT_DIR)

    # 2. Extract archives
    extracted_files = extract_all_reports(OUTPUT_DIR)

    # 3. Parse each report
    all_reports = []
    all_records = []
    for xml_file in extracted_files:
        if xml_file.suffix.lower() != ".xml":
            continue
        report = parse_dmarc_report(xml_file)
        if report:
            all_reports.append(report)
            # flatten records for CSV
            for r in report["records"]:
                all_records.append(
                    {
                        "file": report["file"],
                        "source_ip": r.get("source_ip"),
                        "count": r.get("count"),
                        "header_from": r.get("header_from"),
                        "spf_domain": (r.get("spf") or {}).get("domain"),
                        "spf_result": (r.get("spf") or {}).get("result"),
                        "dkim_domain": (r.get("dkim") or {}).get("domain"),
                        "dkim_result": (r.get("dkim") or {}).get("result"),
                    }
                )

    # 4. Export
    export_json(all_reports, OUTPUT_DIR)
    export_csv(all_records, OUTPUT_DIR)


if __name__ == "__main__":
    main()
