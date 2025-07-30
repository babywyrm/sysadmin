#!/usr/bin/env python3
"""
DMARC Report Fetcher & ZIP Extractor -  ~~beta~~refresh~~ 
"""

import imaplib
import email
import zipfile
import logging
from pathlib import Path
from email.message import Message
from typing import Optional

# ==== CONFIGURATION ====
IMAP_SERVER = 'mail.feanor.net'
IMAP_USER = 'administrator@feanor.net'
IMAP_PASSWORD = 'fus######f###F#sd9'
SUBJECT_MATCH = 'Report domain:'
OUTPUT_DIR = Path('/root/DMARC_FETCH/OUTPUT')

# ==== LOGGING SETUP ====
logging.basicConfig(level=logging.INFO, format="[*] %(message)s")
log = logging.getLogger(__name__)


def connect_imap(server: str, user: str, password: str) -> imaplib.IMAP4_SSL:
    log.info(f"Connecting to IMAP server {server}")
    m = imaplib.IMAP4_SSL(server)
    m.login(user, password)
    m.select("INBOX")
    return m


def download_attachments(mailbox: imaplib.IMAP4_SSL, email_id: bytes, output_dir: Path) -> None:
    typ, data = mailbox.fetch(email_id, "(BODY.PEEK[])")
    if typ != 'OK' or not data or not data[0]:
        log.warning(f"Failed to fetch email ID {email_id}")
        return

    msg = email.message_from_bytes(data[0][1])

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        disposition = part.get("Content-Disposition", "")
        if "attachment" not in disposition:
            continue

        filename = part.get_filename()
        if not filename:
            continue

        # Ensure safe filename
        safe_name = Path(filename).name
        target_path = output_dir / safe_name

        log.info(f"Saving attachment: {target_path}")
        with open(target_path, "wb") as f:
            f.write(part.get_payload(decode=True))


def fetch_by_subject(subject: str, output_dir: Path):
    mailbox = connect_imap(IMAP_SERVER, IMAP_USER, IMAP_PASSWORD)
    try:
        status, message_ids = mailbox.search(None, f'(SUBJECT "{subject}")')
        if status != 'OK':
            log.warning("No messages found.")
            return

        ids = message_ids[0].split()
        log.info(f"Found {len(ids)} emails matching subject '{subject}'")

        output_dir.mkdir(parents=True, exist_ok=True)

        for email_id in ids:
            download_attachments(mailbox, email_id, output_dir)

    finally:
        mailbox.logout()


def safe_extract_zip(zip_path: Path, extract_dir: Path) -> None:
    log.info(f"Extracting {zip_path}...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            member_path = extract_dir / member.filename
            if not str(member_path.resolve()).startswith(str(extract_dir.resolve())):
                log.warning(f"Skipping suspicious path: {member.filename}")
                continue
            zip_ref.extract(member, extract_dir)


def extract_all_zips_in_dir(dir_path: Path):
    for item in dir_path.glob("*.zip"):
        safe_extract_zip(item, dir_path)
        # Uncomment if you want to delete ZIPs after extract
        # item.unlink()


def main():
    fetch_by_subject(SUBJECT_MATCH, OUTPUT_DIR)
    extract_all_zips_in_dir(OUTPUT_DIR)


if __name__ == "__main__":
    main()
