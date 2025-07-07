import requests
import json
from datetime import datetime

## example slack alerter
WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK")  # export SLACK_WEBHOOK=https://hooks.slack...

def send_alert(host, message, level="info"):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "host": host,
        "level": level.upper(),
        "message": message
    }
    # Append to log file
    with open("alerts.jsonl", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    # Slack webhook alert
    if WEBHOOK_URL:
        payload = {
            "text": f"*{level.upper()}* alert on `{host}`:\n```{message}```"
        }
        try:
            requests.post(WEBHOOK_URL, json=payload, timeout=3)
        except Exception:
            pass  # Fail silently

##
##
