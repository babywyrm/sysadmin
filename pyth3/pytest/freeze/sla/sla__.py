from datetime import datetime, date, timedelta

def is_sla_breached(disclosure_date: date, sla_days: int = 30) -> bool:
    """
    Returns True if today’s date is strictly after (disclosure_date + sla_days).
    All comparisons are done on .date(), so time‐of‐day is ignored.
    """
    today = datetime.now().date()
    deadline = disclosure_date + timedelta(days=sla_days)
    return today > deadline

##
##
