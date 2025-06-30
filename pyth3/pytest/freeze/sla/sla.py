from datetime import datetime, date, timedelta

def is_sla_breached(
    disclosure_date: date,
    sla_days: int = 30,
    business_days: bool = False
) -> bool:
    """
    Returns True if today's date is strictly after the SLA deadline.

    :param disclosure_date: the date the CVE was disclosed
    :param sla_days: number of days allowed to remediate
    :param business_days: if True, count only weekdays; otherwise count calendar days
    """
    today = datetime.now().date()

    if business_days:
        # compute deadline by advancing only on weekdays
        days_added = 0
        deadline = disclosure_date
        while days_added < sla_days:
            deadline += timedelta(days=1)
            if deadline.weekday() < 5:  # Monday=0 … Friday=4
                days_added += 1
    else:
        # calendar‐day deadline
        deadline = disclosure_date + timedelta(days=sla_days)

    return today > deadline
