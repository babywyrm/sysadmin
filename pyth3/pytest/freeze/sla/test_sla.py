import pytest
from datetime import date
from freezegun import freeze_time
from sla import is_sla_breached

DISCLOSURE = date(2025, 1, 1)

@freeze_time("2025-01-31")
def test_not_breached_on_deadline():
    # 30 days after Jan 1 is Jan 31 — not yet breached
    assert is_sla_breached(DISCLOSURE, sla_days=30) is False

@freeze_time("2025-02-01")
def test_breached_next_day():
    # Day 31 → breached
    assert is_sla_breached(DISCLOSURE, sla_days=30) is True

@freeze_time("2025-12-01")
def test_breached_months_later():
    # Long after deadline → still breached
    assert is_sla_breached(DISCLOSURE, sla_days=30) is True

@pytest.mark.parametrize("disclosure,check_date,days,expected", [
    (date(2025,1,1),   "2025-01-31", 30, False),
    (date(2025,1,1),   "2025-02-01", 30, True),
    (date(2025,6,15),  "2025-07-15", 30, False),
    (date(2025,6,15),  "2025-07-16", 30, True),
    (date(2024,12,1),  "2025-01-01", 31, False),
    (date(2024,12,1),  "2025-01-02", 31, True),
])
def test_sla_parametrized(disclosure, check_date, days, expected):
    """
    Table-driven boundary tests:
      - disclosure date
      - check_date (frozen “today”)
      - SLA length in days
      - expected breach flag
    """
    @freeze_time(check_date)
    def inner():
        assert is_sla_breached(disclosure, sla_days=days) is expected
    inner()
