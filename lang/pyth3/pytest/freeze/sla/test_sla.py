import pytest
from datetime import date
from freezegun import freeze_time
from sla import is_sla_breached

DISCLOSURE = date(2025, 1, 1)

@freeze_time("2025-01-31")
def test_calendar_sla_not_breached():
    # 30 calendar days after Jan 1 is Jan 31
    assert is_sla_breached(DISCLOSURE, sla_days=30, business_days=False) is False

@freeze_time("2025-02-01")
def test_calendar_sla_breached():
    assert is_sla_breached(DISCLOSURE, sla_days=30, business_days=False) is True

@freeze_time("2025-02-26")
def test_business_sla_not_breached():
    # 20th day is Friday Feb 21, then skip weekend, 30 business days later lands on Wed Mar 12
    # but on Feb 26 it’s still before deadline
    assert is_sla_breached(DISCLOSURE, sla_days=30, business_days=True) is False

@freeze_time("2025-03-13")
def test_business_sla_breached():
    # One day after the 30th business‐day deadline
    assert is_sla_breached(DISCLOSURE, sla_days=30, business_days=True) is True

@pytest.mark.parametrize("disclosure,check_date,days,bdays,expected", [
    (date(2025,1,1), "2025-01-31", 30, False, False),
    (date(2025,1,1), "2025-02-01", 30, False, True),
    (date(2025,1,1), "2025-02-27", 30, True, False),  # after skipping weekends
    (date(2025,1,1), "2025-02-28", 30, True, True),
])
def test_parametrized_sla(disclosure, check_date, days, bdays, expected):
    @freeze_time(check_date)
    def inner():
        assert is_sla_breached(disclosure, sla_days=days, business_days=bdays) is expected
    inner()
