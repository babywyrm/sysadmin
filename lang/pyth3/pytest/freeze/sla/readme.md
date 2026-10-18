### SLA Testing with Freezegun ( Probably.. )

Use Freezegun to verify date-based SLAs (e.g. CVE remediation windows) reliably. 

The table below illustrates common boundary cases and why this pattern works:

| Scenario                        | Disclosure Date | “Today” (freeze) | SLA Days | Business-Day Mode | Expected   | Notes                                                                       |
|---------------------------------|-----------------|------------------|----------|------------------|------------|-----------------------------------------------------------------------------|
| On calendar-day deadline        | 2025-01-01      | 2025-01-31       | 30       | No               | Not breached | 30 days after Jan 1 is Jan 31; SLA not yet expired                          |
| Day after calendar deadline     | 2025-01-01      | 2025-02-01       | 30       | No               | Breached    | First calendar day past the deadline                                        |
| Weeks later                     | 2025-01-01      | 2025-03-01       | 30       | No               | Breached    | Long after deadline → still breached                                         |
| On business-day deadline        | 2025-01-01      | 2025-02-12       | 30       | Yes              | Not breached | 30 business days (Mon–Fri) from Jan 1 lands on Feb 12                        |
| Day after business-day deadline | 2025-01-01      | 2025-02-13       | 30       | Yes              | Breached    | First business-day past the deadline                                         |
| Variable SLA length             | 2025-03-17      | 2025-05-01       | 45       | No               | Not breached | 45 calendar days after Mar 17 is May 1; this day is deadline, not yet breached |
| Leap-year edge (calendar days)  | 2024-02-29      | 2024-03-30       | 30       | No               | Not breached | 2024 is a leap year; 30 days after Feb 29 is Mar 30                          |
| Leap-year edge (biz days)       | 2024-02-29      | 2024-04-11       | 30       | Yes             | Not breached | 30 business days after Feb 29 lands on Apr 11 (skips weekends)               |

#### Why this works

- **Deterministic “today”**  
  Freezegun’s `@freeze_time` pins `datetime.now()` so your tests always run against a known date without waiting.

- **Edge-case coverage**  
  You can simulate:
  - Calendar vs. business-day counting  
  - Leap-year quirks  
  - Variable SLA lengths  
  - Off-by-one boundary checks  

- **Scalable, data-driven tests**  
  Parametrize dozens or hundreds of (disclosure, freeze, SLA) combinations in a table-driven style.

- **CI-friendly**  
  No reliance on the real clock—your SLA rules will be validated consistently on every CI run.


##
##
