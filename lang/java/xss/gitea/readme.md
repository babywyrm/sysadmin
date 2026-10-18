Advisory CVE-2024-6886 references a vulnerability in the following Go modules:

# https://github.com/advisories/GHSA-4h4p-553m-46qh

Gitea Cross-site Scripting Vulnerability
Critical severity GitHub Reviewed Published on Aug 5, 2024 to the GitHub Advisory Database • Updated on Aug 7, 2024
Vulnerability details
Dependabot alerts
0
```
Package
 code.gitea.io/gitea (
Go
)
Affected versions
< 1.22.1
Patched versions
1.22.1
Description
Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability in Gitea Gitea Open Source Git Server allows Stored XSS.This issue affects Gitea Open Source Git Server: 1.22.0.
```
References
https://nvd.nist.gov/vuln/detail/CVE-2024-6886
go-gitea/gitea#31200
https://blog.gitea.com/release-of-1.22.1
go-gitea/gitea@b6280f4
https://pkg.go.dev/vuln/GO-2024-3056

##
##

Module
github.com/go-gitea/gitea
Description:
Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability in Gitea Gitea Open Source Git Server allows Stored XSS.This issue affects Gitea Open Source Git Server: 1.22.0.

References:

ADVISORY: https://nvd.nist.gov/vuln/detail/CVE-2024-6886
FIX: Split sanitizer functions and fine-tune some tests (#31192) go-gitea/gitea#31200
WEB: https://blog.gitea.com/release-of-1.22.1/
Cross references:

github.com/go-gitea/gitea appears in 20 other report(s):
data/excluded/GO-2022-0308.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2021-45325 #308) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0309.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2021-45326 #309) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0310.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2021-45327 #310) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0314.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2021-45329 #314) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0315.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2021-45331 #315) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0353.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2021-29134 #353) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0442.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2022-27313 #442) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0450.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2022-30781 #450) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0579.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: GHSA-36h2-95gj-w488 #579) EFFECTIVELY_PRIVATE
data/excluded/GO-2022-0823.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea/models: GHSA-f5fj-7265-jxhj #823) NOT_IMPORTABLE
data/excluded/GO-2022-0830.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: GHSA-g2qx-6ghw-67hm #830) NOT_IMPORTABLE
data/excluded/GO-2022-0846.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea/models: GHSA-hpmr-prr2-cqc4 #846) NOT_IMPORTABLE
data/excluded/GO-2022-0862.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea/models: GHSA-q47x-6mqq-4w92 #862) NOT_IMPORTABLE
data/excluded/GO-2022-1065.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2022-42968 #1065) EFFECTIVELY_PRIVATE
data/excluded/GO-2023-1999.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2022-38795 #1999) EFFECTIVELY_PRIVATE
data/excluded/GO-2023-2221.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2019-1000002 #2221) LEGACY_FALSE_POSITIVE
data/excluded/GO-2023-2222.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2019-1010314 #2222) LEGACY_FALSE_POSITIVE
data/excluded/GO-2023-2234.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2019-11576 #2234) LEGACY_FALSE_POSITIVE
data/excluded/GO-2023-2276.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2020-14144 #2276) LEGACY_FALSE_POSITIVE
data/excluded/GO-2023-2298.yaml (x/vulndb: potential Go vuln in github.com/go-gitea/gitea: CVE-2020-28991 #2298) LEGACY_FALSE_POSITIVE
See doc/quickstart.md for instructions on how to triage this report.
```
id: GO-ID-PENDING
modules:
    - module: github.com/go-gitea/gitea
      vulnerable_at: 1.22.1
summary: CVE-2024-6886 in github.com/go-gitea/gitea
cves:
    - CVE-2024-6886
references:
    - advisory: https://nvd.nist.gov/vuln/detail/CVE-2024-6886
    - fix: https://github.com/go-gitea/gitea/pull/31200
    - web: https://blog.gitea.com/release-of-1.22.1/
source:
    id: CVE-2024-6886
    created: 2024-08-06T05:01:11.358806801Z
review_status: UNREVIEWED

