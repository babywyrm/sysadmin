
##
#
https://github.com/haproxy/haproxy/issues/2312
#
##

H2 rapid reset aka CVE-2023-44487 #2312
Open
darix opened this issue Oct 10, 2023 · 2 comments
Comments
@darix
darix commented Oct 10, 2023
Detailed Description of the Problem

An issue for tracking how haproxy is affected by CVE-2023-44487

    https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack
    https://blog.cloudflare.com/zero-day-rapid-reset-http2-record-breaking-ddos-attack/
    https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/

Expected Behavior

it should not be affected by CVE-2023-44487 :)
Steps to Reproduce the Behavior

see cloudflare technical blog
Do you have any idea what may have caused this?

h2 protocol level bug?
Do you have an idea how to solve the issue?

No response
What is your configuration?

not applicable

Output of haproxy -vv

not applicable

Last Outputs and Backtraces

No response
Additional Information

No response
@darix darix added status: needs-triage type: bug labels Oct 10, 2023
@janl
janl commented Oct 10, 2023

https://www.mail-archive.com/haproxy@formilux.org/msg44134.html
@GoVulnBot GoVulnBot mentioned this issue Oct 10, 2023
x/vulndb: potential Go vuln in github.com/envoyproxy/envoy: CVE-2023-44487 golang/vulndb#2106
Open
@wtarreau
Member
wtarreau commented Oct 10, 2023

Some updates and measurements there, along with some rules to avoid log pollution from random attackers that iwll inevitably appear in the next few days:

https://www.mail-archive.com/haproxy@formilux.org/msg44136.html

So far I failed to harm the process more than with regular traffic (neither CPU nor concurrency).

I will not post my reproducer for now because there's no point in easing the job of hurting various sites for script kiddies. However if anyone has an effective repro that manages to harm haproxy more than with h2load or other regular tools, I'm obviously interested.
@wtarreau wtarreau added status: cannot reproduce and removed status: needs-triage labels Oct 10, 2023
@wtarreau wtarreau changed the title h2 RST bug aka CVE-2023-44487 H2 rapid reset aka CVE-2023-44487 Oct 10, 2023
to join this conversation on GitHub. Already have an account? Sign in to comment
Assignees
No one assigned
Labels
status: cannot reproduce
type: bug
Projects
None yet
Milestone
No milestone
Development

No branches or pull requests
3 participants
@janl
@darix
@wtarreau
Footer
© 2023 GitHub, Inc.
Footer navigation

    Terms
    Privacy
    Security
    Status
    Docs
    Contact GitHub
    Pricing
    API
    Training
    Blog
    About

