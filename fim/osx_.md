Securing mailboxes in the era of persistent threats

##
#[SSTIC2021-Article-runtime_security_with_ebpf-fournier_afchain_baubeau.pdf](https://github.com/babywyrm/sysadmin/files/15102632/SSTIC2021-Article-runtime_security_with_ebpf-fournier_afchain_baubeau.pdf)

https://material.security/blog/protecting-the-security-and-privacy-of-our-customers
#
##


    We believe security products should be simple, elegant, pragmatic—and loved.

‹  Back
October 30, 2023 · 7m read
File Access Monitoring with Osquery: Weaponize your entire macOS fleet into a filesystem-based honeypot

Chris Long 

Protecting the security and privacy of our customers' data is our top priority at Material Security. 
We are constantly improving our ability to detect and respond to increasingly sophisticated threats, and in this scenario we saw an opportunity to contribute an incredibly powerful capability to osquery, a widely used open-source security utility. This new capability greatly improves defenders' ability to detect initial access and reconnaissance activity on macOS endpoints, slowing down a potential attacker. With our open source contribution, this capability is now available to all osquery users.

File Integrity Monitoring Limitations

File integrity monitoring (FIM) is a feature in osquery that allows you to detect file creations, renames, deletions, or modifications. However, these events lack contextual information around which processes or users were responsible for the change – making the investigation of these events difficult or impossible. Similar features in other security tools suffer from the same limitations.

As attacker tradecraft has evolved, it's no longer sufficient to only monitor and detect changes being made to sensitive files. It's well understood that employee workstation filesystems usually contain sensitive data including, but not limited to:

    Cloud platform access keys
    Browser cookies and browsing history
    Electron app cookies/session tokens
    Shell history files
    Keychain files
    Password vaults

Consider SwiftBelt, a macOS post-exploitation tool modeled after Seatbelt. SwiftBelt contains functions to search systems for cloud provider credentials, bookmarks, and other sensitive data that is likely to be resident on user endpoints. This information helps attackers understand what security tools or controls are present on the host, and it surfaces credentials that may allow them to escalate privileges or pivot to other systems.

To access sensitive information, attackers only need to view or copy the file contents from the filesystem. File integrity monitoring does not address this problem.
File Access Monitoring in Osquery

To address these limitations in osquery, we teamed up with Sharvil Shah (owner of Orchard Labs) to develop and open source macOS file access monitoring in osquery. Any open() syscall will trigger a file access event. Beginning with version 5.10.2 of osquery, this functionality is now available to all osquery users running macOS Ventura or greater.

macOS osquery file access monitoring leverages the existing es_process_file_events table and allows users to define a set of sensitive files or directories to monitor. Any time a process accesses that file, osquery will create an event that contains:

    The type of file access (open, modify, etc)
    The filename being accessed
    The PID of the process that accessed the file
    The parent PID of the process that accessed the file
    The command line arguments of the command associated with the PID
    The file path associated with the PID that accessed the file
    The timestamp of the file access

Because sensitive files on disk are typically only accessed by a predictable and finite set of applications (e.g. Chrome is probably the only process that should access your Chrome Cookies database file), achieving a baseline of expected file access by process is a relatively trivial undertaking once a few days of data has been collected. For example, it would be reasonable to expect your system's ssh to access your ssh_config file.
Enabling File Access Monitoring

To take advantage of this new functionality, you must define the file paths you want to monitor under the file_paths directive and the following osquery flags must be set:

If you're looking for inspiration on what files are worth monitoring, I highly recommend taking a look at the SearchCreds() function in SwiftBelt.
Lay the Defensive Minefield

Today, adversaries are often able to explore the filesystem contents of a compromised system without a high probability of being detected. Engineers regularly use system utilities like "cat", "less", "more", and "grep". Because of this frequent use, security teams rarely create robust detections around their usage. If they do, there's a high risk of either false positives (if the detection is too broad) or false negatives (if the detection is too specific). Alerting on suspicious/anomalous usage of "cat" in your environment is likely to be futile, and alerting on overly specific command line strings such as "cat /etc/passwd" ignores a myriad of alternative ways an attacker could view the contents of /etc/passwd without using "cat". 

By first defining a list of files and/or directories that we know to contain sensitive content, we greatly reduce the chance of false positives. Let's use Chrome as an example. Within the directory that stores Chrome profiles, we can define a list of files we consider to be sensitive in our osquery config. We use Fleet, so our config is in YAML format:

We expect the Chrome application to access or modify these files, but any other application that does so is unexpected and unusual (at least in our environment). So, to detect any anomalous access to these files, we could write the following query:

This will cause an event to be emitted anytime a process accesses one of the files listed above as long as the process' path is not within the /Applications/Google Chrome.app/ directory.
Be Deceptive

This functionality can also be extended by seeding fake sensitive files across the filesystem. Years ago, we seeded canary GCP service account keys across our developers' workstations. "Canary" in this context refers to a set of keys that are functional, but have no associated permissions. During one of our annual penetration tests, a tester with ceded workstation access discovered the key and attempted to use it which immediately alerted us to their presence. Canaries have historically been limited to file types which change the state of some external system (e.g. cloud access tokens, documents, etc). Using osquery's file access monitoring, any file on the filesystem can be a canary; just the act of inspecting the contents of a file is sufficient to trigger an alert.

This functionality gives us the ability to greatly impair adversaries' ability to leverage files on a compromised endpoint. If an attacker has to worry about any arbitrary file on the filesystem being monitored for access, it will cause them to operate much slower, and ultimately a single mistake could lead to discovery and eviction from the environment. No detection method is foolproof, but we believe this an extremely effective and efficient way of imposing cost on our adversaries.
