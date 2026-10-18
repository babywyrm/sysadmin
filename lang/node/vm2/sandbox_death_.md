

##
#
https://nakedsecurity.sophos.com/2023/04/09/popular-server-side-javascript-security-sandbox-vm2-patches-remote-execution-hole/
#
https://codesandbox.io/examples/package/vm2
#
##

PoC exploit released for VM2 JavaScript sandbox library vulnerability
Home / Threat Intelligence bulletins / PoC exploit released for VM2 JavaScript sandbox library vulnerability

Update: PoC exploit available for VM2 library Sandbox escape vulnerability – 18th April 2023
Overview
A Proof-of-Concept (PoC) code has been disclosed for the vulnerabilities, tracked as CVE-2023-30547 (CVSS score: 9.8 – critical) and CVE-2023-29199 (CVSS score: 9.8 – critical), that allows for the execution of malicious code on a host running the VM2 sandbox. This follows a recent release of previous PoC for CVE-2023-29017

Exploitation of these vulnerabilities allows threat actors to escape the sandbox restrictions and perform arbitrary code execution on target host systems, opening up the potential for significant attack efforts.

Updated Impact
– Successful exploitation of CVE-2023-30547 allows threat actors to raise an unsanitised host exception inside “handleException()” which can be used to escape the sandbox and run arbitrary code on a target host.

– Successful exploitation of CVE-2023-29199 allows threat actors to bypass “handleException()” and leak unsanitised host exceptions which can be used to escape the sandbox and run arbitrary code on a target host. A threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox.

Updated Containment, Mitigations & Remediations
There are currently no known workarounds for these vulnerabilities. As such, it is strongly recommended that all users of the VM2 library upgrade to version 3.9.17 as soon as possible.

Updated Further Information
PoC GitHub Repository

Target Industry
Indiscriminate, opportunistic targeting.

Overview
Severity Level – Critical: Compromise will result in the loss of confidentiality and integrity of data.

A proof-of-concept (PoC) exploit code has been released for the recently disclosed VM2 vulnerability, tracked as CVE-2023-29017 (CVSSv3 Score: 10.0). The security flaw pertains to the VM2 library JavaScript sandbox, which is applied to run untrusted code in virtualised environments on Node.js servers. The vulnerability was discovered to be related to the VM2 library improperly handling the host objects passed to the ‘Error.prepareStackTrace’ function when an asynchronous error occurs.

The PoC creates a new file named, ‘flag’, on the host system. Assuming that VM2’s sandbox protections can be bypassed, this leads to the execution of commands to create arbitrary files on the target system.

Impact
Successful exploitation of CVE-2023-29017 would allow a threat actor to bypass the sandbox protections to gain remote code execution capabilities on the host running the sandbox.

Vulnerability Detection
VM2 has released the required security patch for the vulnerability of the respective product versions. As such, previous versions are vulnerable to potential exploitation.

Affected Products
VM2 versions 3.9.14 and prior
Node version: 18.15.0, 19.8.1, 17.9.1
Containment, Mitigations & Remediations
This vulnerability was patched in the release of VM2 version 3.9.15. As such, users are strongly recommended to apply the patch as soon as possible. At the time of this writing, there are not currently any known workaround protocols.

Indicators of Compromise
No specific Indicators of Compromise (IoC) are available at this time.

Threat Landscape
VM2 receives over 17 million monthly downloads and is used by many different IT platforms, including integrated development environments (IDEs), function-as-a-service (FaaS) solutions, and penetration-testing frameworks. Given that threat actors generally utilise a combination of probability and asset value to determine which attack surfaces to focus on, virtual machine platforms can emerge as a prime target for threat actors. Due to the fact that such platforms have become an integral aspect of both personal and business operations, threat actors will continue to exploit vulnerabilities contained within the associated products in an attempt to exfiltrate the sensitive data contained therein.

In October 2022, VM2 were subjected to another critical vulnerability, CVE-2022-36067 (CVSSv3 Score: 10.0), which also allowed threat actors to escape the sandbox environment and run commands on the host system.

Threat Group
No attribution to specific threat actors or groups has been identified at the time of this writing.

Mitre Methodologies
Tactic:

TA0002 – Execution

TA0008 – Lateral Movement

Lateral Movement Technique:

T1210 – Exploitation of Remote Services

