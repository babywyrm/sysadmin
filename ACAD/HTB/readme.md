

# Pre-engagement 

educating the client and adjusting the contract. All necessary tests and their components are strictly defined and contractually recorded. In a face-to-face meeting or conference call, many arrangements are made, such as:

1.  Non-Disclosure Agreement
2.  Goals
3.  Scope
4.  Time Estimation
5.  Rules of Engagement



# Stage	Description

1.  Pre-Engagement	
The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions.

2.  Information Gathering	
Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions.

3.  Vulnerability Assessment	
With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions.

4.  Exploitation	
Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities.

5.  Post-Exploitation	
Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations).

6.  Lateral Movement	
If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered.

7.  Proof-of-Concept	
We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities.

8.  Post-Engagement	
Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings.


##
##
##

# Prep

Document	Timing for Creation
1. Non-Disclosure Agreement (NDA)	After Initial Contact
2. Scoping Questionnaire	Before the Pre-Engagement Meeting
3. Scoping Document	During the Pre-Engagement Meeting
4. Penetration Testing Proposal (Contract/Scope of Work (SoW))	During the Pre-engagement Meeting
5. Rules of Engagement (RoE)	Before the Kick-Off Meeting
6. Contractors Agreement (Physical Assessments)	Before the Kick-Off Meeting
7. Reports	During and after the conducted Penetration Test

##
##

# Kick-off

The kick-off meeting usually occurs at a scheduled time and in-person after signing all contractual documents. This meeting usually includes client POC(s) (from Internal Audit, Information Security, IT, Governance & Risk, etc., depending on the client), client technical support staff (developers, sysadmins, network engineers, etc.), and the penetration testing team (someone in a management role (such as the Practice Lead), the actual penetration tester(s), and sometimes a Project Manager or even the Sales Account Executive or similar). We will go over the nature of the penetration test and how it will take place. Usually, there is no Denial of Service (DoS) testing. We also explain that if a critical vulnerability is identified, penetration testing activities will be paused, a vulnerability notification report will be generated, and the emergency contacts will be contacted. Typically these are only generated during External Penetration Tests for critical flaws such as unauthenticated remote code execution (RCE), SQL injection, or another flaw that leads to sensitive data disclosure. The purpose of this notification is to allow the client to assess the risk internally and determine if the issue warrants an emergency fix. We would typically only stop an Internal Penetration Test and alert the client if a system becomes unresponsive, we find evidence of illegal activity (such as illegal content on a file share) or the presence of an external threat actor in the network or a prior breach.

Explaining the penetration testing process gives everyone involved a clear idea of our entire process. This demonstrates our professional approach and convinces our questioners that we know what we are doing. Because apart from the technical staff, CTO, and CISO, it will sound like a certain kind of magic that is very difficult for non-technical professionals to understand. So we must be mindful of our audience and target the most technically inexperienced questioner so our approach can be followed by everyone we talk to.

All points related to testing need to be discussed and clarified. It is crucial to respond precisely to the wishes and expectations of the customer/client. Every company structure and network is different and requires an adapted approach. Each client has different goals, and we should adjust our testing to their wishes. We can typically see how experienced our clients are in undergoing penetration tests early in the call, so we may have to shift our focus to explain things in more detail and be prepared to field more questions, or the kickoff call may be very quick and straightforward.

##


# Documentation and Reporting

Before completing the assessment and disconnecting from the client's internal network or sending "stop" notification emails to signal the end of testing (meaning no more interaction with the client's hosts), we must make sure to have adequate documentation for all findings that we plan to include in our report. This includes command output, screenshots, a listing of affected hosts, and anything else specific to the client environment or finding. We should also make sure that we have retrieved all scan and log output if the client hosted a VM in their infrastructure for an internal penetration test and any other data that may be included as part of the report or as supplementary documentation. We should not keep any Personal Identifiable Information (PII), potentially incriminating info, or other sensitive data we came across throughout testing.

We should already have a detailed list of the findings we will include in the report and all necessary details to tailor the findings to the client's environment. Our report deliverable (which is covered in detail in the Documentation & Reporting module) should consist of the following:

An attack chain (in the event of full internal compromise or external to internal access) detailing steps taken to achieve compromise
A strong executive summary that a non-technical audience can understand
Detailed findings specific to the client's environment that include a risk rating, finding impact, remediation recommendations, and high-quality external references related to the issue
Adequate steps to reproduce each finding so the team responsible for remediation can understand and test the issue while putting fixes in place
Near, medium, and long-term recommendations specific to the environment
Appendices which include information such as the target scope, OSINT data (if relevant to the engagement), password cracking analysis (if relevant), discovered ports/services, compromised hosts, compromised accounts, files transferred to client-owned systems, any account creation/system modifications, an Active Directory security analysis (if relevant), relevant scan data/supplementary documentation, and any other information necessary to explain a specific finding or recommendation further
At this stage, we will create a draft report that is the first deliverable our client will receive. From here, they will be able to comment on the report and ask for any necessary clarification/modifications.
