

##
#
https://www.splunk.com/en_us/blog/security/aws-iam-privilege-escalation-threat-research-release-march-2021.html
#
https://boxboat.com/2023/03/15/github-splunk-integration/
#
##
  
SECURITY
Detecting AWS IAM Privilege Escalation
Splunk Threat Research Team  By Splunk Threat Research Team April 05, 2021
The Splunk Threat Research Team developed an analytic story to help security operations center (SOC) analysts detect adversaries attempting to escalate their privileges and gain elevated access to Amazon Web Services (AWS) resources. In this blog, we will:

Walk you through an AWS privilege escalation analytic story.
Demonstrate how we simulated these attacks using Atomic Red Team.
Collect and analyze the AWS cloudtrail logs.
Highlight a few detections from the releases.
Watch the video below to learn more about how we can simulate AWS Privilege Escalation TTPs using Atomic Red Team and detection engineering.


Amazon Web Services Identity and Access Management (IAM) Privilege Escalation
The AWS identity and access management (IAM) privilege escalation analytic story addresses various tactics, techniques and procedures (TTPs) used by attackers to escalate their privileges to gain additional access to an existing compromised AWS Environment.  

AWS provides a neat feature called identity and access management (IAM) that helps organizations manage various AWS services and resources in a secure way. All IAM users have roles, groups and policies associated with them that govern and set permissions to allow specific users to bypass specific restrictions. 

However, if these IAM policies are misconfigured (which is often the case) and also have specific combinations of weak permission, attackers can escalate their privileges to move laterally or further compromise the organization.

Rhino Security Labs and Bishop Fox Labs published comprehensive blogs detailing the various techniques attackers use to exploit IAM policies to gain elevated access. Inspired by their research, the Splunk Threat Research Team simulated these attacks using Atomic Red Team’s framework to allow for repeatability, and curated and collected the AWS Cloudtrail datasets, to provide you with detection queries to help uncover these potentially malicious events. 

Since privilege escalation typically happens after exploitation, we made a few assumptions as we developed and simulated these detections:

We assumed the attacker already gained access to leaked AWS credentials (Access key and Secret key), allowing them to programmatically interact with AWS. 
We assumed the victim has either full access to the AWS services, or enough permissions to allow an attacker to escalate their privileges and expand their access.  
 
Important Disclaimers
Atomic Red Team now supports writing atomics for AWS, Azure and GCP. The part of the demo video above showing attack simulation has slightly changed. Read more on how to write atomics for cloud. The TTPs and detection analytics in Splunk are relevant today and used by adversaries.
 
Here are a few examples of our Detection Searches:
Name

Technique ID

Tactic(s)

Note

AWS Create Policy Version to allow all resources

T1078.004

Privilege Escalation, Persistence

This query identifies a new policy created to allow “all” access to resources, which can include normal administrative activity as well as malicious activity. 

AWS SetDefaultPolicyVersion

T1078.004

Privilege Escalation, Persistence

This query detects users who set default policy versions.

AWS CreateAccessKey

T1136.003

Privilege Escalation, Persistence

This query detects creation of access keys for other users.

AWS CreateLoginProfile

T1136.003

Privilege Escalation, Persistence

This query detects creation of login profile and console login events from the same source IP address. 

AWS UpdateLoginProfile

T1136.003

Privilege Escalation, Persistence

This query detects API calls when a new password is set for another user.


Why Should You Care?


The information security community has observed an increase in cloud-based attacks, including major breaches. Common to most of these incidents is a mix of leaked credentials and IAM policy misconfigurations. Rhino Security has published an excellent blog highlighting numerous ways in which AWS credentials get compromised. The Capital One breach is one of the best examples to show how damaging misconfiguration of IAM policies can be.

This is why monitoring Cloudtrail logs for specific events that lead to AWS privilege escalation is crucial in order for defenders to stay on top of these threats.  

Learn More
You can find the latest content about security analytic stories on GitHub and in Splunkbase. All of these detections are available in Splunk Security Essentials. 

Feedback
Any feedback or requests? Feel free to put in an Issue on Github and we’ll follow up. You can also  join us on the Slack channel #security-research. Follow these instructions If you need an invitation to our Splunk user groups on Slack.

