
##
#
https://www.crowdsec.net/blog/protect-your-applications-with-aws-waf-and-crowdsec
#
https://github.com/crowdsecurity/cs-aws-waf-bouncer
#
##

Protect your applications with AWS WAF and CrowdSec
Learn how to configure the AWS WAF bouncer to protect an application running behind an ALB with the ability to block both IPs and countries.

In this article, we will see how to install and configure the newly released AWS WAF bouncer and use it to protect a simple Nginx web server running behind an Application Load Balancer.
Our target infrastructure is:


AWS WAF is a managed Web Application Firewall offering, allowing you to inspect requests and block them (or display a captcha) based on criteria of your choosing.

It can inspect requests to:

API Gateway REST API
Cloudfront distributions
Application Load Balancer
AppSync GraphQL API
The CrowdSec bouncer takes advantage of this to:

Either block or display a captcha to IPs or ranges for which CrowdSec has a decision
Either block or display a captcha to countries for which CrowdSec has a decision
CrowdSec for Windows will also be able to detect network scans that attempt to get past the Windows firewall.

Bouncer installation
First, we will install CrowdSec and the bouncer.

Add the CrowdSec repository to your system (for this article, we will be using an Ubuntu 20.04 server):

curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
If you are using another OS, please refer to the documentation to install CrowdSec on your distribution: https://docs.crowdsec.net/docs/getting_started/install_crowdsec

Next, we will install CrowdSec:

sudo apt install crowdsec
This command will install CrowdSec and automatically detect supported services running (we already have an Nginx server installed, so CrowdSec will automatically monitor its logs and enable the Nginx collection).

Finally, we will install the bouncer:

sudo apt install crowdsec-aws-waf-bouncer
This will install the bouncer, and automatically register it with the local API.

You can check that the bouncer registered itself properly by running “cscli bouncers list”.

root@ip-172-31-29-160:~# cscli bouncers list
---------------------------------------------------------------------------------------------------------------------------------------------------------
NAME                IP ADDRESS  VALID  LAST API PULL         TYPE                      VERSION                                                          
---------------------------------------------------------------------------------------------------------------------------------------------------------
 AWS-WAF-1647938971  127.0.0.1   ✔      2022-04-26T09:25:02Z  crowdsec-aws-waf-bouncer  v0.1.3-debian-pragmatic-92d8fc9061f2b1b602ba4d836fcb112c5f11d4fd 
---------------------------------------------------------------------------------------------------------------------------------------------------------
root@ip-172-31-29-160:~#
AWS WAF configuration
In order to be able to use the bouncer, you will need to have created a web ACL (web access control list)  in AWS WAF and associate it with a (or multiple) AWS resources.

In this article, we will associate our ACL with an application load balancer (ALB) proxying traffic to an EC2 instance running a simple Nginx server.

We just need to create a new rule using the AWS console, and associate it with our ALB:


As we are adding the ACL to a regional resource (in this case, an ALB), the web ACL must live in the same region.

Bouncer configuration
First, we need to grant the bouncer the permissions to interact with the AWS WAF APIs.

For this article, the bouncer is running on an EC2 instance, so we can create an instance role with the following permissions and associate it to the instance:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": [
        "wafv2:DeleteIPSet",
        "wafv2:DeleteRuleGroup",
        "wafv2:CreateRuleGroup",
        "wafv2:UpdateWebACL",
        "wafv2:GetIPSet",
        "wafv2:UpdateRuleGroup",
        "wafv2:GetWebACL",
        "wafv2:GetRuleGroup",
        "wafv2:CreateIPSet",
        "wafv2:UpdateIPSet"
      ],
      "Resource": [
        "arn:aws:wafv2:*:*:*/webacl/*/*",
        "arn:aws:wafv2:*:*:*/ipset/*/*",
        "arn:aws:wafv2:*:*:*/rulegroup/*/*"
      ]
    },
    {
      "Sid": "VisualEditor1",
      "Effect": "Allow",
      "Action": [
        "wafv2:ListRuleGroups",
        "wafv2:ListWebACLs",
        "wafv2:ListIPSets"
      ],
      "Resource": "*"
    }
  ]
}
Of course, in a real-world deployment, you will want to restrict the permission of the bouncer to the ACLs and rule groups it will manage.

If you are not running the bouncer on EC2 (or do not want to use instance roles), the bouncer also supports authentication with an access key (it will look in $HOME/.aws/ for the default profile or the profile configured in the bouncer).

Before being able to start the bouncer, we will need to configure it with the name of the ACL we created previously, and a few other parameters:

api_key: 926c1f30880dcc691375504e856988bd
api_url: "http://127.0.0.1:8080/"
update_frequency: 10s
daemon: true
log_media: file
log_dir: /var/log/
log_level: info
waf_config:
  - web_acl_name: web-acl-article
  fallback_action: ban
  rule_group_name: crowdsec-rule-group-eu-west-1
  scope: REGIONAL
  region: eu-west-1
  ipset_prefix: crowdsec-ipset-eu-west-1
Some explanations on the waf_config section:

web_acl_name: this is the name of our web ACL, in which the bouncer will add its rule group
Fallback_action: If the bouncer receives a decision with an unknown type, use that instead
Rule_group_name: the name of the rule group in which the bouncer will add its rules
Scope: whether we are creating rules for a CloudFront distribution or not
Region: the AWS region in which everything will be created
When you’re done editing the configuration, just restart the bouncer by running systemctl restart crowdsec-aws-waf-bouncer for it to create a new rule group in your web ACL and the required IP sets.

It may take a minute for the bouncer to be fully up and running.

We will also modify the CrowdSec profiles.yaml to apply a captcha for all HTTP-related scenarios instead of a classic IP ban.

The profiles.yaml file tells CrowdSec what to do when it receives an alert (i.e., a scenario has been matched enough time for its bucket to overflow).

We will add the following at the top of /etc/crowdsec/profiles.yaml:

name: captcha_http_scenarios
filters:
- Alert.Remediation ==	true &&	Alert.GetScenario() startsWith "crowdsecurity/http-"
decisions:
- type: captcha
  duration: 4h
on_success: break
—
This instructs CrowdSec to create a `captcha` decision valid for 4h if the name of the scenario that triggered the alert starts with crowdsecurity/http-.

Restart (or reload) CrowdSec for the changes to take effect.

Testing the bouncer
To do so, we will simply run Nikto, a very noisy web scanner, in order to trigger decisions:

nikto -h lb-aws-waf-article-1898138181.eu-west-1.elb.amazonaws.com
CrowdSec will detect the attack and create a decision:

root@ip-172-31-29-160:~# cscli decisions list
+---------+----------+------------------+----------------------------+---------+---------+------------------+--------+-------------------+----------+
|   ID    |  SOURCE  |   SCOPE:VALUE    |           REASON           | ACTION  | COUNTRY |        AS        | EVENTS |    EXPIRATION     | ALERT ID |
+---------+----------+------------------+----------------------------+---------+---------+------------------+--------+-------------------+----------+
| 5167576 | crowdsec | Ip:42.42.42.42 | crowdsecurity/http-crawl-non-static | captcha | FR      | 12322 Free SAS |     43 | 3h59m7.904366287s |     1157 |
+---------+----------+------------------+----------------------------+---------+---------+------------------+--------+-------------------+----------+
The bouncer will the get the decision at its next poll cycle (by default, every 10s), and update the WAF configuration to display a captcha to the user (note that AWS may take some time to propagate the new configuration, but in our experience, it takes about 30s in most cases):




If we solve the captcha, we will gain access to the website:


The bouncer also supports decisions at a country level.

First, let’s delete our current decision: 

root@ip-172-31-29-160:~# cscli decisions delete -i 42.42.42.42
Next, let’s add a ban decision that will apply to all French IPs:

root@ip-172-31-29-160:~# cscli decisions add --scope country --value FR --type ban
If we visit our website from a French IP, we will get a 403:


Conclusion
In this article, we configured the AWS WAF bouncer to protect an application running behind an ALB and demonstrated its ability to block both IPs and countries. You can also use this bouncer to protect any application running behind CloudFront, a REST API Gateway, or an AppSync GraphQL API.

We have shown the bouncer running on an EC2 instance, but you can also easily run it in a container, for example with AWS Fargate.

The repository for the bouncer is available here: https://github.com/crowdsecurity/cs-aws-waf-bouncer

The documentation is available here: https://docs.crowdsec.net/docs/next/bouncers/aws_waf

The next article on AWS WAF protection will be dedicated to protecting applications in a serverless environment. Stay tuned!
