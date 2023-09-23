CLOUD AWS PENTEST SERIES IAM ENUMERATION
Alparslan Akyıldız academy

##
#
https://alparslanakyildiz.medium.com/cloud-aws-pentest-series-iam-enumeration-b2ed922e7cab
#
##

Alparslan Akyıldız academy
·

Follow
5 min read
·
Jun 13

IAM (Identity and Access Management) is an essential aspect of securing your AWS (Amazon Web Services) infrastructure. It helps you control access to your AWS resources by enabling you to manage users, groups, and permissions effectively. In your cyber security article about IAM in AWS, you can cover the following key points:

1. Introduction to IAM: Begin by explaining what IAM is and why it is crucial for securing AWS resources. Highlight how IAM provides centralized control over user authentication, authorization, and resource permissions.

2. Key IAM Components: Describe the main components of IAM, such as users, groups, roles, and policies. Explain how users represent individuals, groups organize users with similar access needs, roles define permissions for AWS services, and policies define permissions for users and roles.

3. User Management: Discuss the process of creating and managing IAM users. Explain how to grant users access to the AWS Management Console and provide an overview of user password policies and multi-factor authentication (MFA) options.

4. Group Management: Explore the concept of groups and their importance in IAM. Discuss how groups simplify permission management by allowing you to assign policies to multiple users simultaneously.

5. Role-Based Access Control (RBAC): Explain how IAM roles help enforce the principle of least privilege. Discuss how roles are associated with specific permissions and how they can be assumed by trusted entities such as EC2 instances or Lambda functions.

6. Access Policies: Discuss the structure and syntax of IAM policies. Explain how policies define the permissions and resources that users or roles can access. Highlight the use of policy variables, conditions, and policy simulation tools for fine-grained access control.

7. Security Best Practices: Provide a list of recommended best practices for IAM in AWS, including:

· Regularly reviewing and auditing IAM policies to ensure they align with the principle of least privilege.

· Enforcing strong password policies and enabling MFA for all IAM users.

· Leveraging AWS CloudTrail to monitor and log IAM actions for security analysis.

· Utilizing IAM roles instead of long-term access keys for AWS service authentication.

· Applying the concept of separation of duties to limit the scope of each IAM user’s access.

8. Integration with Other AWS Services: Highlight how IAM integrates with other AWS services to enhance security. For example, you can mention how IAM works with AWS S3 bucket policies, AWS CloudFormation, AWS Identity Federation, and more.

9. Multi-Account IAM: Discuss the challenges and best practices for managing IAM across multiple AWS accounts, including the use of AWS Organizations, consolidated billing, and cross-account access.

Ok after a brief information about IAM now we jump the enumeration about IAM user and groups for finding weak permissions to exploit them. First we need to install awscli and we need to configure aws access key id and access private keys for connecting the cloud services.

aws iam list-users commad is utilized for listing the cyrrent users on the aws account.

If you wonder that the which group does have a spesific user you can use aws iam list-groups-for-user — username user — profile profilename command.

ad-adminson user is in the ad-Admin group. For learning which policies are attached to user the following command can be used;

aws iam list-attached-user-policies — user-name ad-user — profile iamlab1

Certificates are very curicial for authentication issues. So For enumerating the signing certificates of the spesific user;

aws iam list-signing-certificates — user-name <user> — profile <profile name>

command can be utilized.

SSH is commonly used protocol for secure shell connections and it gives the users an opportunity like getting directly shell from terminal instead of using access keys for connections.

MFA (multi factor authentication) is the another important security mechanism for preventing attackers to access to credential cmpromised accounts. So for enumerating the MFA statament of the user account we can utilize this command;

aws iam list-virtual-mfa-devices — profile <profile name>
aws iam list-virtual-mfa-devices

For wieving login profile information;
aws iam get-login-profile — user-name <user>

As you see for this user PasswordResetRequired is false.

Which were groups created?
aws iam list-groups — profile <profile name>

If you can find out the names of the groups, in the next step you can dig group policies;
aws iam list-group-policies — group-name <group name>

The next step is, which policy are attached to groups? For answering this question;
aws iam list-attached-group-policies — group-name

For listing all policies;
aws aim list-policies

For getting the policy details;

Roles are used for delagating the privilige or defining which user or group what do can. For listing the roles;
aws iam list-roles

For getting role deatils;
aws iam get-role — role-name <role>

Returns a set of temporary security credentials that you can use to access Amazon Web Services resources. These temporary credentials consist of an access key ID, a secret access key, and a security token. Typically, you use AssumeRole within your account or for cross-account access. For a comparison of AssumeRole with other API operations that produce temporary credentials, see Requesting Temporary Security Credentials and Comparing the Amazon Web Services STS API operations in the IAM User Guide

https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html

Thank you for reading.
