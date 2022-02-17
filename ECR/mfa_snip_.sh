## Implementation requirements
##   --If you tag it as latest, you won't know when it was built when you look at it later, so use the git revision at the time of release. --Caution: You should take the revision of the release branch, so change the master part as needed --Build if the image tagged with the specified revision does not already exist --Skip build if it exists --Tag the image for ECR with the specified revision tagged if it does not already exist --Skip tagging if it exists --Log in to ECR --Caution: Before logging in to the ECR, obtain the authentication information that can operate the AWS account in which the ECR exists. --Read the profile, if any. ――In my case, I need to obtain temporary authentication information with MFA, so that part is written. --Push the built image to ECR

## Bonus: MFA verification
##   This was annoying, so I hope it helps someone.
#############################################################

#Accepts mfa code input from standard input
read -p "Input mfa code: " mfaCode

result=$(aws sts assume-role \
  --role-arn arn:aws:iam::************:role/<role-name> \
  --role-session-name <session-name> \
  --serial-number <mfa-serial> \
  --token-code $mfaCode --profile <profile-name>)

export AWS_ACCESS_KEY_ID=$(echo $result | jq ".Credentials.AccessKeyId" -r)
export AWS_SECRET_ACCESS_KEY=$(echo $result | jq ".Credentials.SecretAccessKey" -r)
export AWS_SESSION_TOKEN=$(echo $result | jq ".Credentials.SessionToken" -r)


#############################################################
##
##
