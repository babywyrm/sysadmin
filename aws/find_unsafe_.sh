#!/bin/sh

# Script finds AWS Security Groups with potentially unsafe rules and lists instances that use such security groups.
#
# Unsafe security group rules are:
# 1. open to the world (0.0.0.0/0),
# 2. not restricted to another security group,
# 3. not use safe ports (22,80,443; you can set SAFE_PORTS environment variable to override).
#
# To run this script:
# 1. sudo pip install awscli
# and configure AWS region and credentials (https://github.com/aws/aws-cli#getting-started):
#    export AWS_DEFAULT_REGION=us-west-2
#    export AWS_ACCESS_KEY_ID=<access_key>
#    export AWS_SECRET_ACCESS_KEY=<secret_key>
# 2. sudo npm install -g jsontool
# (Manual at http://trentm.com/json/)
#
# After run a set of json-files will be created, see the bottom of the script.

# Set region from env value
AWS_REGION=${AWS_DEFAULT_REGION:-"us-west-2"}
echo "Region: $AWS_REGION"

# Fetch security groups
test -f sg_all.json || aws ec2 describe-security-groups --region $AWS_REGION > sg_all.json

# Filter unsafe security groups
SAFE_PORTS=${SAFE_PORTS:-"22,80,443"}
echo "Safe ports: $SAFE_PORTS"
CODE="
    IpPermissionsEgress = undefined;
    FilteredIpPermissions = [];
    IpPermissions.forEach(function(v){
        // skip safe ports
        if(v.ToPort==v.FromPort && [${SAFE_PORTS}].indexOf(v.ToPort)!=-1) return;
        // skip ports opened to another sg
        if(v.UserIdGroupPairs.length>0) return;
        // skip permissions where address '0.0.0.0/0' is not used 
        if(!v.IpRanges.some(function(r){return r.CidrIp=='0.0.0.0/0';})) return;
        FilteredIpPermissions.push(v); 
    });
    IpPermissions=undefined;
"

cat sg_all.json | json SecurityGroups | json -e "$CODE" | json -c 'FilteredIpPermissions.length>0' > sg_unsafe_rules.json

# Get instances for each unsafe security group
echo "Potentially unsafe security groups:"
UNSAFE_GROUP_IDS=`cat sg_unsafe_rules.json | json -a GroupId -d,`
for i in $UNSAFE_GROUP_IDS; do
    echo $i
    test -f sg_instances_$i.json || aws ec2 describe-instances --filter Name=group-id,Values=$i --region $AWS_REGION | \
                                 json Reservations -j | json -a Instances | \
                                 json -g -a PublicDnsName LaunchTime InstanceId Tags -j \
                                 > sg_instances_$i.json
done

echo <<EOF
See AWS Security Groups analyze reports:
 - sg_all.json - all security groups
 - sg_unsafe_rules.json - filtered potentially unsafe security groups' rules
 - sg_instances_<security_group_id> - instance list for each security group from the previous file

Remove these files if you want data to be redownloaded next run.

EOF

#################
#################
##
##
##
EOF
