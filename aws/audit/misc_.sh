# Count total EBS based storage in AWS
aws ec2 describe-volumes | jq "[.Volumes[].Size] | add"
# Count total EBS storage with a tag filter
aws ec2 describe-volumes --filters "Name=tag:Name,Values=CloudEndure Volume qjenc" | jq "[.Volumes[].Size] | add"
# Describe instances concisely
aws ec2 describe-instances | jq '[.Reservations | .[] | .Instances | .[] | {InstanceId: .InstanceId, State: .State, SubnetId: .SubnetId, VpcId: .VpcId, Name: (.Tags[]|select(.Key=="Name")|.Value)}]'
# Wait until $instance_id is running and then immediately stop it again
aws ec2 wait instance-running --instance-id $instance_id && aws ec2 stop-instances --instance-id $instance_id

# Get 10th instance in the account
aws ec2 describe-instances | jq '[.Reservations | .[] | .Instances | .[]] | .[10]'
# List the private IP addresses of all instances
aws ec2 describe-instances | jq '[.Reservations | .[] | .Instances | .[] | .PrivateIpAddress] | sort'
# Do that, but only on non-terminated instances
aws ec2 describe-instances | jq '[.Reservations | .[] | .Instances | .[] | select(.State.Name!="terminated") | {Name: (.Tags[]|select(.Key=="Name")|.Value), PrivateIp: .PrivateIpAddress}]'
# JQ export to csv command / suffix
export_csv_suffix='| map([.Name, .PrivateIp] | join(",")) | join("\n")'

# Get all production instances
instance_ids=$(aws ec2 describe-instances | jq '[.Reservations | .[] | .Instances | .[] | select(.State.Name!="terminated") | select((.Tags[]|select(.Key=="Environment")|.Value) =="prod") | {Name: (.Tags[]|select(.Key=="Name")|.Value), InstanceId: .InstanceId}]' | jq ".[] | .InstanceId")
# Add a backup tag to those instances
echo $instance_ids | sed "s/\"//g" | grep i- | parallel --delay 3 aws ec2 create-tags --resources {} --tags Key=Backup,Value=PolicyA

# Attach multiple new ebs volumes to an instance
instance_id="i-0d42888191f597bb8"
volume_size="8"
for x in {a..h}
do
    volume_id=$(aws ec2 create-volume --size $volume_size --volume-type gp2 --availability-zone eu-west-1a | jq -r ".VolumeId")
    aws ec2 wait volume-available --volume-ids $volume_id
    aws ec2 attach-volume --volume-id $volume_id --instance-id $instance_id --device /dev/xvd$x
done

# Produce a summary of instances
jq '[.Reservations | .[] | .Instances | .[] | select(.State.Name!="terminated") | {Name: (.Tags[]|select(.Key=="Name")|.Value), InstanceId: .InstanceId}]'

# Check instances for ones which are missing required tags
instances=$(cat "./scripts/prod-instances.json")
required_tags='["Environment","Backup","Owner","AppName","Name"]'

echo $instances | jq "[.Reservations | .[] | .Instances | .[] | select(.Tags | [.[] | .Key] | contains($required_tags) | not)]" | jq '
[.[] | select(.State.Name!="terminated") | select(([.Tags | .[] | .Key]) | contains(["CloudEndure creation time"]) | not) | {
  InstanceId: .InstanceId,
  InstanceName: (.Tags | from_entries | .Name),
  MissingTags: (('$required_tags') - ([.Tags | .[] | .Key]))
}]'

# Get the 'Live & Tagged' instances
instances=$(aws ec2 describe-instances)
live=$(echo $instances | jq "[.Reservations | .[] | .Instances | .[] | select(.Tags | [.[] | .Key] | contains($required_tags))]")

# Enable termination protection from a list of instances stored in $list
echo $live | jq -r ".[] | .InstanceId" | while read id
do
  echo "Enabling termination proection on machine: $id"
  aws ec2 modify-instance-attribute --disable-api-termination --instance-id $id
done

# Attach unused EBS Volumes to an instance
instance_id="i-abcd1234"
letters=({a..j})
volumes=$(aws ec2 describe-volumes | jq -r ".Volumes[] | select(.State==\"available\") | .VolumeId")
lc=1
echo $volumes | while read id
do
  echo "Attaching volume on: $id"
  aws ec2 attach-volume --instance-id $instance_id --volume-id $id --device /dev/sd${letters[++lc]}
done

# Detach and delete secondary volumes on a machine
aws ec2 describe-instances --instance-ids $instance_id | jq -r ".Reservations[0].Instances[0].BlockDeviceMappings | .[] | select(.DeviceName != \"/dev/sda1\") | .Ebs.VolumeId" | while read volume_id
do
  aws ec2 detach-volume --volume-id $volume_id && \
  aws ec2 wait volume-available --volume-ids $volume_id && \
  aws ec2 delete-volume --volume-id $volume_id
done

# Copy everything from an account into an OSX clipboard
aws ec2 describe-volumes | jq "[.Volumes[] | select(.State==\"available\") | .VolumeId]" | pbcopy

# Tell me ALL my instances in ALL regions across ALL accounts (from CLI file)
echo -e 'Profile \t Region \t InstanceId \t Name Tag'
for profile in $(grep "^\[.*\]" ~/.aws/config | sed 's/\[//g' | sed 's/\]//g' | cut -d ' ' -f 2) ; do
    for region in `aws --profile $profile --region us-east-1 ec2 describe-regions | jq -r '.Regions | .[] | .RegionName'`; do
        instances=$(aws --profile $profile --region $region ec2 describe-instances)
        filtered=$(echo $instances | jq "[.Reservations | .[] | .Instances | .[] | select(.State.Name!=\"terminated\")]")
        summary=$(echo $filtered | jq "[ .[] | {Name: (.Tags // {} | from_entries | .Name ), InstanceId: .InstanceId, Profile: \"$profile\", Region: \"$region\"} ]")
        # JSON format: echo $summary
        # Tabular format:
        echo "$summary" | jq -r '.[] | [.Profile, .Region, .InstanceId, .Name] | @tsv'
    done
done

# Iterating all profiles / regions is useful as a tool for account scanning. Let's define a useful alias for doing this:
function awsloop() {
    for profile in $(grep "^\[.*\]" ~/.aws/config | sed 's/\[//g' | sed 's/\]//g' | cut -d ' ' -f 2) ; do
        for region in `aws --profile $profile --region us-east-1 ec2 describe-regions | jq -r '.Regions | .[] | .RegionName'`; do
            echo "--------------------------------------------"
            echo "| profile: $profile, region: $region"
            echo "--------------------------------------------"
            AWS_PROFILE=$profile AWS_REGION=$region $SHELL -c "$@"
        done
    done
}
function awsgloop() {
    for profile in $(grep "^\[.*\]" ~/.aws/config | sed 's/\[//g' | sed 's/\]//g' | cut -d ' ' -f 2) ; do
        echo "--------------------------------------------"
        echo "| profile: $profile, region: us-east-1"
        echo "--------------------------------------------"
        AWS_PROFILE=$profile AWS_REGION=us-east-1 $SHELL -c "$@"
    done
}

# Use our all accounts / all regions shorthand to list out all VPC CIDR ranges in use in all regions in all accounts
awsloop 'aws ec2 describe-vpcs | jq -r ".Vpcs | .[] | {\"ID\": .VpcId, \"CIDR\": .CidrBlock}"'

# Let's use the awsgloop function to locate which account a particular S3 bucket lives in
awsgloop 'aws s3 list-buckets | grep my-s3-bucket-name'

# Iterate all AWS profiles and regions, reporting on EKS clusters running there
# (Using ~/.aws/config instead of ~/.aws/credentials file)
for profile in $(grep "^\[.*\]" ~/.aws/config | sed 's/\[//g' | sed 's/\]//g' | cut -d ' ' -f 2) ; do
    for region in `aws --profile $profile --region us-east-1 ec2 describe-regions | jq -r '.Regions | .[] | .RegionName'`; do
        clusters=$(aws --profile $profile --region $region eks list-clusters)
        clusters=$(echo $clusters | jq -r '.clusters | .[]')
        if [ ! -z "$clusters" ]; then
            echo ">> profile: $profile | region: $region"
            echo $clusters
        fi
    done
done
