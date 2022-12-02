Tech-tip: Converting your virtual machine to AWS EC2 AMI
Sharing is caring!
The way to use AWS is not limited to AMI provided by Amazon (or 3rd party/community), but is possible to instantiate an EC2 workload starting from your own image, and converting to AMI.

###
###
https://blog.linoproject.net/tech-tip-converting-your-virtual-machine-to-aws-ec2-ami/
###
###


The steps to create your custom AMI starting from VMware runs through these macro steps:

create VM template (ova)
create S3 bucket and upload the template
convert with awscli
OVA creation and upload in S3
This is the easiest part of this how-to that I don’t want to explain is how to export the Virtual Machine ova from the vInfrastructure or Workstation/Fusion… anyway IMHO the best method to manage VM template is using ova; starting from ovf and vmdk files, you could simply converting these files to ovf using ovftool (https://www.vmware.com/support/developer/ovf/), and executing the following command:

ovftool <vm_image>.ovf <vm_image>.ova
1
ovftool <vm_image>.ovf <vm_image>.ova
Create an S3 bucket and upload the ova template via web, keeping in mind the name of the bucket and the name of the ova.

AMI conversion
Prepare the policy document trust-policy.json:

{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "vmie.amazonaws.com" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals":{
         "sts:Externalid": "vmimport"
      }
    }
  }]
}
1
2
3
4
5
6
7
8
9
10
11
12
13
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "vmie.amazonaws.com" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals":{
         "sts:Externalid": "vmimport"
      }
    }
  }]
}
Then, create the role:

aws iam create-role --role-name vmimport --assume-role-policy-document file://trust-policy.json
1
aws iam create-role --role-name vmimport --assume-role-policy-document file://trust-policy.json
…and repare the role policy document named role-policy.json

{
 "Version": "2012-10-17",
 "Statement": [{
   "Effect": "Allow",
   "Action": [
     "s3:ListBucket",
     "s3:GetBucketLocation",
     "s3:FullAccess"
   ],
   "Resource": [
     "arn:aws:s3:::<s3bucket>"
   ]},
   {
     "Effect": "Allow",
     "Action": [
       "s3:GetObject"
     ],
     "Resource": [
       "arn:aws:s3:::<s3bucket>/*"
     ]
   },{
     "Effect": "Allow",
     "Action":[
       "ec2:ModifySnapshotAttribute",
       "ec2:CopySnapshot",
       "ec2:RegisterImage",
       "ec2:Describe*",
       "ec2:FullAccess"
     ],
     "Resource": "*"
   }
 ]
}
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
{
 "Version": "2012-10-17",
 "Statement": [{
   "Effect": "Allow",
   "Action": [
     "s3:ListBucket",
     "s3:GetBucketLocation",
     "s3:FullAccess"
   ],
   "Resource": [
     "arn:aws:s3:::<s3bucket>"
   ]},
   {
     "Effect": "Allow",
     "Action": [
       "s3:GetObject"
     ],
     "Resource": [
       "arn:aws:s3:::<s3bucket>/*"
     ]
   },{
     "Effect": "Allow",
     "Action":[
       "ec2:ModifySnapshotAttribute",
       "ec2:CopySnapshot",
       "ec2:RegisterImage",
       "ec2:Describe*",
       "ec2:FullAccess"
     ],
     "Resource": "*"
   }
 ]
}
After role, create the role policy:

aws iam put-role-policy --role-name vmimport --policy-name vmimport --policy-document file://role-policy.json
1
aws iam put-role-policy --role-name vmimport --policy-name vmimport --policy-document file://role-policy.json
Finally we could proceed with the real conversion, uploading the ova file into S3 bucket and creating the “container” description file.

The container.json will look like this:

[{
  "Description": "My OVA",
  "Format": "ova",
  "UserBucket": {
    "S3Bucket": "<s3bucket>",
    "S3Key": "<uploaded_ova>.ova"
  }
}]
1
2
3
4
5
6
7
8
[{
  "Description": "My OVA",
  "Format": "ova",
  "UserBucket": {
    "S3Bucket": "<s3bucket>",
    "S3Key": "<uploaded_ova>.ova"
  }
}]
Then execute the command:

aws ec2 import-image --description "my AMI from OVA" --license-type BYOL --disk-containers file://containers.json
1
aws ec2 import-image --description "my AMI from OVA" --license-type BYOL --disk-containers file://containers.json
The process is asynchronous and to see what is the state of this task, simply issuing the following command using “import-ami-xxxxxx” as task id:

aws ec2 describe-import-image-tasks --import-task-ids import-ami-xxxx
1
aws ec2 describe-import-image-tasks --import-task-ids import-ami-xxxx
aws_import_ami_status

Following the official documentation ( http://docs.aws.amazon.com/vm-import/latest/userguide/vmimport-image-import.html ) the states are:

active — The import task is in progress.
deleting — The import task is being canceled.
deleted — The import task is canceled.
updating — Import status is updating.
validating — The imported image is being validated.
converting — The imported image is being converted into an AMI.
completed — The import task is completed and the AMI is ready to use.
When the conversion is completed, you could start the first EC2 instance to see if all is gone well.

My Use Case
This guide must be used to convert only Linux or Windows machine running a file system recognized in Amazon EC2 environment (again AWS doesn’t handle Virtual Machines! it handles instances that could be executed in its environment).

Note: this guide is valid is not valid for other filesystems such as FreeBSD or similar.

That’s all folks

Source: http://docs.aws.amazon.com/vm-import/latest/userguide/vmimport-image-import.html





###############
###############


## How to provision VMWare compatible .ova images on EC2

EC2 only lets you export instances as VMWare-compatible OVA files if you originally imported that instance from an OVA. Presumably it preserves the metadata and XML gubbins for the instance, and just wraps it up again using that metadata on export.

In order to provision arbitrary VMs in an OVA-exportable way, we abuse the volume snapshots on one VM.

### Prep work:

* Make a fresh install of ubuntu server or whatever your base distro is, in VMWare, export as OVA file. (single disk only!)
* Untar the OVA and import the VMDK file into ec2 using `ec2-instance-import` onto an HVM instance type (ie, no xen kernel needed)
* Snapshot the volume, make a note of the snapshot ID. This is the "freshly installed ubuntu server" snapshot.

### Provisioning an OVA-exportable instance:

* Stop instance (`ec2-stop-instances`)
* Detach existing volume from instance (`ec2-detach-volume`)
* Delete existing volume (`ec2-delete-volume`)
* Make new volume from `$INITIAL_SNAPSHOT_ID` (`ec2-create-volume`)
* Attach new volume to instance (`ec2-attach-volume`)
* Boot instance (`ec2-start-instances`)
* Provision (eg: run packer with null builder, run chef, etc)
* Export instance using `ec2-create-instance-export`
* Download your OVA from S3, import to VMWare / Virtualbox
* Repeat for the next provisioning job.

### Automation

I have a 100 line shell script as part of a jenkins job that does this to build exportable VM images. You have to block until completion, eg call `ec2-create-volume` when poll `ec2-describe-volumes` until your action has completed.

Have fun.

##
##
##


#!/bin/bash -e
export PATH=/var/lib/jenkins/packer:$PATH
test -f ~/.aws/creds.env && source ~/.aws/creds.env
# build VMWare.
# none of the ec2-* commands have a "block until done" option
# so we have to poll the ec2-describe commands in some places
#
# I made a clean install of ubuntu 14.04 in vmware, with a single disk (no LVM)
# and used amazons import tools.
export instance_id="i-xxxxxx"
# then I made a snapshot of the filesystem in the freshly imported state
export initial_snapshot_id="snap-xxxxxx"
# all this is happening in:
export region="us-west-1"
export availability_zone="us-west-1c"
#
#1) Ensure instance is stopped
echo "Stopping instance $instance_id"
ec2-stop-instances --region $region $instance_id
until ec2-describe-instances --region $region $instance_id | grep ^INSTANCE | grep stopped
do
  echo "Waiting for instance to be stopped.."
  sleep 10
done
#2) Remove EBS volume (ie, so instance has no associated disk)
old_volume_id=$(ec2-describe-instances --region $region $instance_id |
                awk '/^BLOCKDEVICE/ {print $3}')
if [ -n "$old_volume_id" ]
then
  echo "Deleting old volume $old_volume_id"
  ec2-detach-volume --region $region $old_volume_id -i $instance_id 
  while ec2-describe-volumes --region $region $old_volume_id | grep ^ATTACHMENT
  do
    echo "Waiting for detatchment"
    sleep 5
  done
  ec2-delete-volume --region $region $old_volume_id
  while ec2-describe-volumes --region $region $old_volume_id
  do
    echo "Waiting for volume deletion"
  done
fi
#3) Create new EBS volume from initial snapshot
echo "Making new volume from snapshot $initial_snapshot_id"
export new_volume_id=$(ec2-create-volume \
                  --region $region \
                  --availability-zone $availability_zone \
                  --snapshot $initial_snapshot_id |
                awk '/^VOLUME/ {print $2}')
until ec2-describe-volumes --region $region $new_volume_id | grep ^VOLUME | grep available
do
  echo "Waiting for volume creation"
  sleep 5
done
echo "Created new volume: $new_volume_id"
#4) Attach new volume to instance
echo "Attaching new volume to instance"
ec2-attach-volume --region $region $new_volume_id -i $instance_id -d /dev/sda1
until ec2-describe-volumes --region $region $new_volume_id | grep ^ATTACHMENT
do
  echo "Waiting for volume to attach to instance"
  sleep 5
done
#5) Boot instance
echo "Starting instance"
ec2-start-instances --region $region $instance_id
until ec2-describe-instance-status --region $region $instance_id | awk '/^INSTANCE/ && $6=="ok" && $7=="ok"' | grep $instance_id
do
  echo "Waiting for instance to be running"
  sleep 10
done
#6) Provision like the AMI, using packer's null builder (just ssh -> chef)
packer build -color=false vmware-ec2-provision.json
#7) Export as a VMDK using EC2's export tools
#    (only possible because the instance was imported from VMDK initially)
export export_task_id=$(ec2-create-instance-export-task $instance_id \
                  --region $region \
                  -e vmware \
                  -f vmdk \
                  -c OVA \
                  -b irccloud-vms \
                  -d "exporting vmware inst $(date +%s)" |
                 awk '/^EXPORTTASK/ {print $2}')
until ec2-describe-export-tasks \
        --region $region $export_task_id | grep completed
do
  echo "Waiting for export task $export_task_id to complete.."
  sleep 30
done
export export_file=$(ec2-describe-export-tasks --region $region $export_task_id |
              awk '{print $NF}')
echo "Export complete, filename: $export_file, moving buckets"

news3name="irccloud-${ENT_NAME}-$(date +%Y%m%d-%s).ova"
s3cmd mv "s3://irccloud-vms/$export_file" "s3://irccloud-vms/$news3name"

echo "Stopping instance $instance_id, we're done here."
ec2-stop-instances --region $region $instance_id

echo "S3 ASSET: s3://irccloud-vms/$news3name"
