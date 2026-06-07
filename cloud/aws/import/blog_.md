Convert a VM to AMI in AWS

##
#
https://mohamedmsaeed.medium.com/convert-a-vm-to-ami-in-aws-b101a1c52e0e
#
##

In some cases, you may need to commit your VM as an image and use it in a cloud.

AWS; one of the biggest cloud providers in the market; gives you the power to use your own modified VM on the cloud. Simply, you will export your VM as an image then create an AMI from it and finally, run an EC2 using that new AMI you have just created! Simple hah!

So How can we do that!?

Things you need to get this done
VM image.
S3 bucket where we will upload the image
IAM role called ‘vmimport’.
AWS CLI installed on your machine.
Be careful: AWS only supports certain Operating Systems. You can find a list here.

1. Export your VM as an image:
You can prepare a VM, install whatever you want to install on it and then when you are done, export it.

From AWS official documents here are some of the formats that you can use:

Open Virtualization Archive (OVA)
Virtual Machine Disk (VMDK)
Virtual Hard Disk (VHD/VHDX)
Open Virtualization Format (OVF)
2. Create an S3 bucket:
Create an S3 bucket in the region where you will create your EC2s. We will use this bucket to store the VM image.

3. Create an IAM role called ‘vmimport’:
To allow VM import/export service to perform some operation you should create a role called ‘vmimport’.

The role that you will create needs some permission to work properly. Simply those permissions to enable VM import/export from accessing your S3 bucket and register your VM image as AMI.
To do that click on open IAM service >> policies >> create policy.
Choose JSON and paste the following code.
NOTE: change BUCKET with your bucket name.

{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Effect":"Allow",
         "Action":[
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket" 
         ],
         "Resource":[
            "arn:aws:s3:::BUCKET",
            "arn:aws:s3:::BUCKET/*"
         ]
      },
      {
         "Effect":"Allow",
         "Action":[
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:PutObject",
            "s3:GetBucketAcl"
         ],
         "Resource":[
            "arn:aws:s3:::BUCKET",
            "arn:aws:s3:::BUCKET/*"
         ]
      },
      {
         "Effect":"Allow",
         "Action":[
            "ec2:ModifySnapshotAttribute",
            "ec2:CopySnapshot",
            "ec2:RegisterImage",
            "ec2:Describe*"
         ],
         "Resource":"*"
      }
   ]
}
Review the policy >> choose a name then >> save.
Open IAM service >> Roles >> Create Role

For now, choose EC2 >> Next.

Select the policy you have just created. Add a tag. Then save the role with the name “vmimport”.
Now, open vmimport role >> Trust relationships >> Edit trust relationships.

Paste the following code then click update
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vmie.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:Externalid": "vmimport"
        }
      }
    }
  ]
}
4. Install AWS CLI:
To install and configure AWS CLI please follow the following documentation.

https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html

Do the magic and convert VM to AMI:
With AWC CLI installed and configured run the following command

aws ec2 import-image --disk-containers Format=vmdk,UserBucket="{S3Bucket=BUCKET,S3Key=VM-disk.vmdk}"
The output will be something like this:

{
   "ImportImageTasks": [
      {
         "ImportTaskId": "import-ami-05464789141f433fb",
            "Progress": "19",
            "SnapshotDetails": [
                {
                    "DiskImageSize": 2782431232.0,
                    "Format": "VMDK",
                    "Status": "active",
                    "UserBucket": {
                        "S3Bucket": "BUCKET",
                        "S3Key": "VM-disk.vmdk"
                    }
                }
            ],
            "Status": "active",
            "StatusMessage": "converting"
        }
    ]
}
You can check the converting status using the ImportTaskId from the previous output:

aws ec2 describe-import-image-tasks --import-task-ids import-ami-05464789141f433fb
Once it is done, the status will be updated to ‘completed’.

Find more about status messages here.

The only way?
It is worth mentioning that this is not the only way to do the task. You can, for example, use Packer or AWS Server Migration Service.

