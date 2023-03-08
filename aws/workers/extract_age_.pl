### To find the age of the AMI used by worker nodes in an EKS cluster using the AWS CLI and then convert it to a human-readable format using Perl, you can use the following script:


#!/usr/bin/perl

use strict;
use warnings;
use Time::Piece;
use Time::Seconds;

# Retrieve the creation date of the AMI
my $creation_date = `aws ec2 describe-images \
    --filters "Name=name,Values=amazon-eks-node-<version>-<os>-*-*" \
              "Name=state,Values=available" \
    --query "Images[0].CreationDate" \
    --output text`;

# Parse the creation date as an ISO 8601 timestamp
my $timestamp = Time::Piece->strptime($creation_date, '%Y-%m-%dT%H:%M:%S.%Z');

# Calculate the age of the AMI in days
my $age_in_days = int((time() - $timestamp->epoch) / ONE_DAY);

# Print the age of the AMI in a human-readable format
print "The AMI used by the worker nodes is $age_in_days days old.\n";

###
###
Replace <version> and <os> with the version and operating system of your EKS worker nodes, respectively.

This script uses the Time::Piece and Time::Seconds modules to parse the creation date of the AMI as an ISO 8601 timestamp and calculate its age in days. It then prints the age of the AMI in a human-readable format.

Note that this script assumes that you have the AWS CLI and Perl installed on your system and that your AWS CLI is configured with the necessary credentials and permissions to access your EC2 instances and images.
