
# Cross Referencing resources

To reference the resources created by this stack in other stacks you need to define a `data` resource pointing to the S3 bucket and `key` defined in `remote-state.tf.

Your `data` definition should look something like this:

```hcl
data "terraform_remote_state" "vpc" {
    backend = "s3"
    config {
        bucket = "terraform-state.example.com"
        key = "eu-west-1/vpc-1"
        region = "eu-west-1"
    }
}
```

In your code, if you wanted (for example) to reference the `vpc_id` created by this stack you would do something like this:

```hcl
vpc_id = "${data.terraform_remote_state.vpc.vpc_id}"
```

* The `.vpc.` section in the variable name **must** match the name of the `data` resource you define.
* The `.vpc_id` is the name of the variable from this (the source stack). Must be one of those listed in `outputs.tf`.


```
// Directory layout
//
//


stacks/
|__ us-east-1
    |__ test
        |__ vpc
        |__ services
        |__ apps
            |__ foo
            |__ bar

We have REMOTE files in every directory that's a stack, and a Makefile that finds directories
with a REMOTE file to initialize their remote state appropriately.

// If a module needs a VPC output
resource "terraform_remote_state" "vpc" {
  backend = "s3"
  config {
    bucket = "terraform"
    
    // these vars propagate from the stack to every module
    key = "${var.region}/${var.environment}/vpc"
  }
}

// If a module needs to know about the NAT or jump hosts
resource "terraform_remote_state" "services" {
  backend = "s3"
  config {
    bucket = "terraform"
    
    // these vars propagate from the stack to every module
    key = "${var.region}/${var.environment}/services"
  }
}


###############################
##
##

#!/usr/bin/env bash

# List terraform resources in the current directory and ask their arn to import them into terraform state

RESOURCES_LIST=$(awk -F\" '/^resource "/ {print $2"."$4}' *.tf)

for resource in ${RESOURCES_LIST}
do
    read -p "Enter ARN for resource ${resource} (type none to not import it): " arn
    if [[ ${arn} != "none" ]]
    then
        terraform import ${resource} ${arn}
    fi
done


##
##
