// Directory layout

//

//

```
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
