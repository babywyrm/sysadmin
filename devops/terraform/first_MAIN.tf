#############################################
##
## oh wow, this needs cleaning
## and, soon
## or, replicate in CDK
##
##
#############################################
##

variable "aws_region" { default = "us-east-1" } # NYC, Probably

provider "aws" {
    access_key         = "AKIAJI4XXCGYC5EPZBRA"
    secret_key         = "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"
    region             = "us-east-1"
}

resource "aws_instance" "snorty-web-server-1" {
    ami 	       = "ami-0c835d91df905128e"
    instance_type      = "t2.micro"
#   name               = "${data.aws_ami.ubuntu-18_04.name}-encrypted"
#   description        = "${data.aws_ami.ubuntu-18_04.description} (encrypted)"
#   source_ami_id      = "${data.aws_ami.ubuntu-18_04.id}"
#   source_ami_region  = "${var.region}"
#   encrypted          = true
    subnet_id          = "${aws_subnet.snorty-public.id}"
    security_groups    = ["${aws_security_group.snorty-all-in.id}"]
#   security_groups    = ["${aws_security_group.web-node.id}"]
    key_name           = "${aws_key_pair.snorty.key_name}" 

#    provisioner "file" {
#    source             = "${file("/Users/tms/TERRA/LAB1/startup/auto-apt.sh")}" 
#    destination        = "~/auto-apt.sh"
#    connection {
#    type               = "ssh"
#    user               = "ubuntu"
#    private_key        = "${file("/Users/tms/TERRA/LAB1/.ssh/id_rsa")}" 
#    
#    }

#    }
    
       provisioner "remote-exec" {
       inline          = [
	       			"sudo /usr/bin/apt-mark hold kernel*",
				"sudo /usr/bin/apt-mark hold grub*",
				"sudo /usr/bin/apt-get update",
				"sudo /usr/bin/apt-get upgrade -y",
				
    ]
       connection {
       type            = "ssh"
       user            = "ubuntu"
       private_key     = "${file("/Users/tms/TERRA/LAB1/.ssh/id_rsa")}" 

    }
##  }
}
    tags {
       Name            = "Snorty Web Server Instance"
       ImageType       = "ubuntu-18_04"
    }
  
##  lifecycle {
##     prevent_destroy = true
##  }
##############################################################
##############################################################


}

resource "aws_vpc" "snorty-vpc" {
    cidr_block 	       = "20.0.0.0/16"
    tags {
	Name	       = "Snorty VPC"
    }
}

resource "aws_internet_gateway" "snorty-ig" {
    vpc_id = "${aws_vpc.snorty-vpc.id}"
    tags {
  	Name	       = "Snorty Internet Gateway"
    }
}

resource "aws_network_acl" "snorty-acl" {
    vpc_id 	       = "${aws_vpc.snorty-vpc.id}"
    tags {
    	Name           = "Snorty Network ACL"
    }
}

resource "aws_network_acl_rule" "snorty-acl-rule" {
    network_acl_id     = "${aws_network_acl.snorty-acl.id}"
    rule_number        = 100
    egress             = false
    protocol           = "-1"
    rule_action        = "allow"
    cidr_block         = "0.0.0.0/0"
    from_port          = 0
    to_port            = 65535
}

resource "aws_security_group" "snorty-all-in" {
    vpc_id 	       = "${aws_vpc.snorty-vpc.id}"
}

resource "aws_security_group_rule" "open-ssh-in" {
    type 	       = "ingress"
    from_port	       = 22 
    to_port	       = 22 
    protocol           = "tcp"
    cidr_blocks        = ["50.232.9.0/24","69.215.158.0/24","50.200.5.0/24","98.253.229.0/24","173.165.56.0/24"]
    security_group_id  = "${aws_security_group.snorty-all-in.id}"
} 

resource "aws_security_group_rule" "open-https-out" {
    type               = "egress"
    from_port          = 443 
    to_port            = 443 
    protocol           = "tcp"
    cidr_blocks        = ["0.0.0.0/0"]
    security_group_id  = "${aws_security_group.snorty-all-in.id}"
}

resource "aws_security_group_rule" "open-http-out" {
    type               = "egress"
    from_port          = 80 
    to_port            = 80 
    protocol           = "tcp"
    cidr_blocks        = ["0.0.0.0/0"]
    security_group_id  = "${aws_security_group.snorty-all-in.id}"
}

resource "aws_security_group_rule" "open-ssh-out" {
    type               = "egress"
    from_port          = 22 
    to_port            = 22 
    protocol           = "tcp"
    cidr_blocks        = ["0.0.0.0/0"]
    security_group_id  = "${aws_security_group.snorty-all-in.id}"
}

resource "aws_security_group_rule" "open-all-in-icmp" {
    type	       = "ingress"
    from_port 	       = 8
    to_port            = 0
    protocol           = "icmp"
    cidr_blocks        = ["0.0.0.0/0"]
    security_group_id  = "${aws_security_group.snorty-all-in.id}"
}

#resource "aws_security_group_rule" "open-all-out" {
#    type	       = "egress"
#    from_port	       = 0
#    to_port            = 65535
#    protocol	       = "-1"
#    cidr_blocks        = ["0.0.0.0/0"]
#    security_group_id  = "${aws_security_group.acme-all-in.id}"
###}

resource "aws_subnet" "snorty-public" {
    vpc_id	             = "${aws_vpc.snorty-vpc.id}"
    cidr_block	             = "20.0.1.0/24"
    availability_zone        = "us-east-1a"
    map_public_ip_on_launch  = true
    tags {
	Name		     = "Snorty Public Subnet"
    }
}

resource "aws_route_table" "snorty-rt-public" {
    vpc_id                   = "${aws_vpc.snorty-vpc.id}"
}

resource "aws_route" "snorty-r-public-to-internet" {
    route_table_id           = "${aws_route_table.snorty-rt-public.id}"
    destination_cidr_block   = "0.0.0.0/0"
    gateway_id               = "${aws_internet_gateway.snorty-ig.id}"
}
       
resource "aws_route_table_association" "public" {
    subnet_id                = "${aws_subnet.snorty-public.id}"
    route_table_id           = "${aws_route_table.snorty-rt-public.id}"
}

resource "aws_key_pair" "snorty" {
    key_name                 = "snorty-key"
    public_key               = "${file("./.ssh/id_rsa.pub")}"
}

resource "aws_subnet" "snorty-private" {
    vpc_id		     = "${aws_vpc.snorty-vpc.id}"
    cidr_block		     = "20.0.0.0/24"
    availability_zone	     = "us-east-1a"
    map_public_ip_on_launch  = true
    tags {
	Name	 	     = "Snorty Private Subnet"
    }
}

resource "aws_instance" "snorty-db-server-1" {
    ami                         = "ami-0c835d91df905128e"
    instance_type               = "t2.micro"
#   name                        = "${data.aws_ami.ubuntu-18_04.name}-encrypted"
#   description                 = "${data.aws_ami.ubuntu-18_04.description} (encrypted)"
#   source_ami_id               = "${data.aws_ami.ubuntu-18_04.id}"
#   source_ami_region           = "${var.region}"
#   encrypted                   = true
    subnet_id                   = "${aws_subnet.snorty-private.id}"
#   security_groups             = ["${aws_security_group.acme-all-in.id}"]
    security_groups             = ["${aws_security_group.snorty-private.id}"]
    associate_public_ip_address = false
    key_name                    = "${aws_key_pair.snorty.key_name}"
    tags {
       Name                     = "Snorty Database Server Instance"
       ImageType                = "ubuntu-18_04"
    }
}

resource "aws_security_group" "snorty-private" {
    vpc_id                      = "${aws_vpc.snorty-vpc.id}"
}

resource "aws_security_group_rule" "open-mysql-out" {
    type               = "egress"
    from_port          = 3306 
    to_port            = 3306 
    protocol           = "tcp"
    cidr_blocks        = ["0.0.0.0/0"]
    security_group_id  = "${aws_security_group.snorty-private.id}"
}

resource "aws_security_group_rule" "open-mysql-in" {
    type               = "ingress"
    from_port          = 3306
    to_port            = 3306
    protocol           = "tcp"
    cidr_blocks        = ["0.0.0.0/0"]
    security_group_id  = "${aws_security_group.snorty-private.id}"
}

resource "aws_security_group_rule" "open-ssh-db-in" {
    type               = "ingress"
    from_port          = 22 
    to_port            = 22 
    protocol           = "tcp"
    cidr_blocks        = ["0.0.0.0/0"]
    security_group_id  = "${aws_security_group.snorty-private.id}"
}




##############################################################################
###### DEVEL #####
##### currently at home, sawyer & north #### 69.215.158.255  ## 98.253.229.141 DFCB
##############################################################################


#######################################################
##resource "aws_ssh_controls"  


## Ilie Stefanita [3:16 PM]
## here is the solution: change *security_groups* = ["${aws_security_group.acme_all_in.id}"]
## to
## *vpc_security_group_ids* = ["${aws_security_group.acme_all_in.id}"]
##
## I was able to apply new rule without destroying the instance by changing this lines in aws_instance:
## security_groups change to vpc_security_group_ids
## https://github.com/hashicorp/terraform/issues/7221... Show more

######################################################
##data "aws_ami" "ubuntu-18_04" {
##  most_recent = true
##  owners = ["${var.ubuntu_account_number}"]
##
##  filter {
##    name   = "name"
##    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
##  }
## }
