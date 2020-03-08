## Cloud provisioning with Terraform and Bolt
## https://puppet.com/blog/cloud-provisioning-terraform-and-bolt/
##
## by Lucy Wyman|1 April 2019

*Editor’s notes: This post was originally published on lucywyman.me. We are republishing it with Lucy’s permission.*

*SEE ALSO: Since writing this, we've added inventory plugins to Bolt, which allow you to dynamically load inventory from sources like Terraform, PuppetDB, and Azure. I recommend checking out Tony Green's blog post about using the Terraform plugin.*

Terraform is a cloud provisioning tool that's great at managing low-level infrastructure components such as compute instances, storage, and networking. While Terraform is great at creating the infrastructure you need, it's not great at managing the state of your resources over time or enforcing certain states. Nathan Handler described it in a talk at OSCON 2018 as a way to get boxes that you can then go fill with the users, files, applications, and tools you need.


Image from 'Terraform All The Things' by Nathan Handler

Bolt is an open source remote task runner that can run commands, scripts, and puppet code across your infrastructure with a few keystrokes. It's available with RBAC and more enterprise features in Puppet Enterprise. Bolt combines the declarative Puppet language model with familiar and convenient imperative code, making it easy to learn and effective for both one-off tasks and long-term configuration management.

I want to demonstrate how powerful using these tools together is, and how they each enable you quickly get the cloud resources you need and provision them with minimal setup and code. We'll first create an AWS EC2 instance with Terraform, then use Bolt to get the IP of the instance and manage it using Puppet code (with zero Puppet knowledge required1). Let's get started!

Note: If you want to follow along or see a more complete example all my code is available on github.

Create Cloud Resources with Terraform
This step was simple: I followed the Terraform Getting Started Guide to set up a t1.micro EC2 instance, then added a few bits and bobs mostly around ensuring we can SSH into the machine. Here's some key notes and the code:

SSH Key: We need to make sure there's a way to SSH into the boxes we create. I chose to do this with SSH key pairs, but you could also just have username + password set.
Outputs: To make it easier to get the IP addresses for the instances we create I added an output to produce an array of the IPs of the instances. Parsing the default terraform json output in Bolt is equivalent.
Ubuntu Xenial AMI: I'm totally new to AWS and wasn't sure how to create a user on my new instance, or more importantly whether Puppet would work on it. So I just used an ubuntu image instead of the usual Amazon Linux one.
Security Group: This adds a security group to allow traffic into and out of the node so that we can, y'know, make use of it.
~/terraform-playground/example.tf

provider "aws" {
  access_key = <ACCESS_KEY>
  secret_key = <SECRET_KEY>
  region     = "us-west-2"
}

# Add a local SSH key
resource "aws_key_pair" "example" {
  key_name    = "aws_key"
  public_key  = <PUBLIC_KEY>
}

# Add a permissive security group
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     =
    ["0.0.0.0/0"]
  }
}

# Create EC2 instance
resource "aws_instance" "xenial" {
  ami = "ami-076e276d85f524150"
  instance_type = "t1.micro"
  key_name = "aws_key"
  security_groups = ["allow_all"]
}

# Create output for public IPs
# This is an array in case we create multiple instances, but for
# now there's just one
output "public_ips" {
  value = ["${aws_instance.xenial.*.public_ip}"]
}
Configure Instances with Bolt Plans
Now that we've created a box with Terraform, we'll:

Collect the public IP in a Bolt Plan
Add it to the Bolt inventory file so it picks up configuration
And do anything we want with it - for example, deploy a small webpage
First let's create a Bolt inventory file with configuration that Bolt will need to connect to the EC2 instance. This inventory includes 1 group called 'terraform', which defaults to using the SSH transport. It then configures the ssh private key, user, and host key check for this group.

~/terraform_provision/inventory.yaml

groups:
  - name: terraform
    nodes: [] # This will be populated by the Bolt plan
    config:
      transport: ssh
      ssh:
        private-key: ~/.ssh/id_rsa-phraseless
        user: ubuntu
        host-key-check: false
Next we'll write the Bolt plan to run terraform apply, collect the IPs of the instances it creates, and provision those instances.

~/terraform_provision/plans/init.pp

plan terraform_provision(String $tf_path) {
  $localhost = get_targets('localhost')

  # Create infrastructure with terraform apply
  run_command("cd ${$tf_path} && terraform apply", $localhost)
  $ip_string = run_command("cd ${$tf_path} && terraform output public_ips",
                            $localhost).map \|$r| { $r['stdout'] }
  $ips = Array($ip_string).map \|$ip| { $ip.strip }

  # Turn IPs into Bolt targets, and add to inventory
  $targets = $ips.map \|$ip| {
    Target.new("${$ip}").add_to_group('terraform')
  }

  # Deploy website
  apply_prep($targets)

  apply($targets, _run_as => 'root') {
    include apache

    file { '/var/www/html/index.html':
      ensure => 'file',
      source => "puppet:///modules/terraform_provision/site.html"
    }
  }

  return $ips
}
In less than 30 lines of code we've got an apache server up and running!

A few other files we'll need to support running Bolt:

A bolt configuration file, to tell it where to find modules

~/terraform_provision/bolt.yaml

---
modulepath: ./modules:~/githubs/modules
A Puppetfile with dependencies:

~/terraform_provision/Puppetfile

mod 'puppetlabs-apache', '4.0.0'
mod 'puppetlabs-stdlib', '5.2.0'
mod 'puppetlabs-concat', '5.2.0'
And lastly, an HTML page to serve:

~/terraform_provision/files/site.html

<!DOCTYPE html>
<body>
  <h1>Hello from Terraform + Bolt!</h1>
</body>
</html>
Again, all these files are available in this git repo, with a bit more verbosity and structure!

Running Bolt
Phew! Now that all our files are in place, here's how easy it is to deploy our server:

$ bolt puppetfile install
$ bolt plan run terraform_provision \
    -i ~/terraform_provision/inventory.yaml \
    tf_path=~/terraform-playground
And that's it! The plan should output something like:

["34.220.231.46"]
Visit the IP in your browser and check out your new site!
