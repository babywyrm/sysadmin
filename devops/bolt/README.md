####################

Terraform Puppet Provisioner Test
<br>
**https://github.com/alexharv074/terraform-puppet-provisioner-test**

####################

Overview
This is a proof of concept of the Puppet Terraform provisioner that was added in Terraform 0.12.2. It uses Terraform and the Terraform Puppet provisioner to set up a Puppet Master and two Agents, one that uses the latest Amazon Linux 2 AMI and another that uses Windows 2016, and then installs a very simple "hello world" Puppet module on the Puppet Master, and then configures the agent node using this code.

It assumes you will use Mac OS X on your laptop. Minor changes would be required otherwise.

Architecture
The following figure shows the main components of the solution:

Fig 1

Dependencies
Install the latest Terraform (>= 0.12.2). Get that from here.

Puppet Bolt is also required, but the setup.sh script will install it if it's not there.

Note also that, at the time of writing, the project depends on an unmerged pull request I've raised against the puppetlabs-puppet_agent project to add Amazon Linux 2 support. This is branch is referenced in the Puppetfile so again no need to do anything yet.

There is also an assumption that you will provide an EC2 key pair and it will have the name "default". If that's not there, create the EC2 Key Pair using:

▶ aws ec2 create-key-pair --key-name default
Usage
Setup script
First run the setup script.

▶ bash -x setup.sh
This will:

If necessary, install the latest Puppet Bolt as a Brew Cask.
Make the Bolt Config directory.
Install the required Bolt modules (bolt puppetfile install).
See the code here.

Apply terraform
Then run terraform apply:

▶ terraform init
▶ terraform apply -auto-approve
Expected output
▶ terraform apply -auto-approve
data.template_file.winrm: Refreshing state...
data.template_file.user_data: Refreshing state...
data.aws_ami.ami: Refreshing state...
data.aws_ami.windows_2012R2: Refreshing state...
aws_instance.master: Creating...
aws_instance.master: Still creating... [10s elapsed]
aws_instance.master: Still creating... [20s elapsed]
aws_instance.master: Still creating... [30s elapsed]
aws_instance.master: Provisioning with 'remote-exec'...
aws_instance.master (remote-exec): Connecting to remote host via SSH...
aws_instance.master (remote-exec):   Host: 13.239.139.194
aws_instance.master (remote-exec):   User: ec2-user
aws_instance.master (remote-exec):   Password: false
aws_instance.master (remote-exec):   Private key: true
aws_instance.master (remote-exec):   Certificate: false
aws_instance.master (remote-exec):   SSH Agent: true
aws_instance.master (remote-exec):   Checking Host Key: false
aws_instance.master: Still creating... [40s elapsed]
aws_instance.master (remote-exec): Connecting to remote host via SSH...
aws_instance.master (remote-exec):   Host: 13.239.139.194
aws_instance.master (remote-exec):   User: ec2-user
aws_instance.master (remote-exec):   Password: false
aws_instance.master (remote-exec):   Private key: true
aws_instance.master (remote-exec):   Certificate: false
aws_instance.master (remote-exec):   SSH Agent: true
aws_instance.master (remote-exec):   Checking Host Key: false
aws_instance.master: Still creating... [50s elapsed]
aws_instance.master: Still creating... [1m0s elapsed]
aws_instance.master (remote-exec): Connecting to remote host via SSH...
aws_instance.master (remote-exec):   Host: 13.239.139.194
aws_instance.master (remote-exec):   User: ec2-user
aws_instance.master (remote-exec):   Password: false
aws_instance.master (remote-exec):   Private key: true
aws_instance.master (remote-exec):   Certificate: false
aws_instance.master (remote-exec):   SSH Agent: true
aws_instance.master (remote-exec):   Checking Host Key: false
aws_instance.master (remote-exec): Connecting to remote host via SSH...
aws_instance.master (remote-exec):   Host: 13.239.139.194
aws_instance.master (remote-exec):   User: ec2-user
aws_instance.master (remote-exec):   Password: false
aws_instance.master (remote-exec):   Private key: true
aws_instance.master (remote-exec):   Certificate: false
aws_instance.master (remote-exec):   SSH Agent: true
aws_instance.master (remote-exec):   Checking Host Key: false
aws_instance.master (remote-exec): Connected!
aws_instance.master: Still creating... [1m10s elapsed]
aws_instance.master: Still creating... [1m20s elapsed]
aws_instance.master: Still creating... [1m30s elapsed]
aws_instance.master: Still creating... [1m40s elapsed]
aws_instance.master: Still creating... [1m50s elapsed]
aws_instance.master: Still creating... [2m0s elapsed]
aws_instance.master: Still creating... [2m10s elapsed]
aws_instance.master: Still creating... [2m20s elapsed]
aws_instance.master: Still creating... [2m30s elapsed]
aws_instance.master: Still creating... [2m40s elapsed]
aws_instance.master: Still creating... [2m50s elapsed]
aws_instance.master: Still creating... [3m0s elapsed]
aws_instance.master: Still creating... [3m10s elapsed]
aws_instance.master: Creation complete after 3m17s [id=i-0d126b0f634539c45]
aws_instance.linux_agent: Creating...
aws_instance.win_agent: Creating...
aws_instance.win_agent: Still creating... [10s elapsed]
aws_instance.linux_agent: Still creating... [10s elapsed]
aws_instance.linux_agent: Still creating... [20s elapsed]
aws_instance.win_agent: Still creating... [20s elapsed]
aws_instance.linux_agent: Provisioning with 'puppet'...
aws_instance.linux_agent (puppet): Connecting to remote host via SSH...
aws_instance.linux_agent (puppet):   Host: 54.252.134.38
aws_instance.linux_agent (puppet):   User: ec2-user
aws_instance.linux_agent (puppet):   Password: false
aws_instance.linux_agent (puppet):   Private key: true
aws_instance.linux_agent (puppet):   Certificate: false
aws_instance.linux_agent (puppet):   SSH Agent: true
aws_instance.linux_agent (puppet):   Checking Host Key: false
aws_instance.win_agent: Still creating... [30s elapsed]
aws_instance.linux_agent: Still creating... [30s elapsed]
aws_instance.linux_agent (puppet): Connecting to remote host via SSH...
aws_instance.linux_agent (puppet):   Host: 54.252.134.38
aws_instance.linux_agent (puppet):   User: ec2-user
aws_instance.linux_agent (puppet):   Password: false
aws_instance.linux_agent (puppet):   Private key: true
aws_instance.linux_agent (puppet):   Certificate: false
aws_instance.linux_agent (puppet):   SSH Agent: true
aws_instance.linux_agent (puppet):   Checking Host Key: false
aws_instance.win_agent: Still creating... [40s elapsed]
aws_instance.linux_agent: Still creating... [40s elapsed]
aws_instance.linux_agent (puppet): Connecting to remote host via SSH...
aws_instance.linux_agent (puppet):   Host: 54.252.134.38
aws_instance.linux_agent (puppet):   User: ec2-user
aws_instance.linux_agent (puppet):   Password: false
aws_instance.linux_agent (puppet):   Private key: true
aws_instance.linux_agent (puppet):   Certificate: false
aws_instance.linux_agent (puppet):   SSH Agent: true
aws_instance.linux_agent (puppet):   Checking Host Key: false
aws_instance.linux_agent (puppet): Connecting to remote host via SSH...
aws_instance.linux_agent (puppet):   Host: 54.252.134.38
aws_instance.linux_agent (puppet):   User: ec2-user
aws_instance.linux_agent (puppet):   Password: false
aws_instance.linux_agent (puppet):   Private key: true
aws_instance.linux_agent (puppet):   Certificate: false
aws_instance.linux_agent (puppet):   SSH Agent: true
aws_instance.linux_agent (puppet):   Checking Host Key: false
aws_instance.linux_agent (puppet): Connected!
aws_instance.linux_agent (puppet): ip-172-31-10-49.ap-southeast-2.compute.internal
aws_instance.linux_agent: Still creating... [50s elapsed]
aws_instance.win_agent: Still creating... [50s elapsed]
aws_instance.linux_agent: Still creating... [1m0s elapsed]
aws_instance.win_agent: Still creating... [1m0s elapsed]
aws_instance.win_agent: Still creating... [1m10s elapsed]
aws_instance.linux_agent: Still creating... [1m10s elapsed]
aws_instance.win_agent: Still creating... [1m20s elapsed]
aws_instance.linux_agent: Still creating... [1m20s elapsed]
aws_instance.win_agent: Provisioning with 'puppet'...
aws_instance.win_agent (puppet): Connecting to remote host via WinRM...
aws_instance.win_agent (puppet):   Host: 13.211.55.90
aws_instance.win_agent (puppet):   Port: 5985
aws_instance.win_agent (puppet):   User: Administrator
aws_instance.win_agent (puppet):   Password: true
aws_instance.win_agent (puppet):   HTTPS: false
aws_instance.win_agent (puppet):   Insecure: false
aws_instance.win_agent (puppet):   NTLM: false
aws_instance.win_agent (puppet):   CACert: false
aws_instance.win_agent (puppet): Connected!
aws_instance.win_agent (puppet): WIN-IPE5577KSBA
aws_instance.linux_agent (puppet): Info: Downloaded certificate for ca from ec2-13-239-139-194.ap-southeast-2.compute.amazonaws.com
aws_instance.linux_agent (puppet): Info: Downloaded certificate revocation list for ca from ec2-13-239-139-194.ap-southeast-2.compute.amazonaws.com
aws_instance.linux_agent (puppet): Info: Creating a new RSA SSL key for ip-172-31-10-49.ap-southeast-2.compute.internal
aws_instance.win_agent (puppet): ap-southeast-2.compute.internal
aws_instance.linux_agent (puppet): Info: csr_attributes file loading from /etc/puppetlabs/puppet/csr_attributes.yaml
aws_instance.linux_agent (puppet): Info: Creating a new SSL certificate request for ip-172-31-10-49.ap-southeast-2.compute.internal
aws_instance.linux_agent (puppet): Info: Certificate Request fingerprint (SHA256): E3:E8:AD:42:EC:76:EE:F0:DF:47:F9:D1:65:6B:8C:46:0B:59:B2:1A:26:5B:56:B7:55:87:1C:B9:7E:E6:BA:3E
aws_instance.linux_agent (puppet): Info: Downloaded certificate for ip-172-31-10-49.ap-southeast-2.compute.internal from ec2-13-239-139-194.ap-southeast-2.compute.amazonaws.com
aws_instance.win_agent: Still creating... [1m30s elapsed]
aws_instance.linux_agent: Still creating... [1m30s elapsed]
aws_instance.linux_agent (puppet): Info: Using configured environment 'production'
aws_instance.linux_agent (puppet): Info: Retrieving pluginfacts
aws_instance.linux_agent (puppet): Info: Retrieving plugin
aws_instance.linux_agent (puppet): Info: Retrieving locales


aws_instance.win_agent (puppet):     Directory: C:\ProgramData\PuppetLabs\Puppet


aws_instance.win_agent (puppet): Mode                LastWriteTime     Length Name
aws_instance.win_agent (puppet): ----                -------------     ------ ----
aws_instance.win_agent (puppet): d----        10/12/2019  11:47 AM            etc


aws_instance.linux_agent (puppet): Info: Caching catalog for ip-172-31-10-49.ap-southeast-2.compute.internal
aws_instance.linux_agent (puppet): Info: Applying configuration version '1570880860'
aws_instance.linux_agent (puppet): Notice: Hello world from ip-172-31-10-49!
aws_instance.linux_agent (puppet): Notice: /Stage[main]/Main/Node[default]/Notify[Hello world from ip-172-31-10-49!]/message: defined 'message' as 'Hello world from ip-172-31-10-49!'
aws_instance.linux_agent (puppet): Info: Creating state file /opt/puppetlabs/puppet/cache/state/state.yaml
aws_instance.linux_agent (puppet): Notice: Applied catalog in 0.01 seconds
aws_instance.linux_agent: Creation complete after 1m33s [id=i-06b88138c2feda4cf]
aws_instance.win_agent: Still creating... [1m40s elapsed]
aws_instance.win_agent: Still creating... [1m50s elapsed]
aws_instance.win_agent: Still creating... [2m0s elapsed]
aws_instance.win_agent: Still creating... [2m10s elapsed]
aws_instance.win_agent: Still creating... [2m20s elapsed]
aws_instance.win_agent: Still creating... [2m30s elapsed]
aws_instance.win_agent: Still creating... [2m40s elapsed]
aws_instance.win_agent (puppet): Info: Downloaded certificate for ca from ec2-13-239-139-194.ap-southeast-2.compute.amazonaws.com
aws_instance.win_agent (puppet): Info: Downloaded certificate revocation list for ca from ec2-13-239-139-194.ap-southeast-2.compute.amazonaws.com
aws_instance.win_agent (puppet): Info: Creating a new RSA SSL key for win-ipe5577ksba.ap-southeast-2.compute.internal
aws_instance.win_agent: Still creating... [2m50s elapsed]
aws_instance.win_agent (puppet): Info: csr_attributes file loading from C:/ProgramData/PuppetLabs/puppet/etc/csr_attributes.yaml
aws_instance.win_agent (puppet): Info: Creating a new SSL certificate request for win-ipe5577ksba.ap-southeast-2.compute.internal
aws_instance.win_agent (puppet): Info: Certificate Request fingerprint (SHA256): A1:C0:D3:AD:24:C7:80:67:F1:F4:97:FC:06:E2:16:01:12:DA:02:5F:AA:2F:57:98:9F:7D:2A:34:42:3C:D3:50
aws_instance.win_agent (puppet): Info: Downloaded certificate for win-ipe5577ksba.ap-southeast-2.compute.internal from ec2-13-239-139-194.ap-southeast-2.compute.amazonaws.com
aws_instance.win_agent (puppet): Info: Using configured environment 'production'
aws_instance.win_agent (puppet): Info: Retrieving pluginfacts
aws_instance.win_agent (puppet): Info: Retrieving plugin
aws_instance.win_agent (puppet): Info: Retrieving locales
aws_instance.win_agent (puppet): Info: Caching catalog for win-ipe5577ksba.ap-southeast-2.compute.internal
aws_instance.win_agent (puppet): Info: Applying configuration version '1570880943'
aws_instance.win_agent (puppet): Notice: Hello world from WIN-IPE5577KSBA!
aws_instance.win_agent (puppet): Notice: /Stage[main]/Main/Node[default]/Notify[Hello world from WIN-IPE5577KSBA!]/message: defined 'message' as 'Hello world from WIN-IPE5577KSBA!'
aws_instance.win_agent (puppet): Info: Creating state file C:/ProgramData/PuppetLabs/puppet/cache/state/state.yaml
aws_instance.win_agent (puppet): Notice: Applied catalog in 0.02 seconds
aws_instance.win_agent: Creation complete after 2m55s [id=i-07da31c6a0bf6ce14]

Apply complete! Resources: 3 added, 0 changed, 0 destroyed.
Acknowledgements
Thanks to Tim Sharpe at Puppet for writing the provisioner and assisting! Also thanks to Green Reed Technology for their earlier Puppet Provisioner docs.

License

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
