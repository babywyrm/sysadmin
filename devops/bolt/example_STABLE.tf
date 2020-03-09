########################################
## https://github.com/alexharv074/terraform-puppet-provisioner-test
########################################
##
##
variable "key_name" {
  description = "The name of the EC2 key pair to use"
  default     = "thing-thang"
}

variable "key_file" {
  description = "The private key for the ec2-user used in SSH connections and by Puppet Bolt"
  default     = "~/.ssh/thing-thang.pem"
}

locals {
  instance_type = "t2.micro"
}

data "aws_ami" "ami" {
  owners      = ["amazon"]
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-ebs"]
  }
}

data "aws_ami" "windows_2012R2" {
  most_recent = "true"
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2012-R2_RTM-English-64Bit-Base-*"]
  }
}

data "template_file" "user_data" {
  template = file("${path.module}/user_data/master.sh")
}

data "template_file" "winrm" {
  template = file("${path.module}/user_data/os_win_agent.xml")
}

resource "aws_instance" "master" {
  ami           = data.aws_ami.ami.id
  instance_type = local.instance_type
  key_name      = var.key_name
  user_data     = data.template_file.user_data.rendered

  provisioner "remote-exec" {
    on_failure = continue
    inline = [
      "sudo sh -c 'while ! grep -q Cloud-init.*finished /var/log/cloud-init-output.log; do sleep 20; done'"
    ]

    connection {
      host        = self.public_ip
      user        = "ec2-user"
      private_key = file(var.key_file)
    }
  }
}

resource "aws_instance" "agent" {
  ami           = data.aws_ami.ami.id
  instance_type = local.instance_type
  key_name      = var.key_name

  provisioner "puppet" {
    use_sudo    = true
    server      = aws_instance.master.public_dns
    server_user = "ec2-user"

    connection {
      host        = self.public_ip
      user        = "ec2-user"
      private_key = file(var.key_file)
    }
  }

  depends_on = [aws_instance.master]
}

resource "aws_instance" "os_win_agent" {
  ami               = data.aws_ami.windows_2012R2.image_id
  instance_type     = "t2.large"
  key_name          = var.key_name
  get_password_data = true

  timeouts {
    create = "15m"
  }

  provisioner "puppet" {
    open_source = true
    server      = aws_instance.master.public_dns
    server_user = "ec2-user"

    connection {
      host     = self.public_ip
      type     = "winrm"
      user     = "Administrator"
      password = rsadecrypt(self.password_data, file(var.key_file))
      timeout  = "10m"
    }
  }

  user_data  = data.template_file.winrm.rendered
  depends_on = [aws_instance.master]
}

#####################################################
##
##
