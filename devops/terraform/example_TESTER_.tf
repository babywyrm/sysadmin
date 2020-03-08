### https://github.com/rodjek/terraform-puppet-example/blob/master/example.tf
###
###  __tried_bionic_18.04_failed_cannot_get_valid_console_data_on_pupp_mast_aws_
###  __16.04_fails_to_bind_sshd_also___INFINITE_SADNESS__
###
###
########
###

provider "aws" {
  access_key = var.access_key
  secret_key = var.secret_key
  region     = var.region
}

data "aws_ami" "windows_2012R2" {
  most_recent = "true"
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2012-R2_RTM-English-64Bit-Base-*"]
  }
}

resource "aws_instance" "puppetmaster" {
  ami           = var.aws_ami_id
  instance_type = "t2.medium"
  key_name      = var.aws_key_pair

  connection {
    host        = coalesce(self.public_ip, self.private_ip)
    type        = "ssh"
    user        = "ubuntu"
    private_key = file("~/.ssh/id_rsa")
  }

  timeouts {
    create = "15m"
  }

  provisioner "file" {
    content     = templatefile("pe.conf.tmpl", { dns_alt_names = [self.public_dns, "localhost", "puppet"] })
    destination = "/tmp/pe.conf"
  }

  provisioner "file" {
    source      = "autosign-batch.json"
    destination = "/tmp/autosign-batch.json"
  }

  provisioner "remote-exec" {
    on_failure = continue
    inline = [
      "curl -L -o /tmp/puppet-enterprise-${var.pe_version}-${var.pe_platform}.tar.gz https://s3.amazonaws.com/pe-builds/released/${var.pe_version}/puppet-enterprise-${var.pe_version}-${var.pe_platform}.tar.gz",
      "tar zxf /tmp/puppet-enterprise-${var.pe_version}-${var.pe_platform}.tar.gz -C /tmp",
      "sudo mkdir -p /etc/puppetlabs/puppet",
      "sudo /tmp/puppet-enterprise-${var.pe_version}-${var.pe_platform}/puppet-enterprise-installer -c /tmp/pe.conf",
      "sudo puppet module install danieldreier/autosign",
      "sudo /opt/puppetlabs/puppet/bin/gem install ncedit",
      "sudo /opt/puppetlabs/puppet/bin/ncedit update_classes",
      "sudo /opt/puppetlabs/puppet/bin/ncedit batch --json-file /tmp/autosign-batch.json",
      "sudo puppet config set --section master autosign /opt/puppetlabs/puppet/bin/autosign-validator",
      "sudo service pe-puppetmaster restart",
      "sudo sh -c 'while ! puppet agent --test --detailed-exitcodes; do sleep 60; done'",
    ]
  }
}

resource "aws_instance" "agent" {
  ami           = var.aws_ami_id
  instance_type = "t2.medium"
  key_name      = var.aws_key_pair

  connection {
    host        = coalesce(self.public_ip, self.private_ip)
    type        = "ssh"
    user        = "ubuntu"
    private_key = file("~/.ssh/id_rsa")
  }

  provisioner "puppet" {
    use_sudo    = true
    server      = aws_instance.puppetmaster.public_dns
    server_user = "ubuntu"
  }
}

resource "aws_instance" "os_agent" {
  ami           = var.aws_ami_id
  instance_type = "t2.medium"
  key_name      = var.aws_key_pair

  connection {
    host        = coalesce(self.public_ip, self.private_ip)
    type        = "ssh"
    user        = "ubuntu"
    private_key = file("~/.ssh/id_rsa")
  }

  provisioner "puppet" {
    use_sudo    = true
    open_source = true
    server      = aws_instance.puppetmaster.public_dns
    server_user = "ubuntu"
    extension_requests = {
      pp_role = "test"
      pp_provisioner = "terraform"
      pp_application = "awesome_thing"
    }
  }
}

data "template_file" "winrm" {
  template = <<EOD
<script>
    winrm quickconfig -q & winrm set winrm/config @{MaxTimeoutms="1800000"} & winrm set winrm/config/service @{AllowUnencrypted="true"} & winrm set winrm/config/service/auth @{Basic="true"}
</script>
<powershell>
    netsh advfirewall firewall add rule name="WinRM in" protocol=TCP dir=in profile=any localport=5985 remoteip=any localip=any action=allow
    Stop-Service winrm
    Start-Service winrm
</powershell>
EOD

}

resource "aws_instance" "os_win_agent" {
  ami = data.aws_ami.windows_2012R2.image_id
  instance_type = "t2.large"
  key_name = var.aws_key_pair
  get_password_data = true

  timeouts {
    create = "15m"
  }

  connection {
    host = coalesce(self.public_ip, self.private_ip)
    type = "winrm"
    user = "Administrator"
    password = rsadecrypt(self.password_data, file("~/.ssh/id_rsa"))
    timeout = "10m"
  }

  provisioner "puppet" {
    open_source = true
    server = aws_instance.puppetmaster.public_dns
    server_user = "ubuntu"
  }

  user_data = data.template_file.winrm.rendered
}

resource "aws_instance" "win_agent" {
  ami = data.aws_ami.windows_2012R2.image_id
  instance_type = "t2.large"
  key_name = var.aws_key_pair
  get_password_data = true

  timeouts {
    create = "15m"
  }

  connection {
    host = coalesce(self.public_ip, self.private_ip)
    type = "winrm"
    user = "Administrator"
    password = rsadecrypt(self.password_data, file("~/.ssh/id_rsa"))
    timeout = "10m"
  }

  provisioner "puppet" {
    server = aws_instance.puppetmaster.public_dns
    server_user = "ubuntu"
  }

  user_data = data.template_file.winrm.rendered
}
