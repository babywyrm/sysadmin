resource "aws_instance" "example" {
  ami           = "ami-0abcdef1234567890" # Replace
  instance_type = "t3.micro"
  subnet_id     = var.subnet_id

  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "ec2-with-imds-and-secrets"
  }
}
