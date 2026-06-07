```
output "instance_public_ip" {
  value = aws_instance.my_instance.public_ip
}

# Create IAM role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "terraform_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name   = "terraform_lambda_policy"
  role   = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow",
        Action = "lambda:InvokeFunction",
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeAlarms"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = "iam:PassRole",
        Resource = "arn:aws:iam::*:role/terraform_lambda_role"
      },
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:TerminateInstances"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "ssm:SendCommand"
        ],
        Resource = "*"
      }
    ]
  })
}

# Create Lambda function
resource "aws_lambda_function" "terraform_destroy_function" {
  function_name = "terraform_destroy_function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.8"

  filename      = "lambda_function_payload.zip"
  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  environment {
    variables = {
      TF_WORKSPACE = "default"
    }
  }
}

# Create Lambda deployment package
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "lambda"
  output_path = "lambda_function_payload.zip"
}

# Create CloudWatch Event Rule to trigger Lambda after 70 minutes
resource "aws_cloudwatch_event_rule" "schedule_rule" {
  name                = "terraform_destroy_schedule"
  schedule_expression = "rate(70 minutes)"
}

# Add CloudWatch Event Target
resource "aws_cloudwatch_event_target" "target" {
  rule      = aws_cloudwatch_event_rule.schedule_rule.name
  target_id = "lambda_target"
  arn       = aws_lambda_function.terraform_destroy_function.arn
}

# Add permissions for CloudWatch to invoke Lambda
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.terraform_destroy_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule_rule.arn
}

output "instance_public_ip" {
  value = aws_instance.my_instance.public_ip
}
```



Create a lambda directory and add the following Python code to a file named lambda_function.py:

```
import boto3

def handler(event, context):
    client = boto3.client('ssm')
    response = client.send_command(
        InstanceIds=['instance-id'], # Replace with your instance ID
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': ['terraform destroy -auto-approve']}
    )
    return response
```


##
##


cd lambda
zip -r ../lambda_function_payload.zip .
cd ..








